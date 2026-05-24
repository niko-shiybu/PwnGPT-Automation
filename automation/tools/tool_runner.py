from __future__ import annotations

import json
import subprocess
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class ToolResult:
    measured_facts: Dict[str, Any]
    unresolved_facts: List[Dict[str, str]]
    notes: List[str]
    action_results: List[Dict[str, Any]] = None


def _safe_decode(b: bytes) -> str:
    return (b or b"").decode("latin-1", errors="ignore")


def _run_once(binary_path: str, payload: bytes, *, timeout_s: float = 1.2) -> Tuple[int, str]:
    """
    Run binary once, send one line, collect output. Returns (exit_code, blob_text).
    Uses pwntools if available for consistent behavior.
    """
    try:
        from pwn import context, process  # type: ignore

        context.log_level = "error"
        io = process(binary_path, cwd=binary_path.rsplit("/", 1)[0])
        try:
            io.sendline(payload)
            out = io.recvall(timeout=timeout_s)
            io.wait(timeout=0.2)
            rc = io.poll() or 0
            return int(rc), _safe_decode(out)
        finally:
            try:
                io.close()
            except Exception:
                pass
    except Exception:
        # Fallback: minimal subprocess
        import subprocess

        proc = subprocess.run(
            [binary_path],
            input=payload + b"\n",
            capture_output=True,
            timeout=max(0.2, timeout_s),
            check=False,
            cwd=binary_path.rsplit("/", 1)[0],
        )
        blob = _safe_decode(proc.stdout or b"") + _safe_decode(proc.stderr or b"")
        return int(proc.returncode), blob


def tool_fmt_measure_s_offset(binary_path: str, *, min_idx: int = 1, max_idx: int = 40, repeats: int = 2) -> ToolResult:
    """
    Find an argument index that is safe for `%<i>$s` dereference (no SIGSEGV) and yields
    interesting printable output (flag-like or contains braces).
    """
    best = None
    best_score = -1
    notes: List[str] = []
    unresolved: List[Dict[str, str]] = []

    for i in range(min_idx, max_idx + 1):
        ok_runs = 0
        segv_runs = 0
        merged = ""
        for _ in range(max(1, repeats)):
            rc, out = _run_once(binary_path, f"%{i}$s".encode(), timeout_s=1.2)
            merged += "\n" + out
            if rc == -11:
                segv_runs += 1
            else:
                ok_runs += 1
        if segv_runs > 0 and ok_runs == 0:
            continue

        blob = merged.lower()
        score = 0
        if "flag{" in blob:
            score += 200
        if "{" in blob and "}" in blob:
            score += 80
        printable = sum(1 for c in blob[-200:] if 32 <= ord(c) < 127)
        score += min(40, printable // 5)
        if ok_runs >= 1:
            score += 10
        if ok_runs >= repeats:
            score += 15

        if score > best_score:
            best_score = score
            best = i
            notes.append(f"candidate_s_offset:{i}:score={score}:ok={ok_runs}:segv={segv_runs}")

    if best is None:
        unresolved.append({"key": "offsets.fmt_arg_s", "reason": "not_found"})
        return ToolResult(measured_facts={}, unresolved_facts=unresolved, notes=notes)

    return ToolResult(
        measured_facts={"offsets.fmt_arg_s": int(best)},
        unresolved_facts=[],
        notes=notes[-8:],
    )


def tool_fmt_measure_p_offset(binary_path: str, *, min_idx: int = 1, max_idx: int = 40, repeats: int = 2) -> ToolResult:
    """
    Find an argument index that produces a stable 0x... pointer with `%<i>$p`.
    """
    best = None
    best_score = -1
    notes: List[str] = []

    for i in range(min_idx, max_idx + 1):
        tokens: List[str] = []
        for _ in range(max(1, repeats)):
            rc, out = _run_once(binary_path, f"%{i}$p".encode(), timeout_s=1.0)
            if rc == -11:
                tokens.append("segv")
                continue
            m = re.search(r"(0x[0-9a-fA-F]+|\(nil\))", out)
            tokens.append(m.group(1) if m else "")
        if not tokens or any(t in {"", "(nil)", "segv"} for t in tokens):
            continue
        stable = len(set(tokens)) == 1
        score = 10 + (20 if stable else 0)
        if score > best_score:
            best_score = score
            best = i
            notes.append(f"candidate_p_offset:{i}:tokens={tokens}")

    if best is None:
        return ToolResult(measured_facts={}, unresolved_facts=[{"key": "offsets.fmt_arg_p", "reason": "not_found"}], notes=notes)
    return ToolResult(measured_facts={"offsets.fmt_arg_p": int(best)}, unresolved_facts=[], notes=notes[-8:])


def tool_pwntools_got(binary_path: str, *, symbol: str = "printf") -> ToolResult:
    """
    Resolve GOT address for a symbol via pwntools ELF.
    """
    try:
        from pwn import ELF  # type: ignore

        elf = ELF(binary_path, checksec=False)
        got = elf.got.get(symbol)
        if got is None:
            return ToolResult(measured_facts={}, unresolved_facts=[{"key": f"offsets.{symbol}_got", "reason": "not_found"}], notes=[])
        return ToolResult(measured_facts={f"offsets.{symbol}_got": int(got)}, unresolved_facts=[], notes=[])
    except Exception as exc:
        return ToolResult(measured_facts={}, unresolved_facts=[{"key": f"offsets.{symbol}_got", "reason": f"error:{exc}"}], notes=[])


def tool_fmt_scan_stack(
    binary_path: str,
    *,
    min_idx: int = 1,
    max_idx: int = 20,
    marker: str = "AAAA",
    timeout_s: float = 1.2,
) -> ToolResult:
    """
    Fallback format-string offset scanner: send AAAA%i$p for each position,
    find where 0x41414141 appears. Returns offsets.fmt_write_arg.
    Auto-adapts to 64-bit: first 6 args in registers, offset >= 6 from stack.
    """
    try:
        from pwn import context, process, ELF  # type: ignore
        context.log_level = "error"
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.fmt_write_arg", "reason": f"pwntools_missing:{exc}"}],
            notes=[],
        )

    # Detect arch: 64-bit starts from 6 (first 6 args in registers)
    try:
        elf = ELF(binary_path, checksec=False)
        arch = getattr(elf, "arch", "") or ""
    except Exception:
        arch = ""
    is_64bit = arch == "amd64" or arch == "aarch64"
    if is_64bit and min_idx < 6:
        min_idx = 6

    best_offset = None
    best_score = -1
    notes: List[str] = []

    for i in range(min_idx, max_idx + 1):
        try:
            io = process(binary_path, cwd=binary_path.rsplit("/", 1)[0])
            payload = f"{marker}%{i}$p".encode()
            io.sendline(payload)
            out = io.recvall(timeout=timeout_s) or b""
            io.close()
        except Exception:
            continue

        text = out.decode("latin-1", errors="ignore")
        score = 0
        if "0x41414141" in text:
            score += 100
        elif "41414141" in text:
            score += 80
        if marker.encode() in out:
            score += 30
        if score > best_score:
            best_score = score
            best_offset = i
            notes.append(f"candidate:{i}:score={score}:found_marker={score>=100}")

    if best_offset is not None and best_score >= 30:
        return ToolResult(
            measured_facts={"offsets.fmt_write_arg": best_offset, "offsets.fmt_offset_arg": best_offset},
            unresolved_facts=[],
            notes=notes[-6:] + [f"fmt_scan_stack_offset={best_offset}"],
        )
    return ToolResult(
        measured_facts={},
        unresolved_facts=[{"key": "offsets.fmt_write_arg", "reason": "scan_not_found"}],
        notes=notes[-6:] + ["fmt_scan_stack_failed"],
    )


def tool_fmt_measure_write_offset(
    binary_path: str,
    *,
    max_tries: int = 40,
    timeout_s: float = 1.5,
) -> ToolResult:
    """
    Measure format-string write offset using pwntools FmtStr (no guessing).
    Returns offsets.fmt_write_arg and offsets.fmt_offset_arg for compatibility.
    Falls back to fmt_scan_stack if FmtStr returns invalid offset.
    """
    try:
        from pwn import FmtStr, context, process  # type: ignore
    except Exception as exc:
        # Fallback to scan if pwntools unavailable
        return tool_fmt_scan_stack(binary_path, timeout_s=timeout_s)

    context.log_level = "error"

    def exec_fmt(payload: bytes) -> bytes:
        io = process(binary_path, cwd=binary_path.rsplit("/", 1)[0])
        try:
            io.sendline(payload)
            return io.recvall(timeout=timeout_s) or b""
        finally:
            try:
                io.close()
            except Exception:
                pass

    constructor_attempts = [
        ("kwargs_max_len", {"offset": 0, "padlen": 0, "numbwritten": 0, "max_len": 128}),
        ("kwargs_basic", {"offset": 0, "padlen": 0, "numbwritten": 0}),
        ("kwargs_offset_only", {"offset": 0}),
        ("no_kwargs", None),
    ]
    errors: List[str] = []
    fmt = None
    used_ctor = ""
    for ctor_name, kwargs in constructor_attempts:
        try:
            if kwargs is None:
                fmt = FmtStr(exec_fmt)
            else:
                fmt = FmtStr(exec_fmt, **kwargs)
            used_ctor = ctor_name
            break
        except Exception as exc:
            errors.append(f"{ctor_name}:{exc}")
            continue

    if fmt is None:
        return tool_fmt_scan_stack(binary_path, timeout_s=timeout_s)

    try:
        off = int(fmt.offset)
    except Exception as exc:
        return tool_fmt_scan_stack(binary_path, timeout_s=timeout_s)

    if off < 1 or off > max_tries:
        return tool_fmt_scan_stack(binary_path, timeout_s=timeout_s)
    return ToolResult(
        measured_facts={"offsets.fmt_write_arg": off, "offsets.fmt_offset_arg": off},
        unresolved_facts=[],
        notes=[f"fmt_ctor={used_ctor}", f"fmt_write_offset={off}"],
    )


def tool_stack_measure_ret_offset_gdb(
    binary_path: str,
    *,
    pattern_len: int = 512,
    timeout_s: float = 6.0,
) -> ToolResult:
    """
    Measure offset to saved return address.
    Prefers static source annotation parsing (exact, no binary execution).
    Falls back to pwntools process + corefile if source parsing fails.
    """
    # ── Tier 1: source annotation parsing (fast, exact, no execution) ─
    source_off = _try_source_offset_fallback(binary_path)
    if source_off:
        proof = {"method": "source_annotation", "estimated": source_off}
        return ToolResult(
            measured_facts={
                "offsets.ret_offset_bytes": source_off,
                "probe_artifacts.crash_offset_proof": json.dumps(proof, ensure_ascii=False),
            },
            unresolved_facts=[],
            notes=[f"ret_offset_bytes={source_off}", "method=source_annotation"],
        )

    try:
        from pwn import cyclic, cyclic_find, context, process, ELF  # type: ignore
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"pwntools_missing:{exc}"}],
            notes=[],
        )

    # ── detect architecture ──────────────────────────────────────────
    try:
        elf = ELF(binary_path, checksec=False)
        arch = getattr(elf, "arch", "") or ""
    except Exception:
        arch = ""
    is_64bit = arch == "amd64" or arch == "aarch64"
    n = 8 if is_64bit else 4
    word_bytes = 8 if is_64bit else 4

    # ── run binary + send cyclic pattern ─────────────────────────────
    context.log_level = "error"
    pattern = cyclic(int(pattern_len), n=n)
    cwd = binary_path.rsplit("/", 1)[0]
    try:
        io = process(binary_path, cwd=cwd)
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"process_spawn_error:{exc}"}],
            notes=[],
        )

    crash_output = ""
    fault_addr = None

    # ── General-purpose IO prompt auto-detection ──────────────────────
    def _is_prompt(line: str) -> bool:
        s = line.strip().lower()
        if not s:
            return False
        if s.endswith((":", "?", ")", "]", ">")):
            return True
        for kw in ("input", "passwd", "password", "username", "name",
                    "choice", "select", "enter", "send", ">>", "> "):
            if kw in s:
                return True
        return False

    def _sniff_and_navigate(io_obj) -> str:
        """Navigate all IO prompts by sending dummy data. Return the LAST prompt (unanswered)."""
        all_text = ""
        try:
            out = io_obj.recv(timeout=1.0)
            all_text = out.decode("latin-1", errors="ignore") if isinstance(out, bytes) else str(out)
        except Exception:
            pass
        # Auto-detect menu: numbered choices like "1.Login", "2.Exit"
        if re.search(r"\b[1-9]\.[A-Za-z]", all_text):
            try:
                io_obj.sendline(b"1")
                time.sleep(0.3)
                more = io_obj.recv(timeout=1.0)
                all_text += more.decode("latin-1", errors="ignore") if isinstance(more, bytes) else str(more)
            except Exception:
                pass
        # Navigate prompts: send dummy to each, recv for next
        # Stop when no more prompts appear (ready to send payload)
        for _ in range(5):  # max 5 prompt rounds
            cur_prompts = [l.strip() for l in all_text.split("\n") if _is_prompt(l.strip())]
            # Check only the LAST prompt in the latest output (new prompts at end)
            new_prompts = [l.strip() for l in all_text.split("\n")[-20:] if _is_prompt(l.strip())]
            if not new_prompts:
                break
            last = new_prompts[-1]
            # Only send dummy if we've detected MORE than one prompt total so far AND
            # the current last prompt hasn't been answered yet (we haven't sent to it)
            if len(cur_prompts) <= 1:
                break  # Only one prompt total, this is the target
            try:
                io_obj.sendline(b"AAAA")
            except Exception:
                break
            try:
                time.sleep(0.3)
                more = io_obj.recv(timeout=1.0)
                all_text += more.decode("latin-1", errors="ignore") if isinstance(more, bytes) else str(more)
            except Exception:
                break
        # Return the very last detected prompt
        final_prompts = [l.strip() for l in all_text.split("\n") if _is_prompt(l.strip())]
        return final_prompts[-1] if final_prompts else ""

    try:
        last_prompt = _sniff_and_navigate(io)
        if last_prompt:
            io.sendlineafter(last_prompt.encode() if isinstance(last_prompt, str) else last_prompt, pattern)
        else:
            io.send(pattern)
    except Exception:
        try:
            io.send(pattern)
        except Exception:
            pass
        # Give the binary time to read, overflow and crash.
        time.sleep(0.3)
        try:
            io.recvall(timeout=1.0)
        except Exception:
            pass
        io.wait(timeout=1.5)

        # ── attempt corefile extraction ──────────────────────────────
        try:
            core = io.corefile
            if core is not None:
                fault_addr = getattr(core, "fault_addr", None)
                if fault_addr is None and hasattr(core, "registers"):
                    # Fallback: read the value that *would have been* popped
                    # as the return address.  On x86-64 a non-canonical
                    # return address causes #GP *at* the ret instruction
                    # so RIP in the core points to ret, not to the pattern.
                    # The value that caused the fault is at [rsp] at crash
                    # time (before ret pops it).
                    try:
                        rsp_name = "rsp" if is_64bit else "esp"
                        rsp = getattr(core, rsp_name, None)
                        if rsp is None and hasattr(core, "registers"):
                            regs = core.registers
                            rsp = regs.get(rsp_name) if isinstance(regs, dict) else getattr(regs, rsp_name, None)
                        if rsp is not None:
                            fault_addr = core.read(rsp, word_bytes)
                            if fault_addr is not None:
                                fault_addr = int.from_bytes(fault_addr, "little")
                    except Exception:
                        pass
        except Exception:
            fault_addr = None

        try:
            crash_output = (io.recvall(timeout=0.5) or b"").decode(errors="ignore")
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            io.close()
        except Exception:
            pass

    # ── resolve offset from fault address ────────────────────────────
    if fault_addr is None or fault_addr == 0:
        # If the process exited cleanly (no crash), corefile won't exist.
        # This happens when the binary has IO interaction (prompts, menus)
        # and the input didn't reach the vulnerable path.
        exit_code = io.poll()
        if exit_code is not None and exit_code >= 0:
            # === 改动3: 尝试从反汇编估算 offset ===
            estimated = _try_disasm_offset_fallback(binary_path, is_64bit)
            if estimated:
                return ToolResult(
                    measured_facts={
                        "offsets.ret_offset_bytes": estimated,
                        "probe_artifacts.crash_offset_proof": json.dumps(
                            {"method": "disasm_frame_analysis", "estimated": estimated},
                            ensure_ascii=False,
                        ),
                    },
                    unresolved_facts=[],
                    notes=[f"estimated_ret_offset={estimated}", "method=disasm_frame_fallback"],
                )
            return ToolResult(
                measured_facts={},
                unresolved_facts=[{
                    "key": "offsets.ret_offset_bytes",
                    "reason": f"binary_exited_cleanly_exit_{exit_code}:binary may have IO prompts, need interactive measurement"
                }],
                notes=[f"exit_code={exit_code}", crash_output[-400:]],
            )
        # Process crashed but no core file available — use GDB fallback.
        return _tool_stack_measure_ret_offset_gdb_fallback(
            binary_path, pattern_len=pattern_len, timeout_s=timeout_s
        )

    try:
        off = int(cyclic_find(fault_addr.to_bytes(word_bytes, "little"), n=n))
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"cyclic_find_error:{exc}"}],
            notes=[f"fault_addr=0x{fault_addr:x}", crash_output[-800:]],
        )

    if off < 1:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"invalid_offset:{off}"}],
            notes=[f"fault_addr=0x{fault_addr:x}", crash_output[-800:]],
        )

    proof = {
        "fault_addr": f"0x{fault_addr:x}",
        "arch": arch,
        "word_bytes": word_bytes,
        "cyclic_n": n,
        "pattern_len": pattern_len,
        "crash_output_tail": crash_output[-800:],
    }
    return ToolResult(
        measured_facts={
            "offsets.ret_offset_bytes": off,
            "probe_artifacts.crash_offset_proof": json.dumps(proof, ensure_ascii=False),
        },
        unresolved_facts=[],
        notes=[f"ret_offset_bytes={off}", f"arch={arch}", f"method=corefile"],
    )


def _tool_stack_measure_ret_offset_gdb_fallback(
    binary_path: str,
    *,
    pattern_len: int = 512,
    timeout_s: float = 6.0,
) -> ToolResult:
    """
    GDB-based fallback for environments where core dumps are unavailable.
    Handles the 64-bit non-canonical address issue by reading the value at
    RSP when the crash occurs at the ret instruction (code address).
    """
    try:
        from pwn import cyclic, cyclic_find  # type: ignore
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"pwntools_missing:{exc}"}],
            notes=[],
        )

    # Detect arch for the fallback too.
    try:
        from pwn import ELF  # type: ignore
        elf = ELF(binary_path, checksec=False)
        arch = getattr(elf, "arch", "") or ""
    except Exception:
        arch = ""
    is_64bit = arch == "amd64" or arch == "aarch64"
    n = 8 if is_64bit else 4
    word_bytes = 8 if is_64bit else 4

    pattern = cyclic(int(pattern_len), n=n)
    gdb_cmds = "\n".join(
        [
            "set pagination off",
            "set confirm off",
            "run <<< $(python3 -c \"import sys; sys.stdout.buffer.write(" + repr(pattern) + ")\")",
            "info registers",
            "x/gx $rsp" if is_64bit else "x/wx $esp",
            "quit",
        ]
    )
    # Find gdb — may not be in the conda env PATH.
    import shutil
    gdb_bin = shutil.which("gdb")
    if not gdb_bin:
        # Check common conda env paths
        for candidate in (
            "/usr/bin/gdb",
            "/home/fyc/miniconda3/envs/pwngpt/bin/gdb",
        ):
            if os.path.exists(candidate):
                gdb_bin = candidate
                break
    if not gdb_bin:
        gdb_bin = "/usr/bin/gdb"  # final fallback, will fail with clear error
    try:
        proc = subprocess.run(
            [gdb_bin, "-q", "--args", binary_path],
            input=gdb_cmds.encode(),
            capture_output=True,
            timeout=timeout_s,
            check=False,
            cwd=binary_path.rsplit("/", 1)[0],
        )
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"gdb_error:{exc}"}],
            notes=[],
        )

    out = (proc.stdout or b"").decode(errors="ignore") + "\n" + (proc.stderr or b"").decode(errors="ignore")

    # Strategy: try to find a value in registers or stack that matches the
    # cyclic pattern.  Prefer the value at [RSP] (the return address that
    # caused the crash) over RIP (which may be the ret instruction itself
    # on 64-bit due to non-canonical address #GP).
    reg_val = None

    # Try to read the value at RSP/ESP from the "x/gx $rsp" output.
    rsp_line = re.search(
        r"0x[0-9a-fA-F]+\s+<\w+\+?\d*>\s*:\s*(0x[0-9a-fA-F]+)",
        out,
    )
    if not rsp_line:
        # Simpler: just look for a hex value after the address
        rsp_line = re.search(r"0x[0-9a-fA-F]+\s+:\s+(0x[0-9a-fA-F]+)", out)
    if rsp_line:
        try:
            reg_val = int(rsp_line.group(1), 16)
        except Exception:
            pass

    # Fallback: try EIP/RIP
    if reg_val is None:
        m = re.search(r"\b(eip|rip)\s+0x([0-9a-fA-F]+)", out)
        if m:
            try:
                val = int(m.group(2), 16)
                # Only use RIP if it looks like a cyclic pattern value (not a
                # code address).  Code addresses are typically in the binary's
                # .text range (0x400xxx-0x4xxxxx or 0x0804xxxx).
                # If the value is in a known code range, it's the ret
                # instruction itself, not the corrupted return address.
                if is_64bit and 0x400000 <= val <= 0x4FFFFF:
                    pass  # code address, not useful — already tried RSP
                elif not is_64bit and 0x08040000 <= val <= 0x08100000:
                    pass  # 32-bit code address
                else:
                    reg_val = val
            except Exception:
                pass

    if reg_val is None:
        # === 改动3: 从反汇编栈帧布局估算 offset（canary/PIE fallback）===
        estimated = _try_disasm_offset_fallback(binary_path, is_64bit)
        if estimated:
            return ToolResult(
                measured_facts={
                    "offsets.ret_offset_bytes": estimated,
                    "probe_artifacts.crash_offset_proof": json.dumps(
                        {"method": "disasm_frame_analysis", "estimated": estimated},
                        ensure_ascii=False,
                    ),
                },
                unresolved_facts=[],
                notes=[f"estimated_ret_offset={estimated}", "method=disasm_frame_fallback"],
            )
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": "no_usable_address_in_gdb_output"}],
            notes=[out[-800:]],
        )

    try:
        off = int(cyclic_find(reg_val.to_bytes(word_bytes, "little"), n=n))
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"cyclic_find_error:{exc}"}],
            notes=[f"reg_val=0x{reg_val:x}", out[-800:]],
        )

    if off < 1:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "offsets.ret_offset_bytes", "reason": f"invalid_offset:{off}"}],
            notes=[f"reg_val=0x{reg_val:x}", out[-800:]],
        )

    proof = {"reg_val": f"0x{reg_val:x}", "arch": arch, "pattern_len": pattern_len, "method": "gdb_fallback"}
    return ToolResult(
        measured_facts={
            "offsets.ret_offset_bytes": off,
            "probe_artifacts.crash_offset_proof": json.dumps(proof, ensure_ascii=False),
        },
        unresolved_facts=[],
        notes=[f"ret_offset_bytes={off}", f"arch={arch}", "method=gdb_fallback"],
    )


def _try_source_offset_fallback(binary_path: str) -> Optional[int]:
    """Extract exact ret offset from C source annotations in problem text / decompiled .c files.

    Hex-Rays annotations: char buf[136]; // [esp+10h] [ebp-88h]
    Offset to return addr = ebp_offset + 4.

    Heuristic: find the overflow-prone function (strcpy/gets/read with large count)
    and use the largest buffer offset within that function.
    """
    import os as _os
    binary_dir = _os.path.dirname(binary_path)
    all_files = sorted([f for f in _os.listdir(binary_dir) if f.endswith((".c", ".txt"))]
                       if _os.path.isdir(binary_dir) else [])
    # Prioritize problems.txt and smaller .c files (decompiled source)
    all_files.sort(key=lambda f: (0 if "problem" in f.lower() else 1, f))

    # Merge all source content
    content = ""
    for c_file in all_files:
        try:
            content += open(_os.path.join(binary_dir, c_file), encoding="utf-8", errors="ignore").read()
        except Exception:
            continue

    if not content:
        return None

    # Find function blocks: //----- (ADDR) -----\n return_type func_name(args)
    func_blocks = re.split(r"//----- \(0?x?[0-9a-fA-F]+\) -+", content)

    def _is_overflow_func(block: str) -> bool:
        """Check if a function contains overflow-prone operations."""
        return bool(re.search(
            r"\b(strcpy|gets|read|fgets|scanf|recv)\s*\(",
            block,
        ))

    def _largest_ebp_in_block(block: str) -> Optional[int]:
        best = None
        for m in re.finditer(r"\[([er])bp-([0-9a-fA-F]+)h\]", block):
            reg = m.group(1)  # 'e' = 32-bit, 'r' = 64-bit
            saved_bp = 8 if reg == 'r' else 4
            off = int(m.group(2), 16) + saved_bp
            if 8 <= off <= 2048 and (best is None or off > best):
                best = off
        return best

    # Strategy 1: INT — function with uint8 + strlen (integer overflow marker)
    for block in func_blocks:
        if re.search(r"unsigned\s+__int8", block) and "strlen" in block:
            off = _largest_ebp_in_block(block)
            if off:
                return off

    # Strategy 2: function with strcpy/gets (classic overflow)
    for block in func_blocks:
        if re.search(r"\b(strcpy|gets)\s*\(", block):
            off = _largest_ebp_in_block(block)
            if off:
                return off

    # Strategy 3: function with read/fgets (ROP-style overflow)
    for block in func_blocks:
        if re.search(r"\b(read|fgets|scanf|recv)\s*\(", block):
            off = _largest_ebp_in_block(block)
            if off:
                return off

    # Strategy 4: any function with char buf[N] declarations
    for block in func_blocks:
        if re.search(r"char\s+\w+\s*\[", block):
            off = _largest_ebp_in_block(block)
            if off:
                return off

    # Strategy 3: just the largest ebp offset anywhere
    best = None
    for m in re.finditer(r"\[[er]bp-([0-9a-fA-F]+)h\]", content):
        off = int(m.group(1), 16) + 4
        if 8 <= off <= 2048 and (best is None or off > best):
            best = off
    return best


def _try_disasm_offset_fallback(binary_path: str, is_64bit: bool) -> Optional[int]:
    """Try to estimate ret offset from function prologue disassembly."""
    # Prefer source annotation (exact) over disasm (approximate)
    source_off = _try_source_offset_fallback(binary_path)
    if source_off:
        return source_off

    try:
        from pwn import ELF  # type: ignore
        elf = ELF(binary_path, checksec=False)
        # Search known vulnerable function names, then main, then any function with sub rsp
        best = None
        for func_name in ("vulnerable_function", "check_passwd", "validate_passwd", "hello", "get_flag", "login", "main"):
            addr = elf.symbols.get(func_name, 0)
            if not addr:
                continue
            disasm = elf.disasm(addr, 128)
            # AT&T syntax: sub $0x30, %rsp   OR   Intel syntax: sub rsp, 0x30
            sub_sp = re.search(r"sub\s+\$(0x[0-9a-fA-F]+),\s*%(?:rsp|esp)", disasm)
            if not sub_sp:
                sub_sp = re.search(r"sub\s+%(?:rsp|esp),\s*(0x[0-9a-fA-F]+)", disasm)
            if not sub_sp:
                sub_sp = re.search(r"sub\s+\$([0-9]+),\s*%(?:rsp|esp)", disasm)
            if not sub_sp:
                sub_sp = re.search(r"sub\s+%(?:rsp|esp),\s*([0-9]+)", disasm)
            if sub_sp:
                stack_alloc = int(sub_sp.group(1), 16 if sub_sp.group(1).startswith("0x") else 10)
                saved_rbp = 8 if is_64bit else 4
                estimated = stack_alloc + saved_rbp
                if 8 <= estimated <= 1024:
                    return estimated
        # Broad fallback: scan first 10 non-underscore functions for sub rsp
        func_count = 0
        for name, addr in sorted(elf.symbols.items(), key=lambda x: x[1]):
            if name.startswith("_") or func_count >= 10:
                continue
            try:
                disasm = elf.disasm(addr, 128)
            except Exception:
                continue
            sub_sp = re.search(r"sub\s+\$(0x[0-9a-fA-F]+),\s*%(?:rsp|esp)", disasm)
            if not sub_sp:
                sub_sp = re.search(r"sub\s+%(?:rsp|esp),\s*(0x[0-9a-fA-F]+)", disasm)
            if not sub_sp:
                sub_sp = re.search(r"sub\s+\$([0-9]+),\s*%(?:rsp|esp)", disasm)
            if not sub_sp:
                sub_sp = re.search(r"sub\s+%(?:rsp|esp),\s*([0-9]+)", disasm)
            if sub_sp:
                stack_alloc = int(sub_sp.group(1), 16 if sub_sp.group(1).startswith("0x") else 10)
                saved_rbp = 8 if is_64bit else 4
                estimated = stack_alloc + saved_rbp
                if 8 <= estimated <= 1024:
                    if best is None or stack_alloc > best[0]:
                        best = (stack_alloc, estimated)
            func_count += 1
        if best:
            return best[1]
        return None
    except Exception:
        return None


def tool_int_boundary_sweep(
    binary_path: str,
    *,
    candidates: Optional[List[int]] = None,
    timeout_s: float = 1.2,
) -> ToolResult:
    """
    Minimal integer boundary sweep. Returns probe_artifacts.int_boundary_results.
    This is a scaffold; planner/decider can interpret results.
    """
    vals = candidates or [-1, 0, 1, 2, 10, 127, 255, 256, 1024, 2147483647, 4294967295]
    results = []
    for v in vals[:30]:
        rc, out = _run_once(binary_path, str(v).encode(), timeout_s=timeout_s)
        results.append({"value": v, "exit_code": rc, "out_tail": out[-200:]})
    return ToolResult(
        measured_facts={"probe_artifacts.int_boundary_results": results},
        unresolved_facts=[],
        notes=[f"tested={len(results)}"],
    )


def tool_heap_ltrace_malloc_free(
    binary_path: str,
    *,
    timeout_s: float = 2.0,
) -> ToolResult:
    """
    Minimal heap trace scaffold using ltrace if available.
    Returns probe_artifacts.heap_trace_raw.
    """
    try:
        proc = subprocess.run(
            ["ltrace", "-f", "-e", "malloc+free+realloc+calloc", binary_path],
            capture_output=True,
            timeout=timeout_s,
            check=False,
            cwd=binary_path.rsplit("/", 1)[0],
            input=b"",
        )
        out = (proc.stdout or b"").decode(errors="ignore") + "\n" + (proc.stderr or b"").decode(errors="ignore")
        return ToolResult(
            measured_facts={"probe_artifacts.heap_trace_raw": out[-20000:]},
            unresolved_facts=[],
            notes=["ltrace_ok"],
        )
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "probe_artifacts.heap_trace_raw", "reason": f"ltrace_error:{exc}"}],
            notes=[],
        )


def tool_run_command(
    binary_path: str,
    *,
    command: str = "",
    timeout_s: float = 8.0,
    output_key: str = "probe_artifacts.command_output",
) -> ToolResult:
    """
    Nyuctf-style generic measurement tool:
    run one shell command and capture structured result.
    """
    if not command.strip():
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": output_key, "reason": "empty_command"}],
            notes=[],
        )
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=max(0.5, float(timeout_s)),
            check=False,
            cwd=binary_path.rsplit("/", 1)[0],
        )
        payload = {
            "command": command,
            "exit_code": int(proc.returncode),
            "stdout_tail": str(proc.stdout or "")[-4000:],
            "stderr_tail": str(proc.stderr or "")[-4000:],
        }
        measured_facts: Dict[str, Any] = {output_key: payload}
        unresolved_facts: List[Dict[str, str]] = []
        stdout_all = str(proc.stdout or "")
        if "PROBE_RESULT_JSON_START" in stdout_all and "PROBE_RESULT_JSON_END" in stdout_all:
            try:
                chunk = stdout_all.split("PROBE_RESULT_JSON_START", 1)[1].split("PROBE_RESULT_JSON_END", 1)[0].strip()
                parsed = json.loads(chunk)
                if isinstance(parsed, dict):
                    mf = parsed.get("measured_facts", {}) or {}
                    uf = parsed.get("unresolved_facts", []) or []
                    if isinstance(mf, dict):
                        measured_facts.update(mf)
                    if isinstance(uf, list):
                        unresolved_facts.extend([x for x in uf if isinstance(x, dict)])
            except Exception:
                pass
        return ToolResult(
            measured_facts=measured_facts,
            unresolved_facts=unresolved_facts,
            notes=[f"run_command_exit={proc.returncode}"],
        )
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": output_key, "reason": f"run_command_error:{exc}"}],
            notes=[],
        )


def tool_disassemble(
    binary_path: str,
    *,
    function: str = "main",
    output_key: str = "",
) -> ToolResult:
    key = output_key or f"probe_artifacts.disassemble_{function}"
    try:
        proc = subprocess.run(
            ["objdump", "-d", "--disassemble=" + function, binary_path],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
            cwd=binary_path.rsplit("/", 1)[0],
        )
        blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if not blob.strip():
            return ToolResult(
                measured_facts={},
                unresolved_facts=[{"key": key, "reason": "empty_disassembly"}],
                notes=[],
            )
        return ToolResult(measured_facts={key: blob[-30000:]}, unresolved_facts=[], notes=["disassemble_ok"])
    except Exception as exc:
        return ToolResult(measured_facts={}, unresolved_facts=[{"key": key, "reason": f"disassemble_error:{exc}"}], notes=[])


def tool_decompile(
    binary_path: str,
    *,
    function: str = "main",
    output_key: str = "",
) -> ToolResult:
    key = output_key or f"probe_artifacts.decompile_{function}"
    # Lightweight fallback if ghidra wrappers are unavailable in current env.
    cmd = f"strings -a '{binary_path}' | sed -n '1,240p'"
    return tool_run_command(binary_path, command=cmd, timeout_s=8.0, output_key=key)


def tool_create_file(
    binary_path: str,
    *,
    path: str = "",
    content: str = "",
    output_key: str = "probe_artifacts.created_file",
) -> ToolResult:
    if not path.strip():
        return ToolResult(measured_facts={}, unresolved_facts=[{"key": output_key, "reason": "missing_path"}], notes=[])
    try:
        from pathlib import Path

        p = Path(path)
        if not p.is_absolute():
            p = Path(binary_path).resolve().parent / p
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return ToolResult(
            measured_facts={output_key: {"path": str(p), "size": len(content)}},
            unresolved_facts=[],
            notes=["create_file_ok"],
        )
    except Exception as exc:
        return ToolResult(measured_facts={}, unresolved_facts=[{"key": output_key, "reason": f"create_file_error:{exc}"}], notes=[])

def tool_pwntools_symbols(
    binary_path: str,
    *,
    names: Optional[List[str]] = None,
    output_key: str = "symbols",
) -> ToolResult:
    """
    Resolve symbol addresses via pwntools ELF (nm fallback).
    If names not provided, auto-discovers: x, win, flag, magic, backdoor, passwd, get_flag, not_called, EZ_WIN.
    """
    default_names = ["x", "win", "flag", "magic", "backdoor", "passwd", "get_flag", "not_called", "EZ_WIN", "main"]
    targets = [n for n in (names or default_names) if n.strip()]
    measured: Dict[str, Any] = {}
    unresolved: List[Dict[str, str]] = []
    try:
        from pwn import ELF  # type: ignore
        elf = ELF(binary_path, checksec=False)
        for name in targets:
            addr = elf.symbols.get(name)
            if addr and addr > 0:
                measured[f"symbols.{name}"] = hex(addr)
            else:
                unresolved.append({"key": f"symbols.{name}", "reason": "not_found"})
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": output_key, "reason": f"pwntools_symbols_error:{exc}"}],
            notes=[],
        )
    return ToolResult(
        measured_facts=measured,
        unresolved_facts=unresolved,
        notes=[f"pwntools_symbols_found={len(measured)}"],
    )


def tool_run_binary_with_payload(
    binary_path: str,
    *,
    payload: str = "",
    timeout_s: float = 2.0,
    output_key: str = "probe_artifacts.binary_output",
) -> ToolResult:
    """
    Run the binary with a given payload (string or bytes) and capture output.
    Useful for interactive measurement when other tools fail.
    """
    try:
        from pwn import context, process  # type: ignore
        context.log_level = "error"
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": output_key, "reason": f"pwntools_missing:{exc}"}],
            notes=[],
        )
    p = payload.encode() if isinstance(payload, str) else (payload or b"")
    try:
        io = process(binary_path, cwd=binary_path.rsplit("/", 1)[0])
        if p:
            io.sendline(p)
        out = io.recvall(timeout=timeout_s) or b""
        io.close()
        out_text = out.decode("latin-1", errors="ignore")
        return ToolResult(
            measured_facts={output_key: out_text[:8000]},
            unresolved_facts=[],
            notes=["run_binary_ok"],
        )
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": output_key, "reason": f"run_binary_error:{exc}"}],
            notes=[],
        )


def tool_rop_find_gadgets(binary_path: str) -> ToolResult:
    """Find key ROP gadgets using pwntools ROP(). Returns pop_rdi, ret, pop_rsi etc."""
    try:
        from pwn import ELF, ROP  # type: ignore
        elf = ELF(binary_path)
        rop = ROP(elf)
        measured: Dict[str, Any] = {}
        for name, regs in [
            ("pop_rdi_ret", ["pop rdi", "ret"]),
            ("pop_rsi_ret", ["pop rsi", "ret"]),
            ("ret", ["ret"]),
        ]:
            try:
                g = rop.find_gadget(regs)
                if g:
                    measured[f"gadgets.{name}"] = hex(g[0])
            except Exception:
                pass
        if not measured:
            return ToolResult(
                measured_facts={},
                unresolved_facts=[{"key": "gadgets.*", "reason": "no_gadgets_found"}],
                notes=["gadget_search: no results"],
            )
        return ToolResult(measured_facts=measured, unresolved_facts=[], notes=["gadget_search_ok"])
    except Exception as exc:
        return ToolResult(
            measured_facts={},
            unresolved_facts=[{"key": "gadgets.*", "reason": f"gadget_search_error:{exc}"}],
            notes=[],
        )


TOOLS: Dict[str, Callable[..., ToolResult]] = {
    "fmt_measure_s_offset": tool_fmt_measure_s_offset,
    "fmt_measure_p_offset": tool_fmt_measure_p_offset,
    "fmt_measure_write_offset": tool_fmt_measure_write_offset,
    "fmt_scan_stack": tool_fmt_scan_stack,
    "pwntools_got": tool_pwntools_got,
    "pwntools_symbols": tool_pwntools_symbols,
    "run_binary_with_payload": tool_run_binary_with_payload,
    "stack_measure_ret_offset_gdb": tool_stack_measure_ret_offset_gdb,
    "int_boundary_sweep": tool_int_boundary_sweep,
    "heap_ltrace_malloc_free": tool_heap_ltrace_malloc_free,
    "run_command": tool_run_command,
    "disassemble": tool_disassemble,
    "decompile": tool_decompile,
    "create_file": tool_create_file,
    "rop_find_gadgets": tool_rop_find_gadgets,
}


def run_actions(actions: List[Dict[str, Any]], *, binary_path: str) -> ToolResult:
    measured: Dict[str, Any] = {}
    unresolved: List[Dict[str, str]] = []
    notes: List[str] = []
    action_results: List[Dict[str, Any]] = []

    for a in actions:
        tool = str(a.get("tool") or "")
        args = a.get("args") or {}
        request_id = str(a.get("request_id", "") or "")
        action_id = str(a.get("action_id", "") or "")
        if tool not in TOOLS:
            unresolved.append({"key": "*", "reason": f"unknown_tool:{tool}"})
            action_results.append(
                {
                    "request_id": request_id,
                    "action_id": action_id,
                    "tool": tool,
                    "status": "error",
                    "error": f"unknown_tool:{tool}",
                    "measured_keys": [],
                    "unresolved_count": 1,
                }
            )
            continue
        fn = TOOLS[tool]
        try:
            # all tools accept binary_path as first arg
            res = fn(binary_path, **(args if isinstance(args, dict) else {}))
        except Exception as exc:
            unresolved.append({"key": "*", "reason": f"tool_exec_error:{tool}:{exc}"})
            action_results.append(
                {
                    "request_id": request_id,
                    "action_id": action_id,
                    "tool": tool,
                    "status": "error",
                    "error": f"tool_exec_error:{tool}:{exc}",
                    "measured_keys": [],
                    "unresolved_count": 1,
                }
            )
            continue
        measured.update(res.measured_facts)
        for item in (res.unresolved_facts or []):
            if isinstance(item, dict):
                item.setdefault("request_id", request_id)
            unresolved.append(item)
        notes.extend(res.notes)
        action_results.append(
            {
                "request_id": request_id,
                "action_id": action_id,
                "tool": tool,
                "status": "ok" if not res.unresolved_facts else "partial",
                "measured_keys": sorted((res.measured_facts or {}).keys()),
                "unresolved_count": len(res.unresolved_facts or []),
                "notes": list(res.notes or [])[:8],
            }
        )
        time.sleep(0.05)

    return ToolResult(
        measured_facts=measured,
        unresolved_facts=unresolved,
        notes=notes[:40],
        action_results=action_results,
    )

