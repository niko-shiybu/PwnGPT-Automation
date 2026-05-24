from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from automation.schemas import BinaryInfo, Evidence


def _run(cmd: List[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return out.strip()
    except Exception as exc:  # pragma: no cover
        return f"[collector-error] {' '.join(cmd)}: {exc}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_arch(file_output: str) -> str:
    text = file_output.lower()
    if "64-bit" in text:
        return "x86_64"
    if "32-bit" in text:
        return "i386"
    return "unknown"


def _parse_checksec_features(checksec_output: str, arch: str) -> Dict[str, Any]:
    lower = checksec_output.lower()
    bits = 64 if arch == "x86_64" else 32 if arch == "i386" else None
    return {
        "arch_bits": bits,
        "nx": "nx enabled" in lower,
        "pie": "pie enabled" in lower,
        "canary": "canary found" in lower,
        "relro": "full" if "full relro" in lower else "partial" if "partial relro" in lower else "none",
    }


def _detect_runtime(binary: Path, repo_root: Path) -> Dict[str, Any]:
    runtime: Dict[str, Any] = {"aslr_enabled": None, "libc_path": "", "libc_version": ""}
    aslr_path = Path("/proc/sys/kernel/randomize_va_space")
    if aslr_path.exists():
        try:
            runtime["aslr_enabled"] = int(aslr_path.read_text(encoding="utf-8").strip()) > 0
        except Exception:
            runtime["aslr_enabled"] = None

    ldd_out = _run(["ldd", str(binary)], repo_root)
    libc_line = ""
    for line in ldd_out.splitlines():
        if "libc.so.6" in line:
            libc_line = line.strip()
            break
    if libc_line:
        m = re.search(r"=>\s+(\S+)\s+\(", libc_line)
        if m:
            runtime["libc_path"] = m.group(1)
            libc_path = Path(m.group(1))
            if libc_path.exists():
                version_out = _run([str(libc_path)], repo_root)
                vm = re.search(r"release version\s+([0-9.]+)", version_out.lower())
                if vm:
                    runtime["libc_version"] = vm.group(1)
    return runtime


def _extract_prompts(blob: str) -> List[str]:
    candidates = []
    # Collect simple prompt-like lines to help sync IO
    for line in blob.splitlines():
        s = line.strip()
        if not s:
            continue
        if any(x in s for x in ["Choice:", "Index:", "passwd", "username", "meme size", "content"]):
            candidates.append(s)
    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq[:30]


def _build_interaction_model(prompts: List[str]) -> Dict[str, Any]:
    input_kind_map = {}
    for p in prompts:
        p_l = p.lower()
        if any(k in p_l for k in ["choice", "index", "size", "number", "len"]):
            input_kind_map[p] = "int"
        else:
            input_kind_map[p] = "str"
    return {
        "prompt_sequence": prompts[:12],
        "input_kind_map": input_kind_map,
    }


def _extract_symbols(sym_output: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    pattern = re.compile(r"([0-9a-fA-F]{8,16})\s+\w+\s+\w+\s+\w+\s+\w+\s+([A-Za-z_][A-Za-z0-9_@.]*)$")
    for line in sym_output.splitlines():
        m = pattern.search(line.strip())
        if not m:
            continue
        addr, name = m.group(1), m.group(2)
        if name in {"main", "system", "puts", "printf", "write", "read", "gets", "strcpy"}:
            out[name] = f"0x{addr.lower()}"
        if name in {"x", "passwd_buf", "EZ_WIN", "magic", "not_called", "get_flag"}:
            out[name] = f"0x{addr.lower()}"
    return out


def _parse_nm_symbols(nm_out: str) -> Dict[str, str]:
    """
    Parse `nm -n` output lines: <addr> <type> <name>
    Return name -> 0xaddr (lowercase).
    """
    out: Dict[str, str] = {}
    for line in (nm_out or "").splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^([0-9a-fA-F]{8,16})\s+([A-Za-z])\s+([A-Za-z_][A-Za-z0-9_@.]*)$", s)
        if not m:
            continue
        addr, _typ, name = m.group(1), m.group(2), m.group(3)
        out[name] = f"0x{addr.lower()}"
    return out


def _extract_c_sources(problem_path: Path, binary_path: Path) -> Dict[str, str]:
    """
    Heuristic: bundle nearby .c files for LLM audit.
    - Prefer same directory as problem or binary.
    - Keep per-file truncation to avoid huge evidence.
    """
    candidates: List[Path] = []
    for base in [problem_path.parent, binary_path.parent]:
        if base.exists():
            candidates.extend(sorted(base.glob("*.c")))
    # Dedup while preserving order
    seen = set()
    uniq: List[Path] = []
    for p in candidates:
        rp = str(p.resolve())
        if rp in seen:
            continue
        seen.add(rp)
        uniq.append(p)
    sources: Dict[str, str] = {}
    for p in uniq[:6]:
        try:
            sources[str(p)] = p.read_text(encoding="utf-8", errors="ignore")[:60000]
        except Exception:
            continue
    return sources


def _extract_struct_defs_from_c(c_text: str) -> List[Dict[str, Any]]:
    """
    Lightweight struct extractor (text-level, not a C parser).
    Produces: [{"name":"Note","body":"...","fields":[...]}]
    """
    text = c_text or ""
    results: List[Dict[str, Any]] = []
    for m in re.finditer(r"typedef\s+struct\s*(\w+)?\s*\{(?P<body>[\s\S]{0,4000}?)\}\s*(?P<name>\w+)\s*;", text):
        body = m.group("body") or ""
        name = m.group("name") or (m.group(1) or "")
        fields = []
        for line in body.splitlines():
            ls = line.strip().rstrip(";")
            if not ls or ls.startswith("//") or ls.startswith("/*"):
                continue
            # naive: keep as raw field line
            fields.append(ls[:200])
        results.append({"name": name, "fields": fields[:40], "body": body[:2000]})
    return results[:20]


def collect_evidence(problem_path: str, binary_path: str, challenge_type: str, repo_root: Path) -> Evidence:
    binary = repo_root / binary_path
    exists = binary.exists()
    if exists and not os.access(binary, os.X_OK):
        try:
            os.chmod(str(binary), 0o755)
        except Exception:
            pass
    executable = os.access(binary, os.X_OK) if exists else False
    sha = _sha256(binary) if exists else None

    file_out = _run(["file", str(binary)], repo_root) if exists else "binary not found"
    checksec_out = "binary not found"
    if exists:
        checksec_out = _run(["checksec", f"--file={binary}"], repo_root)
        if "Unknown option file" in checksec_out or "unknown option" in checksec_out.lower():
            checksec_out = _run(["checksec", str(binary)], repo_root)
        if "No option selected" in checksec_out or "not found" in checksec_out.lower():
            bundled = repo_root / "checksec.sh" / "checksec.bash"
            if bundled.exists():
                checksec_out = _run([str(bundled), f"--file={binary}"], repo_root)
    readelf_out = _run(["readelf", "-s", str(binary)], repo_root) if exists else "binary not found"
    nm_out = _run(["nm", "-n", str(binary)], repo_root) if exists else "binary not found"
    strings_out = _run(["strings", "-tx", str(binary)], repo_root) if exists else "binary not found"

    prompts_blob = ""
    if exists:
        # Light, non-blocking prompt sniff: run with closed stdin.
        prompts_blob = _run(["bash", "-lc", f"\"{binary}\" </dev/null"], repo_root)
    problem_full = repo_root / problem_path
    if problem_full.exists():
        prompts_blob += "\n" + problem_full.read_text(encoding="utf-8", errors="ignore")
    prompts = _extract_prompts(prompts_blob)

    binary_info = BinaryInfo(
        path=str(binary),
        exists=exists,
        executable=executable,
        sha256=sha,
        arch=_parse_arch(file_out),
        checksec_raw=checksec_out,
    )

    symbols = {}
    symbols.update(_extract_symbols(readelf_out))
    # Add some symbols from nm output as fallback
    for name in ["x", "passwd_buf", "EZ_WIN", "magic", "not_called", "get_flag"]:
        m = re.search(rf"([0-9a-fA-F]{{8,16}})\s+\w\s+{name}$", nm_out, re.M)
        if m and name not in symbols:
            symbols[name] = f"0x{m.group(1).lower()}"

    found_strings = {}
    for needle in ["/bin/sh", "/bin/bash", "flag", "Choice:", "passwd", "username"]:
        m = re.search(rf"^([0-9a-fA-F]+)\s+.*{re.escape(needle)}.*$", strings_out, re.M)
        if m:
            found_strings[needle] = f"0x{m.group(1).lower()}"

    # Structured symbol maps for globals/funcs/got/plt.
    nm_map = _parse_nm_symbols(nm_out) if exists else {}
    readelf_map = _extract_symbols(readelf_out) if exists else {}
    # Prefer readelf extracted subset for funcs/globals; nm_map for broad fallback.
    funcs = {}
    globals_ = {}
    # === 改动1: 从 problems.txt 自动提取函数名加入白名单 ===
    problem_text = ""
    if problem_full.exists():
        problem_text = problem_full.read_text(encoding="utf-8", errors="ignore")
    _known_funcs = {"main", "win", "backdoor", "get_flag", "not_called", "EZ_WIN", "magic"}
    # Scan problem text for function-like names: C decompiled output format
    # "//----- (0xADDR) -----\nint func_name(" or "void func_name("
    for m in re.finditer(r"(?:int|void|char|ssize_t|unsigned|__int64|size_t|bool)\s+[\*]*\s*(\w+)\s*\(", problem_text):
        _known_funcs.add(m.group(1))
    # Also scan for "T func_name\n" in nm output for relevant names
    _extra_from_nm: set[str] = set()
    for line in (nm_out or "").splitlines():
        m = re.match(r"^[0-9a-fA-F]+\s+[Tt]\s+(\w+)$", line.strip())
        if m:
            _extra_from_nm.add(m.group(1))
    # Intersect with problem text: keep functions mentioned in the problem
    for name in _known_funcs:
        if name in nm_map:
            funcs[name] = nm_map[name]
    # === 改动2: 静态二进制（无PLT）放宽符号过滤 ===
    # For static binaries, include more functions from nm_map
    for k, v in {**nm_map, **readelf_map}.items():
        if k in _known_funcs:
            funcs.setdefault(k, v)
        if k in {"x", "passwd_buf"}:
            globals_[k] = v
    # GOT/PLT via pwntools if available.
    got: Dict[str, str] = {}
    plt: Dict[str, str] = {}
    if exists:
        try:
            from pwn import ELF  # type: ignore

            elf = ELF(str(binary), checksec=False)
            for name in ["printf", "puts", "read", "write", "gets", "system", "strcpy", "scanf"]:
                if name in elf.got:
                    got[name] = hex(int(elf.got[name]))
                if name in elf.plt:
                    plt[name] = hex(int(elf.plt[name]))
        except Exception:
            pass

    # === 改动2补: 静态二进制放宽符号过滤 ===
    _is_static = (not plt) and (not got)
    if _is_static and nm_map:
        # Include all non-underscore functions from nm, up to 80
        _count = 0
        for _k, _v in sorted(nm_map.items()):
            if _k in funcs:
                continue
            if _k.startswith("_") or _k.startswith("__") or len(_k) > 50:
                continue
            if _count >= 80:
                break
            funcs[_k] = _v
            _count += 1
        # Also extract key gadgets: pop_*, ret, int_0x80, syscall, call_*
        for _k, _v in nm_map.items():
            _kl = _k.lower()
            if any(_kl.startswith(p) for p in ("pop_", "ret", "syscall", "int_0x80")) and _k not in funcs:
                funcs[_k] = _v

    # Bundle C sources for planner/decider audit.
    problem_full = repo_root / problem_path
    sources = _extract_c_sources(problem_full, binary) if exists else {}
    struct_defs: List[Dict[str, Any]] = []
    for _p, content in list(sources.items())[:3]:
        struct_defs.extend(_extract_struct_defs_from_c(content))

    evidence = Evidence(
        challenge_type=challenge_type,
        problem_path=str(repo_root / problem_path),
        binary=binary_info,
        symbols=symbols,
        symbols_map={"globals": globals_, "funcs": funcs, "got": got, "plt": plt},
        strings=found_strings,
        strings_raw=strings_out.splitlines()[:300] if strings_out and strings_out != "binary not found" else [],
        sources=sources,
        struct_defs=struct_defs,
        io_prompts=prompts,
        binary_features=_parse_checksec_features(checksec_out, binary_info.arch or "unknown"),
        runtime=_detect_runtime(binary, repo_root) if exists else {},
        interaction_model=_build_interaction_model(prompts),
    )
    bits = evidence.binary_features.get("arch_bits")
    if bits:
        evidence.constraints["pointer_width"] = bits // 8
        evidence.provenance["constraints.pointer_width"] = "measured"
    if challenge_type == "heap":
        evidence.constraints["heap_menu_model"] = "unknown"
        evidence.constraints["heap_primitive"] = "unknown"
    if challenge_type in {"int", "rop"}:
        evidence.probe_artifacts["crash_offset_proof"] = ""
    if challenge_type == "rop":
        evidence.probe_artifacts["gadget_inventory"] = {}
    if challenge_type == "heap":
        evidence.probe_artifacts["heap_trace"] = []
    if not exists:
        evidence.notes.append("binary_missing")
    if exists and not executable:
        evidence.notes.append("binary_not_executable")
    return evidence
