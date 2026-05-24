from __future__ import annotations

import re
from typing import Any, Dict

from automation.audit.audit_report import AuditReport
from automation.audit.auditors.base_auditor import AnalysisContext, add_finding, _str_to_bool


def run_generic_checks(ctx: AnalysisContext, report: AuditReport) -> None:
    _check_pack_size(ctx, report)
    _check_symbol_exists(ctx, report)
    _check_variable_defined(ctx, report)
    _check_recv_size(ctx, report)
    _check_binary_as_libc(ctx, report)


# ---------------------------------------------------------------------------
# PACK_SIZE — CRITICAL
# ---------------------------------------------------------------------------

def _check_pack_size(ctx: AnalysisContext, report: AuditReport) -> None:
    if ctx.arch_bits is None:
        return
    payload_lines = [l for _, l in ctx.payload_lines] if ctx.payload_lines else []
    payload_text = " ".join(payload_lines)

    if ctx.arch_bits == 32 and "p64" in payload_text and not any(
        fn == "p32" for fn in [c["fn"] for c in ctx.pack_calls if c["line_no"] in {l for l, _ in ctx.payload_lines}]
    ):
        add_finding(report, "PACK_SIZE", "CRITICAL", "generic",
                    "payload construction",
                    f"Binary is 32-bit (arch={ctx.evidence.binary.arch}) but payload uses p64(). "
                    f"32-bit binaries require 4-byte addresses with p32(). Using p64() will produce "
                    f"8-byte values that corrupt the stack layout.",
                    "Replace all p64() calls with p32() in the payload construction.")

    if ctx.arch_bits == 64 and "p32" in payload_text and not any(
        fn == "p64" for fn in [c["fn"] for c in ctx.pack_calls if c["line_no"] in {l for l, _ in ctx.payload_lines}]
    ):
        add_finding(report, "PACK_SIZE", "CRITICAL", "generic",
                    "payload construction",
                    f"Binary is 64-bit (arch={ctx.evidence.binary.arch}) but payload uses p32(). "
                    f"64-bit binaries require 8-byte addresses with p64(). Using p32() will produce "
                    f"4-byte values that are too short to overwrite 64-bit return addresses.",
                    "Replace all p32() calls with p64() in the payload construction.")


# ---------------------------------------------------------------------------
# SYMBOL_EXISTS — ERROR
# ---------------------------------------------------------------------------

def _check_symbol_exists(ctx: AnalysisContext, report: AuditReport) -> None:
    for entry in ctx.elf_got_lookups:
        name = str(entry["symbol"])
        if name not in ctx.elf_all_symbol_names:
            add_finding(report, "SYMBOL_EXISTS", "ERROR", "generic",
                        f"line {entry['line_no']}",
                        f"ELF got['{name}'] is used but '{name}' does not exist in the binary's GOT table. "
                        f"This will cause a KeyError at runtime.",
                        f"Check the binary's actual GOT entries. Available GOT symbols: "
                        f"{list(ctx.evidence.symbols_map.get('got', {}).keys())[:10]}")
    for entry in ctx.elf_plt_lookups:
        name = str(entry["symbol"])
        if name not in ctx.elf_all_symbol_names:
            add_finding(report, "SYMBOL_EXISTS", "ERROR", "generic",
                        f"line {entry['line_no']}",
                        f"ELF plt['{name}'] is used but '{name}' does not exist in the binary's PLT table. "
                        f"This will cause a KeyError at runtime.",
                        f"Check the binary's actual PLT entries. Available PLT symbols: "
                        f"{list(ctx.evidence.symbols_map.get('plt', {}).keys())[:10]}")
    for entry in ctx.elf_sym_lookups:
        name = str(entry["symbol"])
        if name not in ctx.elf_all_symbol_names:
            add_finding(report, "SYMBOL_EXISTS", "ERROR", "generic",
                        f"line {entry['line_no']}",
                        f"ELF symbols['{name}'] is used but '{name}' does not exist in the binary's symbol table. "
                        f"This will cause a KeyError at runtime.",
                        f"Check the binary's actual symbols.")


# ---------------------------------------------------------------------------
# VARIABLE_DEFINED — ERROR
# ---------------------------------------------------------------------------

def _check_variable_defined(ctx: AnalysisContext, report: AuditReport) -> None:
    # Collect all names used on RHS of payload construction
    used_in_payload: Dict[str, int] = {}
    for line_no, line in ctx.payload_lines:
        # Strip comments to avoid matching English words in comments
        code_part = line.split("#")[0] if "#" in line else line
        # Extract variable names used after += on this line
        rhs_match = re.search(r'[+=]+\s*(.+)$', code_part)
        if rhs_match:
            rhs = rhs_match.group(1)
            for name in re.findall(r'\b([a-zA-Z_]\w*)\b', rhs):
                if name in {"p32", "p64", "b", "rop", "p8", "u32", "u64", "len", "rop_chain",
                             "io", "process", "remote", "ELF", "ROP", "cyclic", "flat", "chain",
                             "str", "int", "bytes", "bytearray", "recv", "recvline", "recvuntil",
                             "send", "sendline", "sendlineafter", "interactive", "context",
                             "OFFSET", "io", "hex", "ord", "chr", "print", "log", "info", "success",
                             "A", "True", "False", "None", "binary", "elf"}:
                    continue
                if len(name) == 1:
                    continue  # skip single-letter variable names (likely string literal fragments)
                if name not in used_in_payload:
                    used_in_payload[name] = line_no

    for name, line_no in used_in_payload.items():
        if name not in ctx.defined_vars:
            add_finding(report, "VARIABLE_DEFINED", "ERROR", "generic",
                        f"line {line_no}",
                        f"Variable '{name}' is used in payload construction but never defined. "
                        f"This will cause a NameError at runtime.",
                        f"Define '{name}' before using it, or check for typos in the variable name.")


# ---------------------------------------------------------------------------
# RECV_SIZE — WARNING
# ---------------------------------------------------------------------------

def _check_recv_size(ctx: AnalysisContext, report: AuditReport) -> None:
    for idx, line in enumerate(ctx.code_lines, 1):
        # u64(recv(N)) where N < 8
        for m in re.finditer(r'u64\s*\(.*?recv\s*\(\s*(\d+)\s*\)', line):
            n = int(m.group(1))
            if n < 8:
                add_finding(report, "RECV_SIZE", "WARNING", "generic",
                            f"line {idx}",
                            f"u64(recv({n})) expects {n} bytes but u64 requires at least 8 bytes. "
                            f"This will cause 'struct.error: unpack requires a buffer of 8 bytes'.",
                            f"Use u64(recv(8)) or u64(recvline().strip().ljust(8, b'\\x00')).")
        # u32(recv(N)) where N < 4
        for m in re.finditer(r'u32\s*\(.*?recv\s*\(\s*(\d+)\s*\)', line):
            n = int(m.group(1))
            if n < 4:
                add_finding(report, "RECV_SIZE", "WARNING", "generic",
                            f"line {idx}",
                            f"u32(recv({n})) expects {n} bytes but u32 requires at least 4 bytes.",
                            f"Use u32(recv(4)) or u32(recvline().strip().ljust(4, b'\\x00')).")


# ---------------------------------------------------------------------------
# BINARY_AS_LIBC — ERROR
# ---------------------------------------------------------------------------

def _check_binary_as_libc(ctx: AnalysisContext, report: AuditReport) -> None:
    binary_path = ctx.evidence.binary.path or ""
    if not binary_path:
        return
    basename = binary_path.rstrip("/").split("/")[-1]
    # Look for ELF(binary_path) used in libc calculation context
    for idx, line in enumerate(ctx.code_lines, 1):
        m = re.search(r"""ELF\s*\(\s*(?:r)?(['"])(.+?)\1""", line)
        if m:
            path_str = m.group(2)
            if basename in path_str or binary_path in path_str:
                # Exclude context.binary / elf / binary assignments (correct usage)
                if re.match(r'\s*(context\.binary|elf|binary)\s*=', line):
                    continue
                # Check if this ELF is used as libc (near libc_base, libc.symbols, etc.)
                surrounding = "\n".join(ctx.code_lines[max(0, idx - 3):min(len(ctx.code_lines), idx + 3)])
                if "libc" in surrounding.lower() or "libc_base" in surrounding or "libc." in surrounding:
                    add_finding(report, "BINARY_AS_LIBC", "ERROR", "generic",
                                f"line {idx}",
                                f"ELF() is loading the binary itself ('{path_str}') as if it were libc. "
                                f"Binary symbols like 'system' may not exist in the binary's own symbol table. "
                                f"Use the actual libc.so path from evidence.runtime.libc_path instead.",
                                f"Load the correct libc: ELF('{ctx.evidence.runtime.get('libc_path', '/lib/x86_64-linux-gnu/libc.so.6')}')")
