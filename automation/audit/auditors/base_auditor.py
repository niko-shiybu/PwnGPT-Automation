from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from automation.schemas import Evidence

from automation.audit.audit_report import CodeSummary, AuditFinding


# ---------------------------------------------------------------------------
# AnalysisContext — all parsed data that auditors can consume
# ---------------------------------------------------------------------------

@dataclass
class AnalysisContext:
    code: str
    code_lines: List[str]
    evidence: Evidence
    fact_store: Dict[str, Any]
    arch_bits: Optional[int]
    is_64bit: bool
    uses_p32: bool
    uses_p64: bool
    used_offset: Optional[int]
    hex_addresses: List[Tuple[str, int]]              # (addr_str, line_no)
    elf_got_lookups: List[Dict[str, object]]          # [{symbol, line_no}]
    elf_plt_lookups: List[Dict[str, object]]
    elf_sym_lookups: List[Dict[str, object]]
    elf_all_symbol_names: set                         # all known symbol names from evidence
    defined_vars: Dict[str, int]                      # {name: line_no}
    pack_calls: List[Dict[str, object]]               # [{fn, arg_raw, line_no}]
    payload_lines: List[Tuple[int, str]]              # (line_no, line) for payload construction lines
    fmt_offset_used: Optional[int]
    pop_rdi_addresses: List[Tuple[str, int]]          # (addr_str, line_no) of pop_rdi assignments
    has_rop_builder: bool                               # uses ROP() or rop.call() or rop.find_gadget
    shellcode_indicators: List[str]                     # "shellcraft", "asm(", etc found
    is_pie: bool
    is_nx_disabled: bool
    is_full_relro: bool
    is_canary: bool

    def to_debug_dict(self) -> Dict[str, Any]:
        return {
            "arch_bits": self.arch_bits,
            "is_64bit": self.is_64bit,
            "uses_p32": self.uses_p32,
            "uses_p64": self.uses_p64,
            "used_offset": self.used_offset,
            "hex_addresses": self.hex_addresses,
            "defined_vars": self.defined_vars,
            "fmt_offset_used": self.fmt_offset_used,
            "pop_rdi_addresses": self.pop_rdi_addresses,
            "shellcode_indicators": self.shellcode_indicators,
            "elf_lookups": {
                "got": [(x["symbol"], x["line_no"]) for x in self.elf_got_lookups],
                "plt": [(x["symbol"], x["line_no"]) for x in self.elf_plt_lookups],
                "sym": [(x["symbol"], x["line_no"]) for x in self.elf_sym_lookups],
            },
        }


def _make_ctx(code: str, evidence: Evidence, fact_store: Dict[str, Any]) -> AnalysisContext:
    lines = code.splitlines()
    arch_bits = _extract_arch_bits(evidence)
    is_64bit = arch_bits == 64
    uses_p32, uses_p64 = _extract_pack_usage(code)
    used_offset = _extract_used_offset(code)
    hex_addrs = _extract_hex_addresses(code)
    got_lookups, plt_lookups, sym_lookups = _extract_elf_lookups(code)
    all_syms = _collect_all_symbol_names(evidence)
    defined = _extract_defined_vars(lines)
    pack_calls = _extract_pack_calls(code)
    payload_lines = _extract_payload_lines(lines)
    fmt_offset = _extract_fmt_offset(code)
    pop_rdi_addrs = _extract_pop_rdi_assignments(code)
    has_rop_builder = "ROP(" in code or "rop.call(" in code or "rop.find_gadget" in code
    shellcode = _extract_shellcode_indicators(code)
    is_pie = _str_to_bool(evidence.binary_features.get("pie", False))
    is_nx_disabled = not _str_to_bool(evidence.binary_features.get("nx", True))
    is_full_relro = evidence.binary_features.get("relro", "") == "full"
    is_canary = _str_to_bool(evidence.binary_features.get("canary", False))
    return AnalysisContext(
        code=code, code_lines=lines, evidence=evidence, fact_store=fact_store,
        arch_bits=arch_bits, is_64bit=is_64bit,
        uses_p32=uses_p32, uses_p64=uses_p64, used_offset=used_offset,
        hex_addresses=hex_addrs,
        elf_got_lookups=got_lookups, elf_plt_lookups=plt_lookups, elf_sym_lookups=sym_lookups,
        elf_all_symbol_names=all_syms,
        defined_vars=defined, pack_calls=pack_calls, payload_lines=payload_lines,
        fmt_offset_used=fmt_offset, pop_rdi_addresses=pop_rdi_addrs,
        has_rop_builder=has_rop_builder,
        shellcode_indicators=shellcode,
        is_pie=is_pie, is_nx_disabled=is_nx_disabled,
        is_full_relro=is_full_relro, is_canary=is_canary,
    )


def _collect_all_symbol_names(evidence: Evidence) -> set:
    names: set = set()
    for section in ("got", "plt", "funcs", "globals"):
        for name in (evidence.symbols_map.get(section) or {}):
            names.add(name)
    for name in evidence.symbols:
        names.add(name)
    return names


# ---------------------------------------------------------------------------
# Extraction functions
# ---------------------------------------------------------------------------

def _str_to_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "enabled")
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _extract_arch_bits(evidence: Evidence) -> Optional[int]:
    raw = evidence.binary_features.get("arch_bits", 0)
    if raw and int(raw) in (32, 64):
        return int(raw)
    arch = (evidence.binary.arch or "").lower()
    if "64" in arch:
        return 64
    if "32" in arch or "i386" in arch or "i686" in arch:
        return 32
    return None


def _extract_pack_usage(code: str) -> Tuple[bool, bool]:
    return ("p32(" in code or "p32 (" in code), ("p64(" in code or "p64 (" in code)


def _extract_used_offset(code: str) -> Optional[int]:
    m = re.search(r'(?:offset|OFFSET|padding|pad)\s*=\s*(\d+)', code)
    if m:
        return int(m.group(1))
    return None


def _extract_hex_addresses(code: str) -> List[Tuple[str, int]]:
    results: List[Tuple[str, int]] = []
    for idx, line in enumerate(code.splitlines(), 1):
        for m in re.finditer(r'0x[0-9a-fA-F]{6,16}', line):
            if not re.search(r'0x[0]{3,}', m.group()):
                results.append((m.group(), idx))
    return results


def _extract_elf_lookups(code: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    got: List[Dict] = []
    plt: List[Dict] = []
    sym: List[Dict] = []
    for idx, line in enumerate(code.splitlines(), 1):
        # Skip libc.symbols / libc.plt / libc.got — these are CORRECT,
        # the symbols exist in libc even if not in the binary itself.
        if re.search(r"\blibc\.(got|plt|symbols)\[", line):
            continue
        for m in re.finditer(r"\.(got|plt|symbols)\['(\w+)'\]", line):
            entry = {"symbol": m.group(2), "line_no": idx}
            section = m.group(1)
            if section == "got":
                got.append(entry)
            elif section == "plt":
                plt.append(entry)
            else:
                sym.append(entry)
        for m in re.finditer(r'\.(got|plt|symbols)\["(\w+)"\]', line):
            entry = {"symbol": m.group(2), "line_no": idx}
            section = m.group(1)
            if section == "got":
                got.append(entry)
            elif section == "plt":
                plt.append(entry)
            else:
                sym.append(entry)
    return got, plt, sym


def _extract_defined_vars(lines: List[str]) -> Dict[str, int]:
    defined: Dict[str, int] = {}
    # Simple regex approach: look for var_name = <value> assignments
    for idx, line in enumerate(lines, 1):
        # Skip import lines, comments, and function defs
        stripped = line.strip()
        if stripped.startswith(("import ", "from ", "#", "def ", "class ", "@")):
            continue
        m = re.match(r'^(\w+)\s*=\s*(.+)$', stripped)
        if m:
            name = m.group(1)
            if name not in ("if", "for", "while", "return", "with", "try", "except"):
                defined[name] = idx
    return defined


def _extract_pack_calls(code: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for idx, line in enumerate(code.splitlines(), 1):
        for m in re.finditer(r'p(32|64)\s*\(\s*([^)]+)\s*\)', line):
            results.append({"fn": f"p{m.group(1)}", "arg_raw": m.group(2).strip(), "line_no": idx})
    return results


def _extract_payload_lines(lines: List[str]) -> List[Tuple[int, str]]:
    results: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.match(r'^(payload|rop|buf)\s*\+?=', stripped):
            results.append((idx, stripped))
    return results


def _extract_fmt_offset(code: str) -> Optional[int]:
    # fmtstr_payload(N, ...)
    m = re.search(r'fmtstr_payload\s*\(\s*(\d+)', code)
    if m:
        return int(m.group(1))
    # %N$n or %N$hn or %N$hhn
    m = re.search(r'%(\d+)\$(?:n|hn|hhn)', code)
    if m:
        return int(m.group(1))
    return None


def _extract_pop_rdi_assignments(code: str) -> List[Tuple[str, int]]:
    results: List[Tuple[str, int]] = []
    for idx, line in enumerate(code.splitlines(), 1):
        m = re.search(r'pop_rdi.*?=\s*(0x[0-9a-fA-F]+)', line)
        if m:
            results.append((m.group(1), idx))
    return results


def _extract_shellcode_indicators(code: str) -> List[str]:
    indicators: List[str] = []
    for keyword in ("shellcraft", "asm(", "shellcode", "asm ("):
        if keyword in code.lower():
            indicators.append(keyword)
    return indicators


# ---------------------------------------------------------------------------
# CodeSummary builder
# ---------------------------------------------------------------------------

def build_code_summary(ctx: AnalysisContext) -> CodeSummary:
    summary = CodeSummary()
    summary.arch_bits = ctx.arch_bits
    if ctx.uses_p32 and ctx.uses_p64:
        summary.pack_function = "mixed"
    elif ctx.uses_p64:
        summary.pack_function = "p64"
    elif ctx.uses_p32:
        summary.pack_function = "p32"
    summary.offset_used = ctx.used_offset
    summary.strategy = _detect_strategy(ctx)
    summary.has_pop_rdi = len(ctx.pop_rdi_addresses) > 0
    summary.has_rop_builder = "ROP(" in ctx.code or "rop.call(" in ctx.code or "rop.find_gadget" in ctx.code
    summary.uses_fmtstr_payload = "fmtstr_payload(" in ctx.code
    summary.fmt_offset_used = ctx.fmt_offset_used
    all_lookups = []
    for entry in ctx.elf_got_lookups:
        all_lookups.append({"symbol": str(entry["symbol"]), "lookup_type": "got"})
    for entry in ctx.elf_plt_lookups:
        all_lookups.append({"symbol": str(entry["symbol"]), "lookup_type": "plt"})
    for entry in ctx.elf_sym_lookups:
        all_lookups.append({"symbol": str(entry["symbol"]), "lookup_type": "symbols"})
    summary.elf_lookups = all_lookups
    return summary


def _detect_strategy(ctx: AnalysisContext) -> str:
    c = ctx.code
    ct = ctx.evidence.challenge_type

    if ct == "fmt":
        if "fmtstr_payload(" in c or "%n" in c:
            return "fmt_overwrite"
        if "%s" in c or "%p" in c or "%x" in c:
            return "fmt_leak"
        return "fmt_unknown"

    if ct == "int":
        return "int_overflow"

    if ct == "heap":
        if "tcache" in c.lower() or "fastbin" in c.lower():
            return "heap_tcache"
        if "unsorted" in c.lower():
            return "heap_unsorted_bin"
        return "heap_generic"

    # ROP strategies
    has_got_leak = bool(ctx.elf_got_lookups) and ("libc_base" in c or "leaked" in c.lower())
    has_libc_base = "libc_base" in c or "libc.address" in c
    has_shellcraft = bool(ctx.shellcode_indicators)

    if has_shellcraft:
        return "ret2shellcode"
    if has_libc_base and has_got_leak:
        return "ret2libc_leak"
    if has_libc_base:
        return "ret2libc"
    if ctx.has_rop_builder or ctx.is_64bit:
        return "rop_builder"
    return "ret2text"


# ---------------------------------------------------------------------------
# Helpers shared by auditors
# ---------------------------------------------------------------------------

def add_finding(
    report,
    type_: str,
    severity: str,
    category: str,
    location: str,
    detail: str,
    suggestion: str,
) -> None:
    report.findings.append(
        AuditFinding(type=type_, severity=severity, category=category,
                     location=location, detail=detail, suggestion=suggestion)
    )


# ---------------------------------------------------------------------------
# Public entry for context building
# ---------------------------------------------------------------------------

def build_context(code: str, evidence: Evidence, fact_store: Dict[str, Any]) -> AnalysisContext:
    return _make_ctx(code, evidence, fact_store)
