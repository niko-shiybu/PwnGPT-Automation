from __future__ import annotations

import re
from typing import Any

from automation.audit.audit_report import AuditReport
from automation.audit.auditors.base_auditor import AnalysisContext, add_finding, _str_to_bool


def run_fmt_checks(ctx: AnalysisContext, report: AuditReport) -> None:
    _check_missing_target_address(ctx, report)
    _check_wrong_fmt_offset(ctx, report)
    _check_full_relro_got_write(ctx, report)
    _check_unaligned_fmt_write(ctx, report)


# ---------------------------------------------------------------------------
# MISSING_TARGET_ADDRESS — ERROR
# ---------------------------------------------------------------------------

def _check_missing_target_address(ctx: AnalysisContext, report: AuditReport) -> None:
    has_pct_n = bool(re.search(r'%\d*\$?n', ctx.code))  # %n, %hn, %hhn, %N$n
    if not has_pct_n:
        return
    if report.code_summary and report.code_summary.uses_fmtstr_payload:
        return  # fmtstr_payload() handles address packing automatically

    # For manual %n: need at least one p32/p64 packing the target address before %n
    pack_args = set()
    for pc in ctx.pack_calls:
        arg = str(pc["arg_raw"])
        pack_args.add(arg)
    pack_in_payload_lines = any(
        pc["line_no"] in {l for l, _ in ctx.payload_lines} for pc in ctx.pack_calls
    )

    # Check if there's a packed address placed before the format string
    has_address_in_payload = bool(pack_in_payload_lines)

    if not has_address_in_payload:
        add_finding(report, "MISSING_TARGET_ADDRESS", "ERROR", "fmt",
                    "format string payload",
                    "Code uses %n to write to memory but does NOT pack a target address "
                    "(p32/p64) into the payload first. Without a target address on the stack, "
                    "%n will write to a random stack location, causing memory corruption.",
                    "Pack the target address at the start of the format string payload: "
                    "payload = p32(target_addr) + b'%N$n' where N is the stack offset.")


# ---------------------------------------------------------------------------
# WRONG_FMT_OFFSET — ERROR
# ---------------------------------------------------------------------------

def _check_wrong_fmt_offset(ctx: AnalysisContext, report: AuditReport) -> None:
    if ctx.fmt_offset_used is None:
        return
    measured_offset = ctx.fact_store.get("offsets.fmt_offset_arg")
    if measured_offset is None or int(measured_offset) <= 0:
        return
    if ctx.fmt_offset_used != int(measured_offset):
        add_finding(report, "WRONG_FMT_OFFSET", "ERROR", "fmt",
                    f"fmt offset (code uses offset={ctx.fmt_offset_used})",
                    f"Code uses format string offset {ctx.fmt_offset_used} but measured offset "
                    f"is {measured_offset}. The format string argument is at a different stack "
                    f"position. Using the wrong offset means %N$n targets the wrong address.",
                    f"Change the offset to {measured_offset}. On 64-bit, make sure to account "
                    f"for register arguments (rdi, rsi, rdx, rcx, r8, r9 are first 6 args).")


# ---------------------------------------------------------------------------
# FULL_RELRO_GOT_WRITE — CRITICAL
# ---------------------------------------------------------------------------

def _check_full_relro_got_write(ctx: AnalysisContext, report: AuditReport) -> None:
    if not ctx.is_full_relro:
        return
    # Check if code targets GOT entries for writing
    targets_got = ctx.elf_got_lookups and ("%n" in ctx.code or "fmtstr_payload" in ctx.code)
    if targets_got:
        add_finding(report, "FULL_RELRO_GOT_WRITE", "CRITICAL", "fmt",
                    "GOT write attempt",
                    "Binary has Full RELRO — the GOT is mapped read-only after relocation. "
                    "Any attempt to overwrite GOT entries (via %n or fmtstr_payload targeting "
                    "a GOT address) will cause a SIGSEGV (write to read-only memory).",
                    "Use an alternative: (1) overwrite __malloc_hook/__free_hook in libc, "
                    "(2) ret2libc without GOT overwrite, (3) overwrite a writable function "
                    "pointer on the stack or in .data/.bss.")


# ---------------------------------------------------------------------------
# UNALIGNED_FMT_WRITE — WARNING
# ---------------------------------------------------------------------------

def _check_unaligned_fmt_write(ctx: AnalysisContext, report: AuditReport) -> None:
    # %n does a 4-byte write; sometimes %hn (2-byte) or %hhn (1-byte) is safer
    has_pct_n = bool(re.search(r'(?<!%)%n', ctx.code))
    has_pct_hn = "%hn" in ctx.code
    has_pct_hhn = "%hhn" in ctx.code
    if has_pct_n and not has_pct_hn and not has_pct_hhn:
        # %n writes 4 bytes at once; for partial overwrites this can be dangerous
        if ctx.is_64bit:
            add_finding(report, "UNALIGNED_FMT_WRITE", "WARNING", "fmt",
                        "format string write",
                        "Using %n (4-byte write) directly instead of %hn (2-byte) or %hhn (1-byte). "
                        "4-byte writes need to produce a very large format string (millions of chars) "
                        "to write a specific address value. This is slow and can fail. "
                        "2-byte or 1-byte partial overwrites are often more practical.",
                        "Consider using %hn for 2-byte writes: p32(target) + p32(target+2) + "
                        "b'%Nc%M$hn%Kc%L$hn'. Or use fmtstr_payload() which handles this automatically.")
