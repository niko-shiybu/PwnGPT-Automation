from __future__ import annotations

import re
from typing import Any

from automation.audit.audit_report import AuditReport
from automation.audit.auditors.base_auditor import AnalysisContext, add_finding


def run_int_checks(ctx: AnalysisContext, report: AuditReport) -> None:
    _check_no_wrap_logic(ctx, report)
    _check_wrong_overflow_length(ctx, report)
    _check_wrong_padding_to_ret(ctx, report)


# ---------------------------------------------------------------------------
# NO_WRAP_LOGIC — ERROR
# ---------------------------------------------------------------------------

def _check_no_wrap_logic(ctx: AnalysisContext, report: AuditReport) -> None:
    """Check if the exploit actually triggers the integer overflow."""
    code = ctx.code
    # Look for signs of integer wrap exploit: large numbers, -1 sent as password, etc.
    has_large_value = bool(re.search(r'len\([^)]+\)\s*[><=]+\s*(?:0x)?\d{3,}', code))
    has_overflow_send = bool(re.search(
        r'sendline\s*\(\s*(?:b?["\'].{200,}["\']|str\s*\(\s*-1\s*\)|b?["\']\s*-1\s*["\'])',
        code
    ))
    has_payload_multiple = bool(re.search(r'[bB]["\'][Aa]["\']\s*\*\s*(?:0x)?\d{3,}', code))
    has_len_gt_255 = bool(re.search(r'(?:len|length).*(?:>|>=)\s*(?:0x)?(?:25[6-9]|2[6-9]\d|'
                                     r'[3-9]\d{2}|\d{4,})', code))

    if not (has_large_value or has_overflow_send or has_payload_multiple or has_len_gt_255):
        add_finding(report, "NO_WRAP_LOGIC", "ERROR", "int",
                    "exploit logic",
                    "No integer overflow logic detected in the exploit code. For INT challenges, "
                    "the vulnerability is typically uint8 truncation of strlen(): if strlen(s) > 255, "
                    "the checked value wraps to strlen(s) % 256, bypassing the length check. "
                    "The exploit must send a payload with length > 255 to trigger this.",
                    "Send a payload with length > 255 so strlen(s) % 256 is in the valid range "
                    "(typically 4-8). Example: payload = b'A' * 260  # 260 % 256 = 4.")


# ---------------------------------------------------------------------------
# WRONG_OVERFLOW_LENGTH — ERROR
# ---------------------------------------------------------------------------

def _check_wrong_overflow_length(ctx: AnalysisContext, report: AuditReport) -> None:
    """Check that payload length % 256 is in the expected range (typically 4-8)."""
    # Try to determine the total payload length from the code
    payload_lengths: list[int] = []
    for line_no, line in ctx.payload_lines:
        m = re.search(r'(["\'])[Aa]*\1\s*\*\s*(\d+)', line)
        if m:
            payload_lengths.append(int(m.group(2)))
    # Also check for length variables
    for name, val_str in ctx.defined_vars.items():
        if "len" in name.lower() or "size" in name.lower() or "length" in name.lower():
            try:
                payload_lengths.append(int(val_str))
            except (ValueError, TypeError):
                pass

    for plen in payload_lengths:
        mod = plen % 256
        if mod < 4 or mod > 8:
            add_finding(report, "WRONG_OVERFLOW_LENGTH", "ERROR", "int",
                        f"payload length ({plen})",
                        f"Payload length {plen} % 256 = {mod}, which is NOT in the valid range [4, 8]. "
                        f"The uint8 length check expects strlen % 256 to be in [4, 8] to bypass the "
                        f"validation. With mod={mod}, the check will fail and strcpy won't be called.",
                        f"Adjust payload length so that length % 256 is in [4, 8]. "
                        f"Example: 260 % 256 = 4.")


# ---------------------------------------------------------------------------
# WRONG_PADDING_TO_RET — CRITICAL
# ---------------------------------------------------------------------------

def _check_wrong_padding_to_ret(ctx: AnalysisContext, report: AuditReport) -> None:
    measured_offset = ctx.fact_store.get("offsets.ret_offset_bytes")
    if measured_offset is None or int(measured_offset) <= 0:
        return
    # For INT challenges, the padding before return address is the key
    padding_match = re.search(r'[bB](["\'])[Aa]*\1', ctx.code)
    padding_expr = re.search(r'(?:padding|pad|fill)\s*=\s*(\d+)', ctx.code)
    padding_from_buf = None
    if padding_expr:
        padding_from_buf = int(padding_expr.group(1))
    else:
        for line_no, line in ctx.payload_lines:
            m = re.search(r'(["\'])[Aa]*\1\s*\*\s*(\d+)', line)
            if m:
                padding_from_buf = int(m.group(2))
                break

    if padding_from_buf is not None and padding_from_buf != int(measured_offset):
        add_finding(report, "WRONG_PADDING_TO_RET", "CRITICAL", "int",
                    f"padding to return address (code uses {padding_from_buf} bytes)",
                    f"Code uses {padding_from_buf} bytes of padding before the return address, "
                    f"but measured offset is {measured_offset}. This will overwrite the wrong "
                    f"stack location or miss the return address entirely.",
                    f"Change padding bytes to {measured_offset}.")
