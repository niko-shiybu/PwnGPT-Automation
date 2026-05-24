from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from automation.audit.audit_report import AuditReport
from automation.audit.auditors.base_auditor import AnalysisContext, add_finding


def run_rop_checks(ctx: AnalysisContext, report: AuditReport) -> None:
    if ctx.is_64bit:
        _check_missing_pop_rdi(ctx, report)
        _check_stack_alignment(ctx, report)
    else:
        _check_calling_convention_32bit(ctx, report)
    _check_offset_mismatch(ctx, report)
    _check_fake_gadget(ctx, report)
    _check_wrong_strategy_nx_disabled(ctx, report)
    _check_manual_chain_no_rop_builder(ctx, report)


# ---------------------------------------------------------------------------
# MISSING_POP_RDI — CRITICAL (64-bit only)
# ---------------------------------------------------------------------------

# Known pwntools identifiers that are NOT addresses
_PWN_IDENTIFIERS = {
    "A", "b", "context", "elf", "io", "p64", "p32", "payload", "rop",
    "write_plt", "read_plt", "puts_plt", "printf_plt", "system_plt",
    "write_got", "read_got", "puts_got", "printf_got", "system_got",
    "main_addr", "main", "ret_offset", "ret_gadget", "pop_rdi", "pop_rdi_ret",
    "pop_rsi_r15_ret", "ret", "ROP", "rop_chain",
}

# Variables whose names suggest they're string/argument addresses, NOT functions
_STRING_ADDR_NAMES = {
    "bin_sh_addr", "binsh_addr", "binsh", "bin_sh", "sh_addr", "shell_addr",
    "shell", "flag_addr", "cat_flag", "cmd_addr",
}

_PLT_SUFFIXES = ("_plt", "@plt")
_GOT_SUFFIXES = ("_got", "@got")
_FUNC_SUFFIXES = ("_addr",)


def _looks_like_fn_addr(name: str, plt_names: Set[str], func_names: Set[str]) -> bool:
    """Check if a variable name looks like it refers to a function address."""
    if name in _PWN_IDENTIFIERS:
        return False
    if name in _STRING_ADDR_NAMES:
        return False  # string addresses are arguments, not functions to call
    if name.endswith(_PLT_SUFFIXES) or name.endswith(_GOT_SUFFIXES):
        return True
    if name.endswith(_FUNC_SUFFIXES) and not any(
        kw in name.lower() for kw in ("sh", "bin", "shell", "flag", "cmd", "cat")
    ):
        return True
    if name in plt_names or name in func_names:
        return True
    # Hex literal that looks like an address
    if re.match(r'0x[0-9a-fA-F]{6,16}', name):
        return True
    return False


def _check_missing_pop_rdi(ctx: AnalysisContext, report: AuditReport) -> None:
    if ctx.has_rop_builder:
        return  # rop.call() handles pop rdi automatically

    plt_names: Set[str] = set()
    for entry in ctx.elf_plt_lookups:
        plt_names.add(str(entry["symbol"]))
    plt_names.update(ctx.evidence.symbols_map.get("plt", {}).keys())
    func_names: Set[str] = set(ctx.evidence.symbols_map.get("funcs", {}).keys())

    # Build sequence of p64() arguments from payload lines
    p64_args: List[Dict[str, object]] = []  # [{arg, line_no}]
    for pc in ctx.pack_calls:
        if pc["fn"] == "p64" and pc["line_no"] in {l for l, _ in ctx.payload_lines}:
            p64_args.append(pc)

    # Also extract from simple += lines
    for line_no, line in ctx.payload_lines:
        for m in re.finditer(r'\+\=\s*p64\s*\(\s*([^)]+)\s*\)', line):
            arg = m.group(1).strip()
            already_tracked = any(
                a["arg_raw"] == arg and a["line_no"] == line_no for a in p64_args
            )
            if not already_tracked:
                p64_args.append({"fn": "p64", "arg_raw": arg, "line_no": line_no})

    # Check consecutive pairs: fn_addr followed by non-ret arg WITHOUT pop_rdi in between
    for i in range(len(p64_args) - 1):
        curr = str(p64_args[i]["arg_raw"])
        nxt = str(p64_args[i + 1]["arg_raw"])

        curr_is_fn = _looks_like_fn_addr(curr, plt_names, func_names)
        nxt_is_fn = _looks_like_fn_addr(nxt, plt_names, func_names)

        # Only flag when curr is a function call and next is NOT another function
        # (function calls in 64-bit need pop rdi before the first arg)
        if curr_is_fn and not nxt_is_fn:
            # If next is 0xdeadbeef or similar padding, it's likely a missing rdi setup
            if "ret" not in curr.lower() and "pop_rdi" not in nxt.lower():
                add_finding(report, "MISSING_POP_RDI", "CRITICAL", "rop",
                            f"payload construction near line {p64_args[i]['line_no']}",
                            f"64-bit binary. Function address '{curr}' is followed by argument '{nxt}' "
                            f"without a 'pop rdi; ret' gadget in between. In x86-64 calling convention, "
                            f"the first argument goes in RDI, not on the stack. The function will receive "
                            f"garbage in RDI and likely crash without producing output.",
                            f"Insert 'pop_rdi_ret' gadget before the function address: "
                            f"payload += p64(pop_rdi_ret) + p64(arg1) + p64(func_addr). "
                            f"Or better: use rop.call(func_addr, [arg1]) which handles this automatically.")


# ---------------------------------------------------------------------------
# OFFSET_MISMATCH — CRITICAL
# ---------------------------------------------------------------------------

def _check_offset_mismatch(ctx: AnalysisContext, report: AuditReport) -> None:
    measured_offset = ctx.fact_store.get("offsets.ret_offset_bytes")
    if measured_offset is None or measured_offset <= 0:
        return
    if ctx.used_offset is None:
        return
    if ctx.used_offset != int(measured_offset):
        # Check if code offset is actually pattern_len
        crash_proof = ctx.fact_store.get("probe_artifacts.crash_offset_proof", {})
        if isinstance(crash_proof, str):
            try:
                import json
                crash_proof = json.loads(crash_proof)
            except Exception:
                crash_proof = {}
        pattern_len = crash_proof.get("pattern_len", 0)
        if ctx.used_offset == pattern_len:
            add_finding(report, "OFFSET_MISMATCH", "CRITICAL", "rop",
                        f"offset assignment (code uses offset={ctx.used_offset})",
                        f"CODE OFFSET {ctx.used_offset} == PATTERN_LEN {pattern_len}! "
                        f"The offset in the code matches the cyclic pattern length, NOT the measured "
                        f"return address offset ({measured_offset}). The pattern length is the total "
                        f"size of the cyclic buffer, not the distance to the return address. "
                        f"This is a common hallucination — the LLM mistook pattern_len for the offset.",
                        f"Replace offset={ctx.used_offset} with offset={measured_offset}.")
        else:
            add_finding(report, "OFFSET_MISMATCH", "CRITICAL", "rop",
                        f"offset assignment (code uses offset={ctx.used_offset})",
                        f"Code uses offset={ctx.used_offset} but measured offset is {measured_offset}. "
                        f"Mismatch of {abs(ctx.used_offset - int(measured_offset))} bytes will cause "
                        f"the ROP chain to overwrite the wrong stack location.",
                        f"Change the offset value to {measured_offset}.")


# ---------------------------------------------------------------------------
# FAKE_GADGET — CRITICAL
# ---------------------------------------------------------------------------

def _check_fake_gadget(ctx: AnalysisContext, report: AuditReport) -> None:
    disasm = ctx.fact_store.get("probe_artifacts.disassemble_main", "")
    if isinstance(disasm, dict):
        disasm = str(disasm.get("output", disasm.get("text", "")))
    if not disasm or len(disasm) < 50:
        return

    for addr_str, line_no in ctx.pop_rdi_addresses:
        addr = int(addr_str, 16)
        # Search disassembly for this address as an instruction boundary
        addr_hex = f"{addr:x}"
        # Check if address appears as a standalone instruction start
        found_as_instruction = False
        in_middle_of_instruction = False

        for dis_line in disasm.splitlines():
            # Lines look like: "  40063e:\te8 7d fe ff ff    \tcall   4004c0 <system@plt>"
            m = re.match(r'\s*([0-9a-fA-F]+):\s+(.*)', dis_line)
            if m:
                instr_addr = int(m.group(1), 16)
                instr_bytes = m.group(2).strip()
                if instr_addr == addr:
                    found_as_instruction = True
                    break
                # Check if addr falls inside this instruction
                byte_count = len(instr_bytes.split())
                if byte_count > 0 and instr_addr < addr < instr_addr + byte_count:
                    # Check if this is a call instruction
                    if "call" in instr_bytes or "e8" in instr_bytes[:2]:
                        add_finding(report, "FAKE_GADGET", "CRITICAL", "rop",
                                    f"line {line_no}",
                                    f"pop_rdi_ret gadget address 0x{addr_hex} is INSIDE a 'call' instruction "
                                    f"at 0x{instr_addr:x} ('{instr_bytes}'). This is NOT a real 'pop rdi; ret' "
                                    f"gadget — it's the second byte of a call encoding. Jumping here will "
                                    f"execute garbage bytes as instructions, causing SIGILL or SIGBUS.",
                                    f"The binary may not have a 'pop rdi; ret' gadget. Try: (1) use "
                                    f"ROPgadget to find a real one, (2) jump to code that sets RDI before "
                                    f"calling system (e.g., mov edi, addr; call system).")
                    else:
                        add_finding(report, "FAKE_GADGET", "WARNING", "rop",
                                    f"line {line_no}",
                                    f"pop_rdi_ret gadget address 0x{addr_hex} falls inside instruction "
                                    f"at 0x{instr_addr:x} ('{instr_bytes}'). It may not be a valid gadget.",
                                    f"Verify this address is a real instruction boundary using ROPgadget.")

        if not found_as_instruction and not in_middle_of_instruction:
            # Address not found at all (or we couldn't parse it); low-confidence warning
            add_finding(report, "FAKE_GADGET", "WARNING", "rop",
                        f"line {line_no}",
                        f"pop_rdi_ret gadget address 0x{addr_hex} not found in disassemble_main output. "
                        f"It may be in a different section or invalid.",
                        f"Verify the gadget address using ROPgadget --binary <binary> | grep 'pop rdi'.")


# ---------------------------------------------------------------------------
# STACK_ALIGNMENT — ERROR (64-bit only)
# ---------------------------------------------------------------------------

def _check_stack_alignment(ctx: AnalysisContext, report: AuditReport) -> None:
    if not ctx.is_64bit:
        return
    # Check if system() is called without a ret gadget for alignment
    has_system_call = "system" in ctx.code.lower() or any(
        "system" in str(a).lower() for a in [c["arg_raw"] for c in ctx.pack_calls]
    )
    if not has_system_call:
        return
    # Look for ret gadget before system call
    has_ret_gadget = any("ret_gadget" in line or "ret_addr" in line
                          for _, line in ctx.payload_lines)
    has_ret_in_chain = re.search(r'p64\(ret', ctx.code)
    if not has_ret_gadget and not has_ret_in_chain and not ctx.has_rop_builder:
        add_finding(report, "STACK_ALIGNMENT", "ERROR", "rop",
                    "system() call in payload",
                    "64-bit binary: calling system() without a 'ret' gadget first may cause "
                    "a crash at movaps in libc due to 16-byte stack misalignment. "
                    "Ubuntu's libc system() uses movaps which requires the stack to be 16-byte aligned.",
                    "Add a 'ret' gadget before calling system(): "
                    "rop.raw(ret_gadget); rop.call(system_addr, [binsh_addr])")


# ---------------------------------------------------------------------------
# CALLING_CONVENTION_32BIT — ERROR (32-bit only)
# ---------------------------------------------------------------------------

def _check_calling_convention_32bit(ctx: AnalysisContext, report: AuditReport) -> None:
    """
    Check 32-bit cdecl calling convention: p32(func) should be followed by
    p32(fake_ret) before p32(arg1).
    """
    p32_args = [c for c in ctx.pack_calls if c["fn"] == "p32"
                and c["line_no"] in {l for l, _ in ctx.payload_lines}]
    if len(p32_args) < 2:
        return

    plt_names = set(ctx.evidence.symbols_map.get("plt", {}).keys())
    func_names = set(ctx.evidence.symbols_map.get("funcs", {}).keys())

    for i in range(len(p32_args) - 2):
        curr = str(p32_args[i]["arg_raw"])
        nxt = str(p32_args[i + 1]["arg_raw"])
        nxt2 = str(p32_args[i + 2]["arg_raw"])

        curr_is_fn = _looks_like_fn_addr(curr, plt_names, func_names)
        nxt_is_fn = _looks_like_fn_addr(nxt, plt_names, func_names)

        # In 32-bit cdecl: p32(func) + p32(fake_ret) + p32(arg1)
        # If curr is a function and next is also a function (no fake_ret), that's wrong
        if curr_is_fn and nxt_is_fn:
            add_finding(report, "CALLING_CONVENTION_32BIT", "ERROR", "rop",
                        f"payload near line {p32_args[i]['line_no']}",
                        f"32-bit cdecl calling convention: p32({curr}) is directly followed by "
                        f"p32({nxt}) without a fake return address placeholder. In cdecl, the stack "
                        f"layout after a function call is: [ret_addr] [arg1] [arg2]... The return "
                        f"address on the stack will be the NEXT p32 value, which is {nxt} (another "
                        f"function address), causing a crash on return.",
                        f"Insert a fake return address: p32(func) + p32(0x41414141) + p32(arg1). "
                        f"Alternatively, use rop.call() which handles cdecl correctly.")


# ---------------------------------------------------------------------------
# WRONG_STRATEGY_NX_DISABLED — WARNING
# ---------------------------------------------------------------------------

def _check_wrong_strategy_nx_disabled(ctx: AnalysisContext, report: AuditReport) -> None:
    if not ctx.is_nx_disabled:
        return
    if ctx.shellcode_indicators:
        return
    if report.code_summary and report.code_summary.strategy and "ret2libc" in report.code_summary.strategy:
        return
    # NX is disabled but exploit is using ROP instead of shellcode
    has_rop_chain = len(ctx.pack_calls) >= 3 or any(
        "pop_rdi" in line for _, line in ctx.payload_lines
    )
    if has_rop_chain:
        add_finding(report, "WRONG_STRATEGY_NX_DISABLED", "WARNING", "rop",
                    "overall strategy",
                    "NX is disabled (stack is executable) but the exploit uses a ROP chain. "
                    "A simpler ret2shellcode approach would work: place shellcode on the stack "
                    "and jump to it. ROP is unnecessarily complex here.",
                    "Consider ret2shellcode: use shellcraft.sh() and jump to the buffer address. "
                    "If the binary leaks a stack address, use it directly.")


# ---------------------------------------------------------------------------
# MANUAL_CHAIN_NO_ROP_BUILDER — INFO
# ---------------------------------------------------------------------------

def _check_manual_chain_no_rop_builder(ctx: AnalysisContext, report: AuditReport) -> None:
    if ctx.has_rop_builder:
        return
    # Count sequential p64/p32 calls in payload
    pack_in_payload = [c for c in ctx.pack_calls
                       if c["line_no"] in {l for l, _ in ctx.payload_lines}]
    if len(pack_in_payload) >= 3:
        add_finding(report, "MANUAL_CHAIN_NO_ROP_BUILDER", "INFO", "rop",
                    "payload construction",
                    f"Payload uses {len(pack_in_payload)} manual p32/p64 calls without using "
                    f"the pwntools ROP builder. Manual chains are error-prone for calling "
                    f"conventions and gadget selection.",
                    f"Use: rop = ROP(elf); rop.call(func_addr, [arg1, arg2]); payload += rop.chain(). "
                    f"This automatically handles calling conventions and gadget selection.")
