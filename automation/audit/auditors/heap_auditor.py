from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from automation.audit.audit_report import AuditReport
from automation.audit.auditors.base_auditor import AnalysisContext, add_finding


def run_heap_checks(ctx: AnalysisContext, report: AuditReport) -> None:
    _check_double_free(ctx, report)
    _check_uaf_pointer_reused(ctx, report)
    _check_wrong_chunk_size_overlap(ctx, report)
    _check_wrong_struct_offset(ctx, report)


# ---------------------------------------------------------------------------
# Parse heap operation sequence from exploit code
# ---------------------------------------------------------------------------

_HEAP_FN_PATTERNS = [
    r'(?:add|create|new)_?(?:note|meme|chunk|heap)\s*\(',
    r'(?:del|delete|free|remove)_?(?:note|meme|chunk|heap)\s*\(',
    r'(?:print|show|view|display)_?(?:note|meme|chunk|heap)\s*\(',
    r'(?:edit|modify|update|change)_?(?:note|meme|chunk|heap)\s*\(',
]

_OP_ADD = "add"
_OP_DEL = "del"
_OP_PRINT = "print"
_OP_EDIT = "edit"


def _parse_heap_ops(code: str) -> List[Dict[str, object]]:
    """Parse heap operation sequence from exploit code.

    Returns list of {op, index, size, line_no} dicts.
    """
    ops: List[Dict[str, object]] = []
    for idx, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # addnote(N, ...)
        m = re.match(r'(?:io\.)?\w*(?:add|create|new)_?\w*\s*\(\s*(\d+)\s*,', stripped)
        if m:
            ops.append({"op": _OP_ADD, "index": int(m.group(1)), "line_no": idx, "size": int(m.group(1))})
            continue
        m = re.match(r'(?:io\.)?\w*(?:add|create|new)_?\w*\s*\(\s*(\d+)\s*\)', stripped)
        if m:
            ops.append({"op": _OP_ADD, "index": int(m.group(1)), "line_no": idx})
            continue
        # delnote(N)
        m = re.match(r'(?:io\.)?\w*(?:del|delete|free|remove)_?\w*\s*\(\s*(\d+)\s*\)', stripped)
        if m:
            ops.append({"op": _OP_DEL, "index": int(m.group(1)), "line_no": idx})
            continue
        # printnote(N)
        m = re.match(r'(?:io\.)?\w*(?:print|show|view|display)_?\w*\s*\(\s*(\d+)\s*\)', stripped)
        if m:
            ops.append({"op": _OP_PRINT, "index": int(m.group(1)), "line_no": idx})
            continue
    return ops


# ---------------------------------------------------------------------------
# DOUBLE_FREE_PATTERN — ERROR
# ---------------------------------------------------------------------------

def _check_double_free(ctx: AnalysisContext, report: AuditReport) -> None:
    ops = _parse_heap_ops(ctx.code)
    if len(ops) < 3:
        return
    for i in range(len(ops) - 1):
        curr = ops[i]
        nxt = ops[i + 1]
        if (curr["op"] == _OP_DEL and nxt["op"] == _OP_DEL
                and curr["index"] == nxt["index"]):
            add_finding(report, "DOUBLE_FREE_PATTERN", "ERROR", "heap",
                        f"line {nxt['line_no']}",
                        f"del({curr['index']}) at line {curr['line_no']} followed by another "
                        f"del({nxt['index']}) at line {nxt['line_no']} without an intervening "
                        f"add({nxt['index']}). This is a double-free which glibc may detect "
                        f"and abort on (especially with tcache key protection in glibc >= 2.32).",
                        f"Ensure there is an add({nxt['index']}) between two frees of the same index, "
                        f"or use a different heap exploitation technique that avoids double-free.")


# ---------------------------------------------------------------------------
# UAF_POINTER_REUSED — ERROR
# ---------------------------------------------------------------------------

def _check_uaf_pointer_reused(ctx: AnalysisContext, report: AuditReport) -> None:
    ops = _parse_heap_ops(ctx.code)
    if len(ops) < 3:
        return
    # Track the lifecycle of each index
    freed_indices: set = set()
    for op in ops:
        idx = int(op["index"])
        if op["op"] == _OP_DEL:
            freed_indices.add(idx)
        elif op["op"] == _OP_ADD:
            freed_indices.discard(idx)
        elif op["op"] == _OP_PRINT:
            if idx in freed_indices:
                add_finding(report, "UAF_POINTER_REUSED", "ERROR", "heap",
                            f"line {op['line_no']}",
                            f"print({idx}) at line {op['line_no']} uses index {idx} which was freed "
                            f"but not re-allocated. If the dangling pointer still points to freed "
                            f"memory that has been overwritten by another allocation, this may "
                            f"trigger the intended UAF primitive. However, if the structure is not "
                            f"correctly set up, it will crash on the stale function pointer.",
                            f"Verify that after the free, a new allocation (add) has overwritten "
                            f"the freed chunk with controlled data.")


# ---------------------------------------------------------------------------
# WRONG_CHUNK_SIZE_OVERLAP — ERROR
# ---------------------------------------------------------------------------

def _check_wrong_chunk_size_overlap(ctx: AnalysisContext, report: AuditReport) -> None:
    ops = _parse_heap_ops(ctx.code)
    if len(ops) < 3:
        return

    # Track: what size was allocated at each index before free
    alloc_sizes: Dict[int, int] = {}
    for op in ops:
        idx = int(op["index"])
        if op["op"] == _OP_ADD:
            if "size" in op:
                alloc_sizes[idx] = int(op["size"])
            elif idx not in alloc_sizes:
                alloc_sizes[idx] = 8  # default

    # For tcache poisoning: after freeing two chunks of the same size,
    # a new allocation of that same size should be used
    freed_sizes: List[Tuple[int, int]] = []  # (index, size)
    for op in ops:
        idx = int(op["index"])
        if op["op"] == _OP_DEL:
            freed_sizes.append((idx, alloc_sizes.get(idx, 0)))

    # Check if there are freed chunks and new allocations
    if len(freed_sizes) >= 2:
        freed_size = freed_sizes[0][1]
        for op in ops:
            idx = int(op["index"])
            if op["op"] == _OP_ADD and op.get("size") is not None:
                new_size = int(op["size"])
                if any(idx == fs[0] for fs in freed_sizes):
                    continue  # re-using old index
                if new_size != freed_size and freed_size > 0 and new_size != 8:
                    add_finding(report, "WRONG_CHUNK_SIZE_OVERLAP", "ERROR", "heap",
                                f"line {op['line_no']}",
                                f"Tcache poisoning: new allocation size {new_size} != freed chunk "
                                f"size {freed_size}. Chunks of different sizes go to different "
                                f"tcache bins, so the new allocation won't reuse the freed chunk "
                                f"and the intended overlap attack will fail.",
                                f"Use the same size for the new allocation as the freed chunks: "
                                f"add({freed_size}, payload).")


# ---------------------------------------------------------------------------
# WRONG_STRUCT_OFFSET — WARNING
# ---------------------------------------------------------------------------

def _check_wrong_struct_offset(ctx: AnalysisContext, report: AuditReport) -> None:
    struct_defs = ctx.evidence.struct_defs or []
    if not struct_defs:
        return

    for sd in struct_defs:
        fields = sd.get("fields", [])
        if not fields:
            continue
        # Check if code uses hardcoded offsets that don't match struct layout
        struct_name = sd.get("name", "struct")
        for idx, line in enumerate(ctx.code_lines, 1):
            # Look for padding/offset comments or hardcoded values
            m = re.search(r'#.*offset\s*[:=]\s*(\d+)', line, re.IGNORECASE)
            if m:
                code_offset = int(m.group(1))
                # Check if any field is at this offset
                field_offsets = {f.get("offset", -1) for f in fields}
                if code_offset not in field_offsets and field_offsets != {-1}:
                    add_finding(report, "WRONG_STRUCT_OFFSET", "WARNING", "heap",
                                f"line {idx}",
                                f"Hardcoded offset {code_offset} doesn't match any field in "
                                f"'{struct_name}'. Struct fields: {fields}. "
                                f"Using wrong offsets will corrupt the wrong struct members.",
                                f"Verify the struct layout and correct the offset to match one of: "
                                f"{sorted(field_offsets)}.")
