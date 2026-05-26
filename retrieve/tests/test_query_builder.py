from __future__ import annotations

import json
from pathlib import Path

from retrieve.evidence_normalizer import normalize
from retrieve.query_builder import build_queries


def _load_sample():
    p = Path(__file__).parent / "sample_evidence_rop3.json"
    return json.loads(p.read_text(encoding="utf-8"))


def test_query_builder_contains_i386():
    """Query must contain i386 or 32 bit for i386 binary."""
    ne = normalize(_load_sample())
    queries = build_queries(ne)
    all_text = " ".join(q.query.lower() for q in queries)
    assert "i386" in all_text or "32 bit" in all_text or "32-bit" in all_text, \
        f"Expected 'i386' or '32 bit' in queries, got: {all_text}"


def test_query_builder_contains_ret2libc():
    """Query must contain ret2libc for NX-enabled stack overflow."""
    ne = normalize(_load_sample())
    queries = build_queries(ne)
    all_text = " ".join(q.query.lower() for q in queries)
    assert "ret2libc" in all_text, \
        f"Expected 'ret2libc' in queries, got: {all_text}"


def test_query_builder_contains_write_plt_got():
    """Query must reference write@plt / write@got since binary has them."""
    ne = normalize(_load_sample())
    queries = build_queries(ne)
    all_text = " ".join(q.query.lower() for q in queries)
    assert "write" in all_text, \
        f"Expected 'write' in queries, got: {all_text}"
    assert "got" in all_text or "plt" in all_text, \
        f"Expected 'got' or 'plt' in queries, got: {all_text}"


def test_query_builder_contains_got_leak():
    """Query must mention GOT leak."""
    ne = normalize(_load_sample())
    queries = build_queries(ne)
    all_text = " ".join(q.query.lower() for q in queries)
    assert "got" in all_text, \
        f"Expected 'got' in queries, got: {all_text}"


def test_query_builder_contains_pwntools():
    """Query must reference pwntools."""
    ne = normalize(_load_sample())
    queries = build_queries(ne)
    all_text = " ".join(q.query.lower() for q in queries)
    assert "pwntools" in all_text, \
        f"Expected 'pwntools' in queries, got: {all_text}"


def test_query_builder_contains_cyclic_find():
    """Query must contain cyclic_find or offset since offset is unverified."""
    ne = normalize(_load_sample())
    assert not ne.vulnerability.offset_verified, "Offset should be unverified in sample"
    queries = build_queries(ne)
    all_text = " ".join(q.query.lower() for q in queries)
    assert "cyclic" in all_text or "offset" in all_text, \
        f"Expected 'cyclic' or 'offset' in queries, got: {all_text}"


def test_query_builder_nx_enabled_no_shellcode_priority():
    """Shellcode queries should not be high priority when NX enabled."""
    ne = normalize(_load_sample())
    queries = build_queries(ne)
    for q in queries:
        if "shellcode" in q.query.lower():
            assert q.priority < 0.6, \
                f"Shellcode query should have low priority when NX enabled, got {q.priority}"


def test_normalizer_detects_conflicting_canary():
    """binary_features.canary=true conflicts with checksec_raw's 'No canary found'."""
    ne = normalize(_load_sample())
    conflict_warnings = [w for w in ne.warnings if "canary" in w.lower()]
    assert len(conflict_warnings) > 0, \
        f"Expected canary conflict warnings, got: {ne.warnings}"
    assert ne.mitigations.canary == False, \
        f"Expected canary=False (checksec takes priority), got {ne.mitigations.canary}"


def test_normalizer_detects_vulnerability():
    """Should detect stack overflow in vulnerable_function with buf[136] and read(256)."""
    ne = normalize(_load_sample())
    assert ne.bug_type == "stack_overflow", f"Expected stack_overflow, got {ne.bug_type}"
    assert ne.vulnerability.function == "vulnerable_function", \
        f"Expected vulnerable_function, got {ne.vulnerability.function}"
    assert ne.vulnerability.candidate_eip_offset is not None, \
        "Expected candidate EIP offset"
    assert ne.vulnerability.candidate_eip_offset >= 136, \
        f"Expected offset >= 136, got {ne.vulnerability.candidate_eip_offset}"


def test_normalizer_extracts_imports():
    """Should extract read and write from symbols_map and strings_raw."""
    ne = normalize(_load_sample())
    imports_lower = [x.lower() for x in ne.imports]
    assert "read" in imports_lower, f"Expected 'read' in imports, got {ne.imports}"
    assert "write" in imports_lower, f"Expected 'write' in imports, got {ne.imports}"
