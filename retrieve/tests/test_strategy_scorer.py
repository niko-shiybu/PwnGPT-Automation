from __future__ import annotations

import json
from pathlib import Path

from retrieve.evidence_normalizer import normalize
from retrieve.schemas import StrategyRecipe
from retrieve.strategy_scorer import score_and_rank


def _load_sample():
    p = Path(__file__).parent / "sample_evidence_rop3.json"
    return normalize(json.loads(p.read_text(encoding="utf-8")))


def _make_local_recipes():
    """Mirror of local_recipe_db.jsonl entries used for testing."""
    return [
        StrategyRecipe(
            id="i386_ret2libc_got_leak_write",
            name="i386 ret2libc via write@plt GOT leak",
            technique="ret2libc",
            arch=["i386"],
            base_score=0.25,
            preconditions=["control_eip", "has_import:write", "has_got:write", "has_reentry_function", "libc_available"],
            required_measurements=["verified_eip_offset", "write_plt", "write_got", "vulnerable_function", "libc_write", "libc_system", "libc_binsh"],
            payload_shape=["padding + write@plt + vulnerable_function + 1 + write@got + 4", "padding + system + exit + binsh"],
            failure_signatures={"EOF_BEFORE_LEAK": "offset, PLT address, or reentry address may be wrong", "BAD_LIBC_BASE": "wrong libc or wrong leaked symbol parsing"},
            source_refs=[{"type": "local_recipe_db", "url": None, "title": "local built-in recipe"}],
            confidence=0.85,
        ),
        StrategyRecipe(
            id="i386_ret2libc_got_leak_puts",
            name="i386 ret2libc via puts@plt GOT leak",
            technique="ret2libc",
            arch=["i386"],
            base_score=0.25,
            preconditions=["control_eip", "has_import:puts", "has_got:puts", "has_reentry_function", "libc_available"],
            required_measurements=["verified_eip_offset", "puts_plt", "puts_got", "vulnerable_function", "libc_puts", "libc_system", "libc_binsh"],
            payload_shape=["padding + puts@plt + vulnerable_function + puts@got", "padding + system + exit + binsh"],
            failure_signatures={},
            source_refs=[{"type": "local_recipe_db", "url": None, "title": "local built-in recipe"}],
            confidence=0.85,
        ),
        StrategyRecipe(
            id="shellcode_stack_exec",
            name="shellcode on executable stack",
            technique="shellcode",
            arch=["i386", "amd64"],
            base_score=0.15,
            preconditions=["control_eip", "nx_disabled", "stack_exec", "known_stack_addr_or_jmp_esp"],
            required_measurements=["verified_eip_offset", "stack_address_or_jmp_esp_gadget"],
            payload_shape=["padding + jmp_esp + shellcode"],
            failure_signatures={},
            source_refs=[{"type": "local_recipe_db", "url": None, "title": "local built-in recipe"}],
            confidence=0.85,
        ),
        StrategyRecipe(
            id="i386_ret2dlresolve",
            name="i386 ret2dlresolve fake Elf32_Rel",
            technique="ret2dlresolve",
            arch=["i386"],
            base_score=0.15,
            preconditions=["control_eip", "no_pie", "partial_relro", "bss_writable"],
            required_measurements=["verified_eip_offset", "bss_base", "plt_stub", "reloc_index", "libc_system", "libc_binsh"],
            payload_shape=["padding + fake_reloc + system_plt_stub + fake_reloc_addr + binsh_addr"],
            failure_signatures={},
            source_refs=[{"type": "local_recipe_db", "url": None, "title": "local built-in recipe"}],
            confidence=0.85,
        ),
        StrategyRecipe(
            id="one_gadget_libc",
            name="one_gadget in provided libc",
            technique="one_gadget",
            arch=["i386", "amd64"],
            base_score=0.15,
            preconditions=["control_eip_or_rip", "libc_available", "can_run_one_gadget_tool"],
            required_measurements=["verified_eip_or_rip_offset", "libc_base_leak_method", "one_gadget_offset"],
            payload_shape=["padding + one_gadget_address"],
            failure_signatures={},
            source_refs=[{"type": "local_recipe_db", "url": None, "title": "local built-in recipe"}],
            confidence=0.85,
        ),
    ]


def test_top1_is_write_ret2libc():
    """i386_ret2libc_got_leak_write must be the top candidate for rop3."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=5)
    assert len(candidates) > 0, "Expected at least one candidate"
    assert candidates[0].id == "i386_ret2libc_got_leak_write", \
        f"Expected top1 to be i386_ret2libc_got_leak_write, got {candidates[0].id} score={candidates[0].score}"


def test_shellcode_not_top():
    """Shellcode must not be top-ranked when NX enabled."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=5)
    top_ids = [c.id for c in candidates[:3]]
    assert "shellcode_stack_exec" not in top_ids, \
        f"Shellcode should not be in top 3 when NX enabled, got {top_ids}"


def test_ret2dlresolve_lower_than_ret2libc():
    """ret2dlresolve should score lower than ret2libc GOT leak when libc available."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=5)
    write_score = next((c.score for c in candidates if c.id == "i386_ret2libc_got_leak_write"), 0)
    dlresolve_score = next((c.score for c in candidates if c.id == "i386_ret2dlresolve"), 0)
    assert write_score > dlresolve_score, \
        f"ret2libc_write ({write_score}) should score higher than ret2dlresolve ({dlresolve_score})"


def test_puts_ret2libc_lower_than_write():
    """puts ret2libc should score lower than write ret2libc when no puts import."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=5)
    write_score = next((c.score for c in candidates if c.id == "i386_ret2libc_got_leak_write"), 0)
    puts_score = next((c.score for c in candidates if c.id == "i386_ret2libc_got_leak_puts"), 0)
    assert write_score > puts_score, \
        f"write ret2libc ({write_score}) should score higher than puts ret2libc ({puts_score}) without puts import"


def test_candidate_has_required_measurements():
    """Top candidate must list required measurements."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=5)
    top = candidates[0]
    expected = ["verified_eip_offset", "write_plt", "write_got", "libc_write", "libc_system", "libc_binsh"]
    for m in expected:
        assert m in top.required_measurements, \
            f"Expected {m} in required_measurements, got {top.required_measurements}"


def test_score_in_range():
    """All scores must be in [0.0, 1.0]."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=10)
    for c in candidates:
        assert 0.0 <= c.score <= 1.0, \
            f"Score {c.score} out of range for {c.id}"


def test_one_gadget_not_top1():
    """one_gadget should not be top1 when better strategies exist."""
    ne = _load_sample()
    recipes = _make_local_recipes()
    candidates = score_and_rank(recipes, ne, top_k=5)
    assert candidates[0].id != "one_gadget_libc", \
        "one_gadget should not be top1"
