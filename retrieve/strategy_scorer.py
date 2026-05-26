from __future__ import annotations

from typing import Dict, List, Tuple

from retrieve.schemas import NormalizedEvidence, StrategyCandidate, StrategyRecipe


def _match_precondition(precond: str, ne: NormalizedEvidence) -> float:
    """Score a single precondition against normalized evidence. Returns -1.0 to 1.0."""
    p = precond.strip().lower()

    # ── Architecture ──────────────────────────────────────────
    if p.startswith("arch:"):
        wanted = p.split(":", 1)[1].strip()
        return 0.20 if ne.arch == wanted else -0.60

    # ── Control flow ──────────────────────────────────────────
    if p == "control_eip" or p == "control_rip":
        if ne.bug_type == "stack_overflow":
            return 0.10
        return 0.05

    if p == "control_eip_or_rip":
        if ne.bug_type == "stack_overflow":
            return 0.10
        return 0.05

    # ── Mitigations ───────────────────────────────────────────
    if p == "nx_enabled":
        return 0.08 if ne.mitigations.nx else -0.10
    if p == "nx_disabled" or p == "stack_exec":
        return 0.20 if not ne.mitigations.nx else -0.70
    if p == "no_pie":
        return 0.08 if not ne.mitigations.pie else -0.30
    if p == "partial_relro":
        return 0.05 if ne.mitigations.relro == "partial" else 0.0

    # ── Imports ───────────────────────────────────────────────
    if p.startswith("has_import:"):
        func = p.split(":", 1)[1].strip()
        for imp in ne.imports:
            if imp.lower() == func.lower():
                return 0.12
        return -0.35

    if p.startswith("has_got:"):
        func = p.split(":", 1)[1].strip()
        got = ne.symbols.get("got", {})
        for name in got:
            if name.lower() == func.lower():
                return 0.12
        return -0.20

    # ── Gadgets ───────────────────────────────────────────────
    if p.startswith("has_gadget:"):
        gadget = p.split(":", 1)[1].strip()
        probe_artifacts = ne.raw.get("probe_artifacts", {}) or {}
        gadget_inventory = probe_artifacts.get("gadget_inventory", {}) or {}
        if isinstance(gadget_inventory, dict) and gadget in gadget_inventory:
            return 0.15
        return -0.05

    # ── Libc ──────────────────────────────────────────────────
    if p == "libc_available":
        return 0.12 if ne.libc.available else -0.30
    if p == "can_run_one_gadget_tool":
        return 0.05 if ne.libc.available else -0.10

    # ── Format string specific ────────────────────────────────
    if p == "format_string_vuln":
        if ne.bug_type == "format_string":
            return 0.12
        return -0.30
    if p.startswith("has_got:writable"):
        return 0.05
    if p == "can_leak_stack_or_libc":
        return 0.10

    # ── Reentry ───────────────────────────────────────────────
    if p == "has_reentry_function":
        funcs = ne.symbols.get("functions", {})
        for name in funcs:
            name_lower = name.lower()
            if any(kw in name_lower for kw in ("vulnerable", "main", "start")):
                return 0.08
        return 0.05

    # ── CSU ───────────────────────────────────────────────────
    if p == "has_libc_csu_init":
        funcs = ne.symbols.get("functions", {})
        for name in funcs:
            if "csu_init" in name.lower():
                return 0.10
        return 0.0

    # ── Known stack addr ──────────────────────────────────────
    if p == "known_stack_addr_or_jmp_esp":
        return 0.0

    # Default
    return 0.0


def score_recipe(recipe: StrategyRecipe, ne: NormalizedEvidence) -> Tuple[float, Dict[str, float]]:
    """Score a strategy recipe against normalized evidence.

    Returns (final_score, breakdown).
    Score is clamped to [0.0, 1.0].
    """
    breakdown: Dict[str, float] = {}
    score = recipe.base_score if hasattr(recipe, "base_score") else 0.25

    # ── Architecture match ────────────────────────────────────
    if ne.arch in recipe.arch:
        breakdown["arch_match"] = 0.03
        score += 0.03
    elif "unknown" in recipe.arch:
        breakdown["arch_match"] = 0.01
        score += 0.01
    else:
        breakdown["arch_mismatch"] = -0.40
        score -= 0.40

    # ── Bug type match ────────────────────────────────────────
    if ne.bug_type == "stack_overflow":
        if "control_eip" in recipe.preconditions or "control_rip" in recipe.preconditions:
            breakdown["bug_type_match"] = 0.05
            score += 0.05
    elif ne.bug_type == "format_string":
        if recipe.technique == "format_string":
            breakdown["bug_type_match"] = 0.20
            score += 0.20
        else:
            breakdown["fmt_bug_mismatch_penalty"] = -0.40
            score -= 0.40

    # ── Shellcode penalty when NX enabled ─────────────────────
    if recipe.technique == "shellcode" and ne.mitigations.nx:
        breakdown["shellcode_nx_penalty"] = -0.50
        score -= 0.50

    # ── PLT/GOT bonus for no PIE ──────────────────────────────
    if not ne.mitigations.pie and recipe.technique in ("ret2libc", "format_string", "ret2dlresolve"):
        breakdown["no_pie_plt_got"] = 0.03
        score += 0.03

    # ── Canary absent bonus ───────────────────────────────────
    if not ne.mitigations.canary and recipe.technique in ("ret2libc", "shellcode", "ret2dlresolve", "ret2csu"):
        breakdown["no_canary_rop"] = 0.05
        score += 0.05

    # ── Libc availability ─────────────────────────────────────
    if ne.libc.available and recipe.technique == "ret2libc":
        breakdown["libc_available"] = 0.05
        score += 0.05

    # ── Import-specific bonuses ───────────────────────────────
    imports_lower = [x.lower() for x in ne.imports]
    if "write" in imports_lower:
        if any("write" in p.lower() for p in recipe.preconditions):
            breakdown["has_write_import"] = 0.05
            score += 0.05
        if ne.symbols.get("got", {}).get("write") and any("write" in p.lower() for p in recipe.preconditions):
            breakdown["has_write_got"] = 0.05
            score += 0.05
    if "puts" in imports_lower:
        if any("puts" in p.lower() for p in recipe.preconditions):
            breakdown["has_puts_import"] = 0.05
            score += 0.05

    # ── ret2dlresolve penalty when libc is given ──────────────
    if recipe.technique == "ret2dlresolve" and ne.libc.available:
        breakdown["ret2dlresolve_libc_penalty"] = -0.10
        score -= 0.10

    # ── one_gadget not top1 ───────────────────────────────────
    if recipe.technique == "one_gadget":
        breakdown["one_gadget_penalty"] = -0.15
        score -= 0.15

    # ── amd64 gadget on i386 ──────────────────────────────────
    if "i386" in ne.arch and any("pop rdi" in p or "ret2csu" in p.lower() for p in recipe.preconditions):
        breakdown["amd64_gadget_on_i386"] = -0.50
        score -= 0.50

    # ── Score per precondition (dampened to avoid saturation) ─
    for precond in recipe.preconditions:
        p_score = _match_precondition(precond, ne)
        if p_score != 0:
            breakdown[f"precond_{precond[:40]}"] = round(p_score * 0.25, 4)
            score += p_score * 0.25

    # ── Confidence factor from recipe ─────────────────────────
    if recipe.confidence > 0:
        breakdown["recipe_confidence"] = round(recipe.confidence * 0.10, 4)
        score += recipe.confidence * 0.10

    # ── Source ref quality ────────────────────────────────────
    if recipe.source_refs:
        max_source = max((s.get("source_score", 0) for s in recipe.source_refs), default=0)
        breakdown["source_quality"] = round(max_source * 0.10, 4)
        score += max_source * 0.10

    final = max(0.0, min(1.0, score))
    return final, breakdown


def score_and_rank(
    recipes: List[StrategyRecipe],
    ne: NormalizedEvidence,
    *,
    top_k: int = 5,
) -> List[StrategyCandidate]:
    """Score and rank strategy recipes. Returns top-k candidates."""
    candidates: List[StrategyCandidate] = []

    for recipe in recipes:
        final_score, breakdown = score_recipe(recipe, ne)

        priority = "low"
        if final_score >= 0.40:
            priority = "high"
        elif final_score >= 0.25:
            priority = "medium"

        candidates.append(StrategyCandidate(
            id=recipe.id,
            name=recipe.name,
            technique=recipe.technique,
            score=round(final_score, 4),
            priority=priority,
            reason=recipe.why_relevant or f"{recipe.technique} technique for {ne.arch} {ne.bug_type}",
            preconditions=recipe.preconditions,
            required_measurements=recipe.required_measurements,
            payload_shape=recipe.payload_shape,
            failure_signatures=recipe.failure_signatures,
            source_refs=recipe.source_refs,
            not_applicable_if=recipe.not_applicable_if,
            scoring_breakdown=breakdown,
        ))

    candidates.sort(key=lambda c: -c.score)
    return candidates[:top_k]
