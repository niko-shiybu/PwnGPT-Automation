from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, List, Optional

from retrieve.schemas import NormalizedEvidence, SearchQuery, SearchResult, StrategyRecipe


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", text.lower().strip())[:80]


def _detect_arch_from_text(text: str) -> List[str]:
    archs: List[str] = []
    txt = text.lower()
    if "i386" in txt or "32 bit" in txt or "32-bit" in txt:
        archs.append("i386")
    if "amd64" in txt or "x86_64" in txt or "x86-64" in txt or "64 bit" in txt or "64-bit" in txt:
        archs.append("amd64")
    return archs if archs else ["unknown"]


def _detect_technique_from_text(text: str) -> str:
    txt = text.lower()
    if "ret2libc" in txt or "return to libc" in txt or "return-to-libc" in txt:
        return "ret2libc"
    if "ret2dlresolve" in txt or "ret2dl_resolve" in txt or "dlresolve" in txt:
        return "ret2dlresolve"
    if "shellcode" in txt:
        return "shellcode"
    if "one_gadget" in txt or "one-gadget" in txt or "one gadget" in txt:
        return "one_gadget"
    if "format string" in txt or "fmtstr" in txt:
        return "format_string"
    if "ret2csu" in txt or "csu gadget" in txt:
        return "ret2csu"
    if "got overwrite" in txt or "got leak" in txt:
        if "format" in txt:
            return "format_string"
        return "ret2libc"
    if "rop" in txt:
        return "ret2libc"
    return "unknown"


def _extract_preconditions(text: str, technique: str, archs: List[str]) -> List[str]:
    pre: List[str] = []
    txt = text.lower()

    if technique == "ret2libc":
        pre.append("control_eip")
        pre.append("has_reentry_function")
        pre.append("libc_available")
        if "write" in txt:
            pre.append("has_import:write")
            pre.append("has_got:write")
        if "puts" in txt:
            pre.append("has_import:puts")
            pre.append("has_got:puts")
    elif technique == "ret2dlresolve":
        pre.append("control_eip")
        pre.append("no_pie")
        pre.append("partial_relro")
    elif technique == "shellcode":
        pre.append("control_eip")
        pre.append("nx_disabled")
        pre.append("stack_exec")
    elif technique == "format_string":
        pre.append("format_string_vuln")
        pre.append("has_got:writable")
    elif technique == "one_gadget":
        pre.append("control_eip")
        pre.append("libc_available")
    elif technique == "ret2csu":
        pre.append("control_rip")
        pre.append("has_libc_csu_init")

    return pre


def _extract_measurements(text: str, technique: str) -> List[str]:
    meas: List[str] = []
    txt = text.lower()

    meas.append("verified_eip_offset")

    if "write" in txt:
        meas.append("write_plt")
        meas.append("write_got")
        meas.append("libc_write")
    if "puts" in txt:
        meas.append("puts_plt")
        meas.append("puts_got")
        meas.append("libc_puts")
    if "ret2libc" in technique or "got" in txt:
        meas.append("libc_system")
        meas.append("libc_binsh")
    if "pop rdi" in txt or "ret2csu" in technique:
        meas.append("pop_rdi_ret")
    if "format string" in technique:
        meas.append("verified_fmt_offset")

    return list(set(meas))


def _extract_payload_shape(text: str, technique: str) -> List[str]:
    shapes: List[str] = []

    if technique == "ret2libc" and "write" in text.lower():
        shapes.append("padding + write@plt + vulnerable_function + 1 + write@got + 4")
        shapes.append("padding + system + exit + binsh")
    elif technique == "ret2libc" and "puts" in text.lower():
        shapes.append("padding + puts@plt + vulnerable_function + puts@got")
        shapes.append("padding + system + exit + binsh")
    elif technique == "format_string":
        shapes.append("fmtstr_write to GOT entry with %n")
    elif technique == "shellcode":
        shapes.append("padding + jmp_esp + shellcode")
    elif technique == "ret2csu":
        shapes.append("padding + csu_gadget1 + 0 + 1 + got_entry + binsh + got_entry + got_entry + csu_gadget2")

    return shapes


def _generate_id(technique: str, archs: List[str], snippet: str) -> str:
    base = f"{'_'.join(archs)}_{technique}"
    h = hashlib.md5(snippet.encode() if isinstance(snippet, str) else b"").hexdigest()[:6]
    return _slugify(base) + "_" + h


def extract_from_search_results(
    ne: NormalizedEvidence,
    query: SearchQuery,
    results: List[SearchResult],
) -> List[StrategyRecipe]:
    """Extract strategy recipes from search results using keyword rules."""
    recipes: List[StrategyRecipe] = []

    for r in results:
        text = (r.title + " " + r.snippet + " " + r.url).lower()

        # Skip clearly irrelevant results
        if not any(kw in text for kw in ["exploit", "pwn", "ctf", "rop", "overflow", "format", "ret2", "shellcode", "libc", "got", "plt"]):
            continue

        technique = _detect_technique_from_text(text)
        archs = _detect_arch_from_text(text)

        recipe = StrategyRecipe(
            id=_generate_id(technique, archs, r.snippet + r.url),
            name=f"{'/'.join(archs)} {technique} " + (r.title[:80] or "from search"),
            technique=technique,
            arch=archs,
            base_score=0.12,
            preconditions=_extract_preconditions(text, technique, archs),
            required_measurements=_extract_measurements(text, technique),
            payload_shape=_extract_payload_shape(text, technique),
            failure_signatures={},
            source_refs=[{
                "type": "web_search",
                "url": r.url,
                "title": r.title,
                "source_score": r.source_score,
                "query": query.query,
            }],
            confidence=0.3,
            raw_snippet=r.snippet[:2000],
        )

        # Adjust confidence based on evidence match
        confidence = 0.3
        if ne.arch in archs:
            confidence += 0.20
        else:
            confidence -= 0.25

        if technique == "ret2libc" and ne.libc.available:
            confidence += 0.15
        if technique == "shellcode" and ne.mitigations.nx:
            confidence -= 0.40
        if technique == "shellcode" and not ne.mitigations.nx:
            confidence += 0.20
        if "write" in text and "write" in [x.lower() for x in ne.imports]:
            confidence += 0.15
        if "puts" in text and "puts" not in [x.lower() for x in ne.imports]:
            confidence -= 0.10
        if "got" in text and not ne.mitigations.pie:
            confidence += 0.10

        recipe.confidence = max(0.0, min(1.0, confidence))
        recipes.append(recipe)

    return recipes


def extract_with_llm(
    ne: NormalizedEvidence,
    query: SearchQuery,
    results: List[SearchResult],
) -> List[StrategyRecipe]:
    """Extract strategy recipes using LLM. Falls back to rule-based on error."""
    try:
        from automation.llm_client import chat_complete
        from pathlib import Path

        prompt_path = Path(__file__).parent / "prompts" / "recipe_extractor_prompt.txt"
        system_prompt = prompt_path.read_text(encoding="utf-8")

        recipes: List[StrategyRecipe] = []

        for r in results:
            evidence_summary = {
                "arch": ne.arch,
                "bits": ne.bits,
                "bug_type": ne.bug_type,
                "mitigations": ne.mitigations.to_dict(),
                "imports": ne.imports,
                "plt": ne.symbols.get("plt", {}),
                "got": ne.symbols.get("got", {}),
                "libc_available": ne.libc.available,
            }

            user_prompt = (
                f"Normalized Evidence:\n{json.dumps(evidence_summary, indent=2)}\n\n"
                f"Search Query: {query.query}\n"
                f"Title: {r.title}\n"
                f"URL: {r.url}\n"
                f"Snippet: {r.snippet[:1500]}\n"
            )

            try:
                response = chat_complete(user_prompt, system_prompt, temperature=0.1)
                data = json.loads(response)
            except Exception:
                continue

            if data.get("discard"):
                continue

            strat = data.get("strategy", {})
            recipe = StrategyRecipe(
                id=_slugify(strat.get("id", "") or strat.get("name", "")),
                name=strat.get("name", ""),
                technique=strat.get("technique", "unknown"),
                arch=strat.get("arch", []),
                base_score=0.12,
                preconditions=strat.get("preconditions", []),
                required_measurements=strat.get("required_measurements", []),
                payload_shape=strat.get("payload_shape", []),
                failure_signatures=strat.get("failure_signatures", {}),
                source_refs=[{
                    "type": "web_search",
                    "url": r.url,
                    "title": r.title,
                    "source_score": r.source_score,
                    "query": query.query,
                }],
                why_relevant=strat.get("why_relevant_to_current_evidence", ""),
                not_applicable_if=strat.get("not_applicable_if", []),
                confidence=float(data.get("confidence", 0.3)),
                raw_snippet=r.snippet[:2000],
            )
            recipes.append(recipe)

        return recipes if recipes else extract_from_search_results(ne, query, results)
    except Exception:
        return extract_from_search_results(ne, query, results)
