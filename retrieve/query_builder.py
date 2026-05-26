from __future__ import annotations

from typing import List

from retrieve.schemas import NormalizedEvidence, SearchQuery


def build_queries(ne: NormalizedEvidence) -> List[SearchQuery]:
    """Generate search queries from normalized evidence using rule-based logic.

    Falls back to this when LLM is unavailable. Otherwise, use build_queries_with_llm().
    """
    queries: List[SearchQuery] = []

    m = ne.mitigations
    v = ne.vulnerability
    imports_lower = [x.lower() for x in ne.imports]
    has_write = "write" in imports_lower
    has_puts = "puts" in imports_lower
    has_read = "read" in imports_lower
    has_system = "system" in imports_lower

    arch_str = "i386" if ne.arch == "i386" else "amd64" if ne.arch == "amd64" else ne.arch
    arch_bit_str = f"{arch_str} 32 bit" if ne.bits == 32 else f"{arch_str} x86_64"

    # ── Core strategy queries ─────────────────────────────────────

    # 1. ret2libc via GOT leak (highest priority for stack_overflow + NX + no PIE + libc)
    if ne.bug_type == "stack_overflow" and m.nx and not m.pie and ne.libc.available:
        if has_write:
            queries.append(SearchQuery(
                query=f"{arch_str} ret2libc write@plt leak write@got pwntools",
                priority=1.0,
                purpose="Primary: ret2libc via write@plt GOT leak with provided libc",
                expected_strategy="ret2libc",
                must_include_terms=["ret2libc", "write", "GOT", "pwntools"],
                avoid_terms=["shellcode"],
            ))
            queries.append(SearchQuery(
                query=f"pwntools {arch_bit_str} write plt got ret2libc",
                priority=0.9,
                purpose="Alternative phrasing: ret2libc write GOT leak",
                expected_strategy="ret2libc",
                must_include_terms=["pwntools", "ret2libc"],
                avoid_terms=[],
            ))
        if has_puts:
            queries.append(SearchQuery(
                query=f"{arch_str} ret2libc puts@plt leak puts@got pwntools",
                priority=1.0,
                purpose="Primary: ret2libc via puts@plt GOT leak with provided libc",
                expected_strategy="ret2libc",
                must_include_terms=["ret2libc", "puts", "GOT", "pwntools"],
                avoid_terms=["shellcode"],
            ))

        # General GOT leak
        queries.append(SearchQuery(
            query=f"CTF pwn provided libc ret2libc GOT leak {arch_bit_str}",
            priority=0.85,
            purpose="General: libc-based ret2libc with GOT leak",
            expected_strategy="ret2libc",
            must_include_terms=["ret2libc", "libc", "GOT"],
            avoid_terms=["shellcode"],
        ))

    # 2. Format string queries
    if ne.bug_type == "format_string":
        queries.append(SearchQuery(
            query=f"{arch_bit_str} format string GOT overwrite pwntools",
            priority=1.0,
            purpose="Primary: format string GOT overwrite",
            expected_strategy="format_string",
            must_include_terms=["format string", "GOT", "pwntools"],
            avoid_terms=[],
        ))
        queries.append(SearchQuery(
            query=f"{arch_bit_str} format string info leak libc base pwntools",
            priority=0.9,
            purpose="Format string libc leak",
            expected_strategy="format_string",
            must_include_terms=["format string", "libc", "pwntools"],
            avoid_terms=[],
        ))

    # 3. Offset search (if not verified)
    if v.candidate_eip_offset is not None and not v.offset_verified:
        queries.append(SearchQuery(
            query=f"site:docs.pwntools.com cyclic_find EIP offset {arch_str}",
            priority=0.8,
            purpose="pwntools cyclic_find usage for offset measurement",
            expected_strategy="any",
            must_include_terms=["cyclic_find"],
            avoid_terms=[],
        ))
    elif v.candidate_eip_offset is None:
        queries.append(SearchQuery(
            query=f"{arch_bit_str} stack overflow EIP offset cyclic pattern measurement",
            priority=0.8,
            purpose="General offset measurement techniques",
            expected_strategy="any",
            must_include_terms=["offset", "cyclic", arch_str],
            avoid_terms=[],
        ))

    # 4. Architecture-specific ROP queries
    if ne.bug_type == "stack_overflow" and m.nx:
        if ne.arch == "amd64":
            queries.append(SearchQuery(
                query="amd64 ret2libc pop rdi ret gadget pwntools ROP",
                priority=0.7,
                purpose="amd64-specific: pop rdi; ret gadget use",
                expected_strategy="ret2libc",
                must_include_terms=["pop rdi", "ret", "pwntools"],
                avoid_terms=[],
            ))
        queries.append(SearchQuery(
            query=f"site:ropemporium.com PLT GOT {arch_bit_str} ROP",
            priority=0.6,
            purpose="ROP Emporium references for ret2libc",
            expected_strategy="ret2libc",
            must_include_terms=["ROP", "PLT", "GOT"],
            avoid_terms=[],
        ))

    # 5. No libc fallback
    if not ne.libc.available:
        if ne.arch == "i386":
            queries.append(SearchQuery(
                query="i386 ret2dlresolve partial RELRO no libc pwntools",
                priority=0.65,
                purpose="Fallback: ret2dlresolve when no libc provided",
                expected_strategy="ret2dlresolve",
                must_include_terms=["ret2dlresolve", "i386"],
                avoid_terms=[],
            ))
        queries.append(SearchQuery(
            query=f"{arch_bit_str} DynELF pwntools libc leak remote",
            priority=0.55,
            purpose="Fallback: DynELF-based libc resolution",
            expected_strategy="DynELF",
            must_include_terms=["DynELF", "pwntools"],
            avoid_terms=[],
        ))

    # 6. One-gadget (secondary)
    if ne.libc.available and ne.bug_type == "stack_overflow":
        queries.append(SearchQuery(
            query=f"{arch_bit_str} one_gadget libc execve pwntools",
            priority=0.4,
            purpose="Secondary: one_gadget approach",
            expected_strategy="one_gadget",
            must_include_terms=["one_gadget"],
            avoid_terms=[],
        ))

    # 7. pwntools docs
    queries.append(SearchQuery(
        query=f"site:docs.pwntools.com ELF plt got {arch_str}",
        priority=0.5,
        purpose="pwntools ELF API reference",
        expected_strategy="any",
        must_include_terms=["ELF", "pwntools"],
        avoid_terms=[],
    ))

    # 8. ret2csu for amd64
    if ne.arch == "amd64" and ne.bug_type == "stack_overflow":
        queries.append(SearchQuery(
            query="amd64 ret2csu __libc_csu_init pwntools",
            priority=0.5,
            purpose="amd64 ret2csu technique",
            expected_strategy="ret2csu",
            must_include_terms=["ret2csu", "amd64"],
            avoid_terms=[],
        ))

    # ── Deduplicate and sort ──────────────────────────────────────
    seen = set()
    unique: List[SearchQuery] = []
    for q in sorted(queries, key=lambda x: -x.priority):
        if q.query.lower() not in seen:
            seen.add(q.query.lower())
            unique.append(q)

    return unique


def build_queries_with_llm(ne: NormalizedEvidence) -> List[SearchQuery]:
    """Generate search queries using LLM. Falls back to rule-based on error."""
    try:
        from automation.llm_client import chat_complete
        import json
        from pathlib import Path

        prompt_path = Path(__file__).parent / "prompts" / "search_planner_prompt.txt"
        system_prompt = prompt_path.read_text(encoding="utf-8")

        evidence_summary = {
            "arch": ne.arch,
            "bits": ne.bits,
            "endian": ne.endian,
            "bug_type": ne.bug_type,
            "mitigations": ne.mitigations.to_dict(),
            "imports": ne.imports,
            "plt": ne.symbols.get("plt", {}),
            "got": ne.symbols.get("got", {}),
            "libc_available": ne.libc.available,
            "libc_version": ne.libc.version,
            "vulnerability": {
                "function": ne.vulnerability.function,
                "type": ne.vulnerability.type,
                "candidate_eip_offset": ne.vulnerability.candidate_eip_offset,
                "offset_verified": ne.vulnerability.offset_verified,
                "candidate_fmt_offset": ne.vulnerability.candidate_fmt_offset,
            },
        }

        user_prompt = f"Evidence:\n{json.dumps(evidence_summary, indent=2, ensure_ascii=False)}"
        response = chat_complete(user_prompt, system_prompt, temperature=0.1)
        data = json.loads(response)

        queries: List[SearchQuery] = []
        for q in data.get("queries", []):
            queries.append(SearchQuery(
                query=q.get("query", ""),
                priority=float(q.get("priority", 0.5)),
                purpose=q.get("purpose", ""),
                expected_strategy=q.get("expected_strategy", ""),
                must_include_terms=q.get("must_include_terms", []),
                avoid_terms=q.get("avoid_terms", []),
            ))
        return queries if queries else build_queries(ne)
    except Exception:
        return build_queries(ne)
