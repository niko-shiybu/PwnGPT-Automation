from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from retrieve.evidence_normalizer import normalize
from retrieve.query_builder import build_queries, build_queries_with_llm
from retrieve.web_search import _create_client, DummySearchClient
from retrieve.source_ranker import rank_results
from retrieve.recipe_extractor import extract_from_search_results, extract_with_llm
from retrieve.strategy_scorer import score_and_rank
from retrieve.schemas import (
    NormalizedEvidence,
    SearchQuery,
    SearchResult,
    StrategyCandidate,
    StrategyCandidatesOutput,
    StrategyRecipe,
)

LOCAL_RECIPE_DB = Path(__file__).parent / "local_recipe_db.jsonl"


def _load_local_recipes() -> List[StrategyRecipe]:
    """Load built-in strategy recipes from local_recipe_db.jsonl."""
    recipes: List[StrategyRecipe] = []
    if not LOCAL_RECIPE_DB.exists():
        return recipes
    for line in LOCAL_RECIPE_DB.read_text(encoding="utf-8").strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            recipes.append(StrategyRecipe(
                id=data.get("id", ""),
                name=data.get("name", ""),
                technique=data.get("technique", "unknown"),
                arch=data.get("arch", []),
                base_score=float(data.get("base_score", 0.5)),
                preconditions=data.get("preconditions", []),
                required_measurements=data.get("required_measurements", []),
                payload_shape=data.get("payload_shape", []),
                failure_signatures=data.get("failure_signatures", {}),
                source_refs=[{"type": "local_recipe_db", "url": None, "title": "local built-in recipe"}],
                confidence=0.85,
            ))
        except Exception:
            continue
    return recipes


def _dedup_recipes(recipes: List[StrategyRecipe]) -> List[StrategyRecipe]:
    """Deduplicate recipes by id, keeping the highest confidence version."""
    seen: Dict[str, StrategyRecipe] = {}
    for r in recipes:
        if r.id not in seen or r.confidence > seen[r.id].confidence:
            seen[r.id] = r
    return list(seen.values())


def _run_search(
    queries: List[SearchQuery],
    client: Optional[any] = None,
    *,
    use_llm: bool = False,
    ne: Optional[NormalizedEvidence] = None,
) -> List[StrategyRecipe]:
    """Run web search for all queries and extract recipes."""
    if client is None:
        client = _create_client()

    all_recipes: List[StrategyRecipe] = []

    for q in queries:
        try:
            results = client.search(q, max_results=5)
        except Exception:
            results = []

        if not results:
            continue

        ranked = rank_results(results)

        if use_llm and ne:
            recipes = extract_with_llm(ne, q, ranked)
        else:
            recipes = extract_from_search_results(ne, q, ranked)

        all_recipes.extend(recipes)
        time.sleep(0.1)  # rate limit

    return all_recipes


def run(
    evidence_path: str,
    *,
    out_path: str = "strategy_candidates.json",
    top_k: int = 5,
    use_llm: bool = False,
    search_only: bool = False,
) -> StrategyCandidatesOutput:
    """Main pipeline: evidence → normalize → search → extract → score → output.

    Args:
        evidence_path: Path to evidence.json
        out_path: Output path for strategy_candidates.json
        top_k: Number of top candidates to return
        use_llm: Use LLM for query planning and recipe extraction (default: rule-based)
        search_only: Only use local recipe DB, skip web search
    """
    # ── Load evidence ──────────────────────────────────────
    evidence_raw = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    ne = normalize(evidence_raw)

    # ── Build queries ───────────────────────────────────────
    if use_llm:
        queries = build_queries_with_llm(ne)
    else:
        queries = build_queries(ne)

    # ── Load local recipes ──────────────────────────────────
    local_recipes = _load_local_recipes()

    # ── Web search ─────────────────────────────────────────
    web_recipes: List[StrategyRecipe] = []
    search_client = _create_client()

    if not search_only and search_client.available:
        web_recipes = _run_search(queries, client=search_client, use_llm=use_llm, ne=ne)
    elif not search_client.available and not search_only:
        # Graceful fallback: just use local recipes
        pass

    # ── Merge & dedup ─────────────────────────────────────
    all_recipes = _dedup_recipes(local_recipes + web_recipes)

    # ── Score & rank ──────────────────────────────────────
    candidates = score_and_rank(all_recipes, ne, top_k=top_k)

    # ── Build output ──────────────────────────────────────
    output = StrategyCandidatesOutput(
        challenge_fingerprint={
            "arch": ne.arch,
            "bits": ne.bits,
            "bug_type": ne.bug_type,
            "mitigations": ne.mitigations.to_dict(),
            "imports": ne.imports,
            "plt": ne.symbols.get("plt", {}),
            "got": ne.symbols.get("got", {}),
            "libc_provided": ne.libc.available,
            "offset_status": "verified" if ne.vulnerability.offset_verified else "candidate_only",
        },
        warnings=ne.warnings,
        search_plan={
            "queries": [{"query": q.query, "priority": q.priority, "purpose": q.purpose} for q in queries],
            "sources": ["local_recipe_db"] + ([search_client.__class__.__name__] if search_client.available else []),
        },
        candidates=candidates,
    )

    # ── Write output ──────────────────────────────────────
    Path(out_path).write_text(output.to_json(), encoding="utf-8")

    return output


def main():
    parser = argparse.ArgumentParser(description="RETRIEVE_STRATEGIES: CTF pwn exploit strategy retrieval")
    parser.add_argument("--evidence", required=True, help="Path to evidence.json")
    parser.add_argument("--out", default="strategy_candidates.json", help="Output path (default: strategy_candidates.json)")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top candidates to output (default: 5)")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM for query planning and recipe extraction")
    parser.add_argument("--local-only", action="store_true", help="Skip web search, use only local recipe DB")

    args = parser.parse_args()

    result = run(
        evidence_path=args.evidence,
        out_path=args.out,
        top_k=args.top_k,
        use_llm=args.use_llm,
        search_only=args.local_only,
    )

    print(f"Wrote {len(result.candidates)} strategy candidates to {args.out}", file=sys.stderr)
    for c in result.candidates:
        print(f"  [{c.priority.upper()}] {c.id} score={c.score:.3f} — {c.name}", file=sys.stderr)


if __name__ == "__main__":
    main()
