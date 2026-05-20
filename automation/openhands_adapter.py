# DEPRECATED: Adapter logic merged into openhands_runner.py.
# This file is kept for reference only.
"""Adaptation layer: convert internal types to OpenHands agent-readable text."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from automation.schemas import Evidence


def evidence_to_text(evidence: Evidence, fact_store: Dict[str, Any]) -> str:
    """Convert evidence + fact_store into a structured text block for the agent."""
    parts = [
        f"Challenge type: {evidence.challenge_type}",
        f"Binary path: {evidence.binary.path}",
        f"Architecture: {evidence.binary.arch}",
        f"Checksec: {evidence.binary.checksec_raw or 'N/A'}",
    ]

    sm = evidence.symbols_map or {}
    plt = sm.get("plt", {})
    got = sm.get("got", {})
    funcs = sm.get("funcs", {})
    if plt:
        parts.append(f"PLT entries: {json.dumps(list(plt.keys()))}")
    if got:
        parts.append(f"GOT entries: {json.dumps(list(got.keys()))}")
    important_funcs = {k: v for k, v in funcs.items()
                       if any(kw in k.lower() for kw in ("main", "win", "flag", "magic", "backdoor",
                                                          "vuln", "call_me", "exec_", "system"))}
    if important_funcs:
        parts.append(f"Key functions: {json.dumps(important_funcs)}")

    bf = evidence.binary_features or {}
    if bf:
        parts.append(f"Binary features: {json.dumps(bf, ensure_ascii=False)}")

    runtime = evidence.runtime or {}
    if runtime.get("libc_path"):
        parts.append(f"Libc path: {runtime['libc_path']}")

    if fact_store:
        parts.append(f"\n=== MEASURED FACTS (fact_store) ===")
        for k, v in fact_store.items():
            parts.append(f"  {k}: {v}")

    return "\n".join(parts)


def problem_text_summary(problem_path: str) -> str:
    """Return the problem text truncated to agent-friendly size."""
    try:
        text = open(problem_path, encoding="utf-8", errors="ignore").read()
        if len(text) > 15000:
            text = text[:15000] + "\n... (truncated)\n"
        return text
    except Exception:
        return "(problem text not available)"


def verify_result_to_text(result: Dict[str, Any]) -> str:
    """Convert a verify result dict into agent-readable diagnosis."""
    success = result.get("success", False)
    exit_code = result.get("exit_code")
    stdout = str(result.get("stdout_tail", ""))[-3000:]
    stderr = str(result.get("stderr_tail", ""))[-3000:]

    parts = [
        f"Exploit result: {'SUCCESS' if success else 'FAILED'} (exit code: {exit_code})",
        "",
        "=== STDOUT ===",
        stdout or "(empty)",
        "",
        "=== STDERR ===",
        stderr or "(empty)",
    ]
    return "\n".join(parts)


def load_evidence(evidence_path: str) -> Evidence:
    """Load evidence JSON from a file path."""
    import os
    if not os.path.exists(evidence_path):
        raise FileNotFoundError(f"evidence.json not found: {evidence_path}")
    return Evidence.from_dict(json.loads(open(evidence_path).read()))


def save_exploit_code(output_path: str, code: str) -> None:
    """Write exploit code to file after deterministic hardening."""
    from automation.orchestrate_dual_llm import _harden_exploit_code
    import os

    run_dir = os.path.dirname(output_path)
    evidence_path = os.path.join(run_dir, "evidence.json")
    evidence = load_evidence(evidence_path) if os.path.exists(evidence_path) else None

    from automation.llm_client import _extract_code
    cleaned = _extract_code(code)

    if evidence:
        cleaned = _harden_exploit_code(cleaned, evidence)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(cleaned)


def save_run_report(report_path: str, report: Dict[str, Any]) -> None:
    """Write run_report.json compatible with evaluate.py."""
    import os
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
