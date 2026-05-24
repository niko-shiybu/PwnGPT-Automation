from __future__ import annotations

from typing import Any, Dict, Optional

from automation.schemas import Evidence

from automation.audit.audit_report import AuditReport
from automation.audit.auditors.base_auditor import build_context, build_code_summary
from automation.audit.auditors.generic_auditor import run_generic_checks
from automation.audit.auditors.rop_auditor import run_rop_checks
from automation.audit.auditors.fmt_auditor import run_fmt_checks
from automation.audit.auditors.int_auditor import run_int_checks
from automation.audit.auditors.heap_auditor import run_heap_checks


def run_static_audit(
    candidate_exploit_code: str,
    evidence: Evidence,
    fact_store: Dict[str, Any],
    runtime_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run static analysis on the exploit code and return structured findings.

    Parameters:
        candidate_exploit_code: Raw Python source of the generated exploit.
        evidence: Evidence dataclass with binary info, symbols, etc.
        fact_store: Accumulated measured facts (offsets, probe artifacts).
        runtime_result: Optional verify result dict (unused currently, for future use).

    Returns:
        Dict with "static_audit" key containing findings and code_summary.
        Always returns a valid structure even if analysis fails.
    """
    report = AuditReport()

    try:
        # Phase 1: Build analysis context and code summary
        ctx = build_context(candidate_exploit_code, evidence, fact_store)
        report.code_summary = build_code_summary(ctx)

        # Phase 2: Run generic checks (all challenge types)
        run_generic_checks(ctx, report)

        # Phase 3: Run type-specific checks
        challenge_type = evidence.challenge_type
        if challenge_type == "rop":
            run_rop_checks(ctx, report)
        elif challenge_type == "fmt":
            run_fmt_checks(ctx, report)
        elif challenge_type == "int":
            run_int_checks(ctx, report)
        elif challenge_type == "heap":
            run_heap_checks(ctx, report)

        # Store raw analysis for debugging
        report.raw_analysis = ctx.to_debug_dict()

    except Exception as exc:
        from automation.audit.audit_report import AuditFinding
        report.findings.append(
            AuditFinding(
                type="AUDIT_INTERNAL_ERROR",
                severity="INFO",
                category="generic",
                location="audit_engine",
                detail=f"Static audit encountered an internal error: {exc}. "
                        f"This does not affect pipeline execution.",
                suggestion="Check audit engine logs for details.",
            )
        )

    return report.to_json_payload()
