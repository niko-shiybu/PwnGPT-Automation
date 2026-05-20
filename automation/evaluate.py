from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Dict, List, Tuple


def _load_manifest(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Manifest must be a JSON array of case objects.")
    required = {"problem", "binary", "challenge_type"}
    for i, case in enumerate(data):
        if not isinstance(case, dict):
            raise ValueError(f"Case index {i} is not an object.")
        missing = [k for k in required if k not in case]
        if missing:
            raise ValueError(f"Case index {i} missing required keys: {missing}")
    return data


def _resolve_python(repo_root: Path) -> str:
    """Use .venv python if available, else fall back to system python3."""
    venv_python = repo_root / ".venv" / "bin" / "python3"
    if venv_python.exists():
        return str(venv_python)
    return "python3"


def _run_case(
    repo_root: Path,
    case: Dict[str, Any],
    max_iters: int,
    timeout_s: int,
    orchestrator_script: str,
) -> Tuple[Dict[str, Any], str]:
    case_id = str(case.get("name") or "")
    python_bin = _resolve_python(repo_root)
    cmd = [
        python_bin,
        orchestrator_script,
        "--problem",
        str(case["problem"]),
        "--binary",
        str(case["binary"]),
        "--challenge-type",
        str(case["challenge_type"]),
        "--max-iters",
        str(max_iters),
        "--repo-root",
        str(repo_root),
    ]
    if case_id:
        cmd += ["--case-id", case_id]
    timeout_arg = None if timeout_s <= 0 else timeout_s
    proc = subprocess.run(
        cmd,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=timeout_arg,
        check=False,
    )
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = re.search(r"report=(.+)", output)
    report_path = Path(m.group(1).strip()) if m else None
    case_result: Dict[str, Any] = {
        "case": case,
        "command": " ".join(cmd),
        "exit_code": proc.returncode,
        "stdout_tail": "\n".join((proc.stdout or "").splitlines()[-40:]),
        "stderr_tail": "\n".join((proc.stderr or "").splitlines()[-40:]),
        "report_path": str(report_path) if report_path else "",
        "success": False,
        "error": "",
        "metrics": {},
    }
    if not report_path or not report_path.exists():
        case_result["error"] = "run_report_not_found"
        return case_result, output

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        case_result["error"] = f"run_report_parse_error:{exc}"
        return case_result, output

    case_result["success"] = bool(report.get("success", False))
    case_result["metrics"] = report.get("metrics", {})
    case_result["final_iteration"] = report.get("final_iteration")
    case_result["dominant_failure_class"] = report.get("metrics", {}).get("dominant_failure_class", "")
    case_result["latest_evidence_completeness"] = report.get("metrics", {}).get("latest_evidence_completeness", {})
    case_result["latest_probe_deterministic_coverage"] = report.get("metrics", {}).get(
        "latest_probe_deterministic_coverage", {}
    )
    return case_result, output


def _aggregate(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    successes = [r for r in results if r.get("success")]
    success_rate = (len(successes) / total) if total else 0.0

    retries: List[float] = []
    completeness_ratios: List[float] = []
    deterministic_cov_ratios: List[float] = []
    failure_class_count: Dict[str, int] = {}
    by_type: Dict[str, Dict[str, Any]] = {}

    for r in results:
        ctype = str(r.get("case", {}).get("challenge_type", "unknown"))
        by_type.setdefault(ctype, {"total": 0, "success": 0})
        by_type[ctype]["total"] += 1
        if r.get("success"):
            by_type[ctype]["success"] += 1

        m = r.get("metrics", {}) or {}
        mr = m.get("median_retries")
        if isinstance(mr, (int, float)):
            retries.append(float(mr))

        comp = (r.get("latest_evidence_completeness") or {}).get("required_fields_completeness_ratio")
        if isinstance(comp, (int, float)):
            completeness_ratios.append(float(comp))

        cov = (r.get("latest_probe_deterministic_coverage") or {}).get("deterministic_coverage_ratio")
        if isinstance(cov, (int, float)):
            deterministic_cov_ratios.append(float(cov))

        fc = r.get("dominant_failure_class")
        if isinstance(fc, str) and fc:
            failure_class_count[fc] = failure_class_count.get(fc, 0) + 1

    for ctype in by_type:
        t = by_type[ctype]["total"]
        s = by_type[ctype]["success"]
        by_type[ctype]["success_rate"] = round((s / t), 3) if t else 0.0

    dominant_failure_class = ""
    if failure_class_count:
        dominant_failure_class = sorted(failure_class_count.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    return {
        "total_cases": total,
        "success_cases": len(successes),
        "success_rate": round(success_rate, 3),
        "median_retries": round(median(retries), 3) if retries else 0.0,
        "avg_evidence_completeness_ratio": round(sum(completeness_ratios) / len(completeness_ratios), 3)
        if completeness_ratios
        else 0.0,
        "avg_probe_deterministic_coverage_ratio": round(sum(deterministic_cov_ratios) / len(deterministic_cov_ratios), 3)
        if deterministic_cov_ratios
        else 0.0,
        "dominant_failure_class": dominant_failure_class,
        "failure_class_count": failure_class_count,
        "by_challenge_type": by_type,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch evaluation for automation orchestrators")
    parser.add_argument(
        "--manifest",
        required=True,
        help="Path to JSON manifest array. Each case: {problem,binary,challenge_type[,name]}",
    )
    parser.add_argument("--repo-root", default=".", help="Repo root path")
    parser.add_argument("--max-iters", type=int, default=2, help="max-iters forwarded to orchestrate")
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout seconds per case. 0 or negative disables timeout (recommended if you only want max-iters to stop).",
    )
    parser.add_argument(
        "--orchestrator",
        default="automation/orchestrate_dual_llm.py",
        help="Orchestrator script path. Default: automation/orchestrate_dual_llm.py",
    )
    parser.add_argument(
        "--agent",
        choices=["tri-llm", "openhands"],
        default="tri-llm",
        help="Agent mode: tri-llm (Planner+ExploitWriter+Decider) or openhands (single agent).",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Output JSON path. Default: automation/benchmarks/<timestamp>-benchmark.json",
    )
    args = parser.parse_args()

    if args.agent == "openhands":
        args.orchestrator = "automation/openhands_runner.py"

    repo_root = Path(args.repo_root).resolve()
    manifest_path = Path(args.manifest).resolve()
    cases = _load_manifest(manifest_path)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    default_output = repo_root / "automation" / "benchmarks" / f"{ts}-benchmark.json"
    output_path = Path(args.output).resolve() if args.output else default_output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    raw_logs: List[Dict[str, str]] = []
    for idx, case in enumerate(cases, start=1):
        print(f"[{idx}/{len(cases)}] running {case.get('name') or case['problem']} ({case['challenge_type']})")
        try:
            case_result, output = _run_case(repo_root, case, args.max_iters, args.timeout, args.orchestrator)
        except subprocess.TimeoutExpired:
            case_result = {
                "case": case,
                "success": False,
                "error": f"timeout>{args.timeout}s",
                "metrics": {},
                "report_path": "",
            }
            output = ""
        results.append(case_result)
        raw_logs.append({"case": str(case.get("name") or case.get("problem")), "output_tail": "\n".join(output.splitlines()[-60:])})

    summary = _aggregate(results)
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest": str(manifest_path),
        "repo_root": str(repo_root),
        "max_iters": args.max_iters,
        "timeout_per_case_sec": args.timeout,
        "summary": summary,
        "results": results,
        "raw_logs_tail": raw_logs,
    }
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[DONE] benchmark_report={output_path}")
    print(
        f"success_rate={summary['success_rate']} "
        f"median_retries={summary['median_retries']} "
        f"dominant_failure_class={summary['dominant_failure_class'] or '(none)'}"
    )


if __name__ == "__main__":
    main()
