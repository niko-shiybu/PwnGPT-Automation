"""OpenHands SDK runner — replaces openhands_agent.py."""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from automation import local_config
from automation.collect.evidence_collector import collect_evidence
from automation.logging_utils import append_run_log
from automation.schemas import Evidence
from automation.verify.verifier import verify_exploit


def _load_problem_text(problem_path: str) -> str:
    try:
        text = Path(problem_path).read_text(encoding="utf-8", errors="ignore")
        if len(text) > 15000:
            text = text[:15000] + "\n... (truncated)\n"
        return text
    except Exception:
        return "(problem text not available)"


def _evidence_to_text(evidence: Evidence, fact_store: Dict[str, Any]) -> str:
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
    important_funcs = {
        k: v
        for k, v in funcs.items()
        if any(
            kw in k.lower()
            for kw in ("main", "win", "flag", "magic", "backdoor", "vuln", "call_me", "exec_", "system")
        )
    }
    if important_funcs:
        parts.append(f"Key functions: {json.dumps(important_funcs)}")
    bf = evidence.binary_features or {}
    if bf:
        parts.append(f"Binary features: {json.dumps(bf, ensure_ascii=False)}")
    runtime = evidence.runtime or {}
    if runtime.get("libc_path"):
        parts.append(f"Libc path: {runtime['libc_path']}")
    if fact_store:
        parts.append("\n=== MEASURED FACTS ===")
        for k, v in fact_store.items():
            parts.append(f"  {k}: {v}")
    return "\n".join(parts)


SYSTEM_PROMPT = """You are a CTF binary exploitation agent. You have TerminalTool, FileEditorTool, and MCP tools (including web_search for looking up strategies and fixes).

=== WORKFLOW ===
1. Read the problem text to understand the vulnerability and challenge type.
2. Use MCP tools to MEASURE facts (offsets, gadgets, format string offsets).
3. If unsure about the exploitation strategy, use web_search to find the correct approach.
4. Write candidate_exploit.py with your pwntools exploit code using FileEditorTool.
5. Run the exploit with TerminalTool: python3 candidate_exploit.py
6. If it fails, read the error output, diagnose, use web_search to find fixes, FIX the code.
7. Repeat until you get a shell or flag.

=== GENERAL RULES ===
- from pwn import * includes everything needed.
- Use process(binary.path), NOT remote().
- Stage markers: print("[STAGE] exploit_start") / print("[STAGE] before_interactive").
- Avoid unbounded recv/recvall. Use sendlineafter() with IO prompts.
- Output ONLY Python code when writing exploit. No markdown, no explanation.
- ALWAYS load libc from the evidence, NOT from the binary path.
- Use binary.got / binary.plt for addresses, NEVER hardcode 0x addresses."""


def run_openhands_agent(
    evidence: Evidence,
    problem_text: str,
    run_dir: Path,
    event_logger: Callable[[str, dict], None],
    max_iters: int = 5,
) -> Dict[str, Any]:
    from openhands.sdk import LLM, Agent, LocalConversation, LocalWorkspace
    from openhands.tools import get_default_tools

    model = getattr(local_config, "OPENHANDS_MODEL", "qwen-max")
    api_key = getattr(local_config, "OPENHANDS_API_KEY", "")
    base_url = getattr(local_config, "OPENHANDS_BASE_URL", "")

    # Setup workspace directory for this run
    ws_dir = run_dir / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)

    # Copy binary to workspace so agent can access it
    binary_src = Path(evidence.binary.path)
    if binary_src.exists():
        import shutil
        ws_binary = ws_dir / "binary"
        shutil.copy2(binary_src, ws_binary)

    # Write evidence and problem to workspace for agent to read
    (ws_dir / "evidence.json").write_text(evidence.to_json())
    (ws_dir / "problem.txt").write_text(problem_text)

    llm_kwargs = {"model": model, "api_key": api_key}
    if base_url:
        llm_kwargs["base_url"] = base_url

    llm = LLM(**llm_kwargs)
    agent = Agent(
        llm=llm,
        tools=[t for t in get_default_tools() if t.name in ("terminal", "file_editor")],
        system_prompt=SYSTEM_PROMPT,
        include_default_tools=['ThinkTool'],  # Remove FinishTool so Agent can't auto-stop
        mcp_config={
            "pwn_tools": {
                "command": sys.executable,
                "args": ["-m", "automation.tools.mcp_server"],
                "cwd": str(_repo_root),
            }
        },
    )

    workspace = LocalWorkspace(working_dir=str(ws_dir))
    conversation = LocalConversation(
        agent=agent,
        workspace=workspace,
        max_iteration_per_run=max_iters,
    )

    initial_prompt = f"""## Problem
{problem_text}

## Evidence
{_evidence_to_text(evidence, {})}

## MANDATORY: You CANNOT stop or finish. Keep trying until you get a shell.
1. Use MCP tools (measure_offset, find_gadgets, measure_fmt_offset, web_search, etc.) to measure facts.
2. Write candidate_exploit.py using FileEditorTool.
3. Run: python3 candidate_exploit.py
4. If it fails: read the error → search for fixes → edit the code → re-run.
5. REPEAT until you see a shell prompt ($) or flag output. NEVER stop early.

The binary is at: binary (in the current working directory)"""

    conversation.send_message(initial_prompt)

    try:
        conversation.run()
    except Exception as exc:
        event_logger("sdk_error", {"error": str(exc)})
        return _make_report(evidence, run_dir, model, success=False, failure="sdk_error", iterations=[])

    # Collect per-iteration snapshots from workspace + verify each
    iterations = []
    success = False
    final_failure = "no_code"

    # Try named snapshots first
    for it in range(1, max_iters + 1):
        snap = ws_dir / "candidate_exploit_iter{}.py".format(it)
        if not snap.exists():
            break
        snap_code = snap.read_text(encoding="utf-8", errors="ignore")
        dest = run_dir / "candidate_exploit_iter{}.py".format(it)
        import shutil
        shutil.copy2(snap, dest)
        (run_dir / "candidate_exploit.py").write_text(snap_code, encoding="utf-8")
        v = verify_exploit(run_dir / "candidate_exploit.py", cwd=_repo_root)
        (run_dir / "verify_iter{}.txt".format(it)).write_text(v.to_json())
        iterations.append({
            "iteration": it,
            "verify": {"success": v.success, "exit_code": v.exit_code,
                       "stdout_tail": v.stdout_tail, "stderr_tail": v.stderr_tail},
        })
        if v.success:
            success = True
            break
        final_failure = v.summary

    # Fallback: use the final candidate_exploit.py
    exploit_path = ws_dir / "candidate_exploit.py"
    if not iterations and exploit_path.exists():
        code = exploit_path.read_text(encoding="utf-8", errors="ignore")
        (run_dir / "candidate_exploit.py").write_text(code, encoding="utf-8")
        v = verify_exploit(run_dir / "candidate_exploit.py", cwd=_repo_root)
        (run_dir / "verify_final.txt").write_text(v.to_json())
        iterations = [{
            "iteration": 1,
            "verify": {"success": v.success, "exit_code": v.exit_code,
                       "stdout_tail": v.stdout_tail, "stderr_tail": v.stderr_tail},
        }]
        success = v.success
        final_failure = "" if v.success else v.summary

    return _make_report(
        evidence, run_dir, model,
        success=success, failure=final_failure,
        iterations=iterations,
    )



def _make_report(
    evidence: Evidence,
    run_dir: Path,
    model: str,
    *,
    success: bool,
    failure: str,
    iterations: list,
) -> Dict[str, Any]:
    return {
        "run_id": run_dir.name,
        "pipeline": "openhands_sdk",
        "engine": "openhands",
        "challenge_type": evidence.challenge_type,
        "problem": evidence.problem_path,
        "binary": evidence.binary.path,
        "success": success,
        "final_iteration": len(iterations),
        "model_roles": {"agent_model": model},
        "fact_store": {},
        "iterations": iterations or [{"verify": {"success": success, "exit_code": 0}}],
        "metrics": {"final_failure_class": failure},
    }


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(description="OpenHands SDK agent for CTF pwn")
    p.add_argument("--problem", required=True)
    p.add_argument("--binary", required=True)
    p.add_argument("--challenge-type", required=True, choices=["fmt", "int", "heap", "rop"])
    p.add_argument("--repo-root", required=True)
    p.add_argument("--max-iters", type=int, default=30)
    p.add_argument("--case-id", default="")
    args = p.parse_args()

    root = Path(args.repo_root).resolve()
    sid = args.case_id.strip().replace("/", "-")
    rid = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-ohsdk")
    if sid:
        rid = f"{rid}-{sid}"
    rd = root / "automation" / "runs" / rid
    rd.mkdir(parents=True, exist_ok=True)
    run_log = rd / "run.log"

    def log_event(event: str, data: dict) -> None:
        append_run_log(run_log, event, data)

    ev = collect_evidence(
        problem_path=args.problem,
        binary_path=args.binary,
        challenge_type=args.challenge_type,
        repo_root=root,
    )
    from automation.orchestrate_dual_llm import _ensure_binary_runnable

    _ensure_binary_runnable(str(root / args.binary))

    (rd / "evidence.json").write_text(ev.to_json())
    pt = _load_problem_text(str(root / args.problem))

    rpt = run_openhands_agent(ev, pt, rd, log_event, max_iters=args.max_iters)

    _save_json(rd / "run_report.json", rpt)

    status = "PASS" if rpt["success"] else "FAIL"
    print(f"[{status}] iteration={rpt['final_iteration']}")
    print(f"evidence={rd / 'evidence.json'}")
    print(f"report={rd / 'run_report.json'}")
    print(f"exploit={rd / 'candidate_exploit.py'}")


def _save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
