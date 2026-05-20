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


SYSTEM_PROMPT = """You are a CTF binary exploitation agent. You have TerminalTool and FileEditorTool available, plus MCP tools for CTF-specific measurements.

=== WORKFLOW ===
1. Read the problem text to understand the vulnerability and challenge type.
2. Use MCP tools to MEASURE facts (offsets, gadgets, format string offsets).
3. Write candidate_exploit.py with your pwntools exploit code using FileEditorTool.
4. Run the exploit with TerminalTool: python3 candidate_exploit.py
5. If it fails, read the error output, diagnose, FIX the code.
6. Repeat until you get a shell or flag.

=== ROP (stack overflow) ===
- ret2text: payload = b"A" * OFFSET + p32/p64(win_addr)
- ret2libc 64-bit: MUST use pop_rdi for first argument. Use rop.call(func, [args]).
- ret2shellcode (NX disabled): shellcode = asm(shellcraft.sh())
- Use measured offset/gadget values from MCP tools.

=== FMT (format string) ===
- Overwrite var: fmtstr_payload(OFFSET, {addr: value})
- Overwrite GOT (RELRO != full): fmtstr_payload(OFFSET, {binary.got['printf']: libc.symbols['system']})
- Full RELRO: leak libc via %s, overwrite return address instead.
- Use measured fmt_offset from MCP tools.

=== GENERAL RULES ===
- from pwn import * includes everything needed.
- Use process(binary.path), NOT remote().
- Stage markers: print("[STAGE] exploit_start") / print("[STAGE] before_interactive").
- Avoid unbounded recv/recvall. Use sendlineafter() with IO prompts.
- Output ONLY Python code when writing exploit. No markdown, no explanation."""


def run_openhands_agent(
    evidence: Evidence,
    problem_text: str,
    run_dir: Path,
    event_logger: Callable[[str, dict], None],
) -> Dict[str, Any]:
    from openhands.sdk import LLM, Agent, LocalConversation, LocalWorkspace
    from openhands.tools.terminal import TerminalTool
    from openhands.tools.file_editor import FileEditorTool

    model = getattr(local_config, "OPENHANDS_MODEL", "qwen-max")
    api_key = getattr(local_config, "OPENHANDS_API_KEY", "")
    base_url = getattr(local_config, "OPENHANDS_BASE_URL", "")
    max_iters = getattr(local_config, "OPENHANDS_MAX_ITERATIONS", 30)

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
        tools=[TerminalTool, FileEditorTool],
        system_prompt=SYSTEM_PROMPT,
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

## Instructions
1. Use MCP tools to measure any needed facts (offsets, gadgets, format string positions).
2. Write your exploit as candidate_exploit.py using FileEditorTool.
3. Run the exploit with TerminalTool: python3 candidate_exploit.py
4. If it crashes or fails, read the output, diagnose the error, and fix the code.
5. Iterate until you get a shell or the flag.

The binary is at: binary (in the current working directory)"""

    conversation.send_message(initial_prompt)

    try:
        conversation.run()
    except Exception as exc:
        event_logger("sdk_error", {"error": str(exc)})
        return _make_report(evidence, run_dir, model, success=False, failure="sdk_error")

    # Extract exploit code from workspace
    exploit_path = ws_dir / "candidate_exploit.py"
    code = ""
    if exploit_path.exists():
        code = exploit_path.read_text(encoding="utf-8", errors="ignore")

    if not code:
        return _make_report(evidence, run_dir, model, success=False, failure="no_code")

    # Copy exploit to run_dir
    (run_dir / "candidate_exploit.py").write_text(code, encoding="utf-8")

    # Verify
    v = verify_exploit(run_dir / "candidate_exploit.py", cwd=_repo_root)
    (run_dir / "verify_final.txt").write_text(v.to_json())

    return _make_report(
        evidence,
        run_dir,
        model,
        success=v.success,
        failure="" if v.success else v.summary,
        iterations=1,
    )


def _make_report(
    evidence: Evidence,
    run_dir: Path,
    model: str,
    *,
    success: bool,
    failure: str,
    iterations: int = 0,
) -> Dict[str, Any]:
    return {
        "run_id": run_dir.name,
        "pipeline": "openhands_sdk",
        "engine": "openhands",
        "challenge_type": evidence.challenge_type,
        "problem": evidence.problem_path,
        "binary": evidence.binary.path,
        "success": success,
        "final_iteration": iterations,
        "model_roles": {"agent_model": model},
        "fact_store": {},
        "iterations": [{"verify": {"success": success, "exit_code": 0}}],
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

    rpt = run_openhands_agent(ev, pt, rd, log_event)

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
