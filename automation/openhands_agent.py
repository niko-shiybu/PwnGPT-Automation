# DEPRECATED: Replaced by openhands_runner.py (OpenHands SDK integration).
# This file is kept for reference only. Use --engine openhands instead.
# See docs/superpowers/specs/2026-05-19-openhands-sdk-integration-design.md
"""OpenHands CodeAct Agent for CTF binary exploitation.

Replaces the tri-LLM pipeline (Planner + Exploit Writer + Decider) with
a single agent that can measure, write code, verify, and fix in a loop.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from automation import local_config
from automation.collect.evidence_collector import collect_evidence
from automation.openhands_adapter import (
    evidence_to_text,
    problem_text_summary,
    verify_result_to_text,
    save_exploit_code,
    save_run_report,
)
from automation.tools.tool_runner import (
    tool_stack_measure_ret_offset_gdb,
    tool_rop_find_gadgets,
    tool_fmt_measure_write_offset,
    tool_fmt_scan_stack,
    tool_pwntools_got,
    tool_pwntools_symbols,
    tool_disassemble,
)

# ---------------------------------------------------------------------------
# Tool wrappers — return JSON strings for the agent
# ---------------------------------------------------------------------------

def _measure_offset(path: str) -> str:
    r = tool_stack_measure_ret_offset_gdb(path)
    if r.measured_facts:
        return json.dumps({"offset": r.measured_facts.get("offsets.ret_offset_bytes")})
    return json.dumps({"error": str(r.unresolved_facts)})

def _find_gadgets(path: str) -> str:
    r = tool_rop_find_gadgets(path)
    return json.dumps(dict(r.measured_facts))

def _measure_fmt_offset(path: str) -> str:
    r = tool_fmt_measure_write_offset(path)
    if r.measured_facts:
        return json.dumps(dict(r.measured_facts))
    return json.dumps({"error": str(r.unresolved_facts)})

def _scan_fmt_stack(path: str) -> str:
    r = tool_fmt_scan_stack(path)
    if r.measured_facts:
        return json.dumps(dict(r.measured_facts))
    return json.dumps({"error": "scan_not_found"})

def _get_got(path: str, sym: str = "printf") -> str:
    r = tool_pwntools_got(path, symbol=sym)
    return json.dumps(dict(r.measured_facts))

def _get_symbols(path: str) -> str:
    r = tool_pwntools_symbols(path)
    return json.dumps(dict(r.measured_facts))

def _disasm(path: str, func: str = "main") -> str:
    r = tool_disassemble(path, function=func)
    raw = str(r.measured_facts.get("probe_artifacts.disassemble_main", ""))
    return raw[:5000]

TOOLS = {
    "measure_offset": ("Measure stack offset to return address", _measure_offset),
    "find_gadgets": ("Find ROP gadgets (pop_rdi, ret, etc.)", _find_gadgets),
    "measure_fmt_offset": ("Measure format string write offset", _measure_fmt_offset),
    "scan_fmt_stack": ("Scan fmt stack positions (AAAA%i$p)", _scan_fmt_stack),
    "get_got": ("Get a GOT entry address", _get_got),
    "get_symbols": ("Get binary symbols", _get_symbols),
    "disassemble": ("Disassemble a function", _disasm),
}


# ---------------------------------------------------------------------------
# Agent System Prompt
# ---------------------------------------------------------------------------

AGENT_SYSTEM_PROMPT = """You are a CTF binary exploitation agent.
You have tools available and must iteratively craft a working pwntools exploit.

=== WORKFLOW ===
1. Read the problem text to understand the vulnerability.
2. Plan exploitation strategy based on challenge type.
3. Use tools to MEASURE facts (offsets, gadgets, format string offsets).
4. Write candidate_exploit.py with your exploit code.
5. The harness will automatically verify (run) your exploit.
6. If it fails, read the verification output, diagnose, FIX the code.
7. Repeat until success or max iterations.

=== ROP (stack overflow) ===
- ret2text: payload = b"A" * OFFSET + p32/p64(win_addr)
- ret2libc 32-bit: p32(func) + p32(0x41414141) + p32(arg1) + p32(arg2)
  Use rop.call(func, [args]) to handle cdecl automatically.
- ret2libc 64-bit: MUST use pop_rdi for first argument.
  rop.call(puts_plt, [puts_got]) handles gadgets automatically.
  NEVER mix rop.raw() with rop.call() — pick one.
- ret2shellcode (NX disabled): shellcode = asm(shellcraft.sh())
- ALWAYS load libc from evidence.runtime.libc_path, NOT binary path.
- ALWAYS use binary.got/binary.plt, NEVER hardcode addresses.
- Use measured offset/gadget values from fact_store.

=== FMT (format string) ===
- Overwrite var: fmtstr_payload(OFFSET, {addr: value})
- Overwrite GOT (RELRO != full): fmtstr_payload(OFFSET, {binary.got['printf']: libc.symbols['system']})
- Full RELRO: GOT read-only. Leak libc via %s, overwrite return address instead.
- Leak: p64(puts_got) + b"%N$s" to read GOT, calculate libc_base.
- 64-bit: offset >= 6 from stack.
- Use measured fmt_offset from fact_store.

=== INT (integer overflow) ===
- uint8 strlen() truncation: payload length MUST be >255, strlen%256 in [4,8].
  payload = b"A" * OFFSET + p32(target_addr)
  payload += b"B" * (260 - len(payload))

=== GENERAL RULES ===
- from pwn import * includes everything needed.
- Use process(binary.path), NOT remote().
- Stage markers: print("[STAGE] exploit_start") / print("[STAGE] before_interactive").
- Avoid unbounded recv/recvall. Use sendlineafter() with IO prompts.
- Output ONLY Python code when writing exploit — no markdown, no explanation.

=== FIXING FAILURES ===
- KeyError: symbol not in binary. Use libc.symbols instead.
- SIGSEGV: wrong offset, missing pop_rdi, or cdecl error.
- struct.error: read fewer bytes or use .ljust(8, b'\\x00').
- BrokenPipe/clean exit: binary exited. Check IO prompts and sync.
- FIX only the specific problem, don't rewrite everything."""


# ---------------------------------------------------------------------------
# Agent Loop
# ---------------------------------------------------------------------------

def run_agent_loop(
    evidence,
    problem_text: str,
    run_dir: Path,
    max_iters: int = 6,
) -> Dict[str, Any]:
    fact_store: Dict[str, Any] = {}
    history: List[Dict] = []
    success = False
    epath = run_dir / "candidate_exploit.py"
    binary_abs = evidence.binary.path

    from automation.llm_client import chat_complete_detailed

    for it in range(1, max_iters + 1):
        ctx = f"""## Problem\n{problem_text}\n\n## Evidence\n{evidence_to_text(evidence, fact_store)}\n\n## Iteration {it}/{max_iters}"""

        if it == 1:
            ctx += "\n\nFIRST ITERATION: Use tools to measure facts, then write exploit code."

        # ---- Agent decides: measure or write ----
        prompt = ctx + """
Respond with JSON to request measurements, or Python code for the exploit.

For measurements: {"action":"measure","tools":[{"name":"...","args":{}}]}

For exploit: Output ONLY Python code."""
        res = chat_complete_detailed(prompt, AGENT_SYSTEM_PROMPT, temperature=0.1)

        if res.raw_content.strip().startswith("{") and '"action"' in res.raw_content:
            try:
                req = json.loads(res.raw_content)
                for t in req.get("tools", []):
                    name, args = t.get("name", ""), t.get("args", {})
                    fn = TOOLS.get(name, (None, None))[1]
                    if fn:
                        try:
                            result = fn(args.get("binary_path", binary_abs), **{k: v for k, v in args.items() if k != "binary_path"})
                            if isinstance(result, str):
                                result = json.loads(result)
                            fact_store.update(result if isinstance(result, dict) else {})
                        except Exception:
                            pass
            except Exception:
                pass
            continue  # After measuring, loop to next iteration

        # ---- Write exploit ----
        code = res.raw_content
        save_exploit_code(str(epath), code)

        from automation.verify.verifier import verify_exploit
        v = verify_exploit(str(epath), timeout_sec=20, repo_root=str(repo_root))
        (run_dir / f"verify_iter{it}.txt").write_text(v.to_json())

        if v.success:
            success = True
            history.append({"iteration": it, "verify": {"success": True, "exit_code": v.exit_code}, "decider": {"failure": "", "notes": ["success"]}})
            break

        # ---- Diagnose + fix ----
        diag = verify_result_to_text({"success": v.success, "exit_code": v.exit_code, "stdout_tail": v.stdout_tail, "stderr_tail": v.stderr_tail})
        fix_prompt = f"Exploit failed:\n\n{diag}\n\nDiagnose and write CORRECTED exploit code (Python only):"
        res2 = chat_complete_detailed(fix_prompt, AGENT_SYSTEM_PROMPT, temperature=0.1)
        save_exploit_code(str(epath), res2.raw_content)

        v = verify_exploit(str(epath), timeout_sec=20, repo_root=str(repo_root))
        if v.success:
            success = True

        history.append({
            "iteration": it,
            "planner_strategy": "", "plan_measurements": [],
            "verify": {"success": v.success, "exit_code": v.exit_code, "stdout_tail": v.stdout_tail, "stderr_tail": v.stderr_tail, "failure_signals": []},
            "decider": {"failure": str(v.stderr_tail or "")[:500], "next_action": "", "notes": []},
            "fact_store_size": len(fact_store),
        })

    report = {
        "run_id": run_dir.name, "pipeline": "openhands_agent",
        "challenge_type": evidence.challenge_type,
        "problem": evidence.problem_path, "binary": evidence.binary.path,
        "success": success, "final_iteration": len(history),
        "model_roles": {"agent_model": getattr(local_config, "OPENHANDS_MODEL", "default")},
        "fact_store": fact_store, "iterations": history,
        "metrics": {"planner_to_executor_rounds": {"planner_rounds": len(history), "executor_rounds": len(history)}, "decider_rounds": len(history), "avg_value_score": 0, "fact_coverage_ratio": 0, "final_failure_class": "" if success else "decider"},
    }
    save_run_report(str(run_dir / "run_report.json"), report)
    return report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="OpenHands agent for CTF pwn")
    p.add_argument("--problem", required=True)
    p.add_argument("--binary", required=True)
    p.add_argument("--challenge-type", required=True, choices=["fmt","int","heap","rop"])
    p.add_argument("--repo-root", required=True)
    p.add_argument("--max-iters", type=int, default=6)
    p.add_argument("--case-id", default="")
    args = p.parse_args()

    root = Path(args.repo_root).resolve()
    sid = args.case_id.strip().replace("/", "-")
    rid = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-dual")
    if sid:
        rid = f"{rid}-{sid}"
    rd = root / "automation" / "runs" / rid
    rd.mkdir(parents=True, exist_ok=True)

    ev = collect_evidence(problem_path=args.problem, binary_path=args.binary, challenge_type=args.challenge_type, repo_root=root)

    from automation.orchestrate_dual_llm import _ensure_binary_runnable
    _ensure_binary_runnable(str(root / args.binary))

    (rd / "evidence.json").write_text(ev.to_json())
    pt = problem_text_summary(str(root / args.problem))
    rpt = run_agent_loop(ev, pt, rd, args.max_iters)

    status = "PASS" if rpt["success"] else "FAIL"
    print(f"[{status}] iteration={rpt['final_iteration']}")
    print(f"evidence={rd / 'evidence.json'}")
    print(f"report={rd / 'run_report.json'}")
    print(f"exploit={rd / 'candidate_exploit.py'}")

if __name__ == "__main__":
    main()
