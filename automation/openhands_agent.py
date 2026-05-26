"""OpenHands CodeAct Agent for CTF binary exploitation.

Single agent loop: COLLECT → RETRIEVE_STRATEGIES → Agent Loop (PLAN → MEASURE → WRITE → VERIFY → FIX).
"""

from __future__ import annotations

import argparse
import json
import re
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
    tool_run_binary_with_payload,
)


# ---------------------------------------------------------------------------
# Tool wrappers
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
1. Read the problem text and strategy candidates to understand the vulnerability.
2. Plan exploitation strategy based on strategy candidates and evidence.
3. **MANDATORY: Use tools to MEASURE facts BEFORE writing any exploit.**
   - For stack/rop: measure_offset, find_gadgets, get_got, get_symbols
   - For fmt: measure_fmt_offset, scan_fmt_stack, get_got
   - You CANNOT skip measurements if the fact store is empty.
4. Only AFTER measurements are done, write candidate_exploit.py.
5. The harness will auto-verify your exploit.
6. If it fails, read the verification output, diagnose the EXACT bug, FIX it.

=== MEASUREMENT RULES ===
- NEVER guess offsets or addresses. ALWAYS measure them with tools.
- If fact_store is empty, you MUST request measurements.
- For stack overflow: measure_offset is mandatory.
- For format string: measure_fmt_offset or scan_fmt_stack is mandatory.
- Only set "measurements": [] AFTER you have all needed facts.

=== GENERAL RULES ===
- from pwn import * includes everything needed.
- Use process(binary.path), NOT remote().
- Stage markers: print("[STAGE] exploit_start") / print("[STAGE] before_interactive").
- Avoid unbounded recv/recvall. Use sendlineafter() with IO prompts.
- After leaking libc, compute: libc.address = leaked - libc.symbols['func'].
- For amd64: use pop_rdi_ret before system, and add a "ret" gadget for stack alignment.
- Output ONLY Python code when writing exploit — no markdown, no explanation.

=== FIXING FAILURES ===
- KeyError: symbol not in binary. Use libc.symbols instead.
- SIGSEGV: wrong offset, missing pop_rdi, or stack alignment. Re-measure offset!
- struct.error: read fewer bytes or use .ljust(8, b'\\x00').
- BrokenPipe/clean exit: binary exited before receiving payload. Check IO prompt sync.
- EOFError: wrong offset or binary crashed. Measure again with different method.
- FIX only the specific problem, don't rewrite everything."""


# ---------------------------------------------------------------------------
# Web search for Decider
# ---------------------------------------------------------------------------

def _web_search(query: str) -> str:
    try:
        from retrieve.web_search import _create_client
        from retrieve.schemas import SearchQuery
        c = _create_client()
        if not c.available:
            return "(web search unavailable)"
        results = c.search(SearchQuery(query=query), max_results=3)
        return "\n".join(f"- {r.title}\n  {r.url}\n  {r.snippet[:200]}" for r in results)
    except Exception as e:
        return f"(search error: {e})"


# ---------------------------------------------------------------------------
# Auto-measurement — force-run critical tools when LLM skips them
# ---------------------------------------------------------------------------

def _auto_measure_critical_facts(
    evidence, fact_store: dict, challenge_type: str
) -> dict:
    """Force-run the most important measurements for the challenge type.

    Called before the first iteration to ensure the agent has baseline facts.
    """
    binary = evidence.binary.path
    measured = {}

    if challenge_type == "rop":
        # Stack offset (mandatory for any ROP)
        if "offsets.ret_offset_bytes" not in fact_store and "offset" not in fact_store:
            r = tool_stack_measure_ret_offset_gdb(binary)
            if r.measured_facts:
                off = r.measured_facts.get("offsets.ret_offset_bytes")
                if off:
                    measured["offset"] = off
                    fact_store["offset"] = off

        # ROP gadgets
        if not any(k.startswith("gadgets.") for k in fact_store):
            r = tool_rop_find_gadgets(binary)
            if r.measured_facts:
                fact_store.update(dict(r.measured_facts))

        # Key symbols
        r = tool_pwntools_symbols(binary)
        if r.measured_facts:
            fact_store.update(dict(r.measured_facts))

        # GOT entries
        for sym in ["write", "puts", "printf", "read"]:
            r = tool_pwntools_got(binary, symbol=sym)
            if r.measured_facts:
                fact_store.update(dict(r.measured_facts))

    elif challenge_type == "fmt":
        # Format string offset
        if "offsets.fmt_write_arg" not in fact_store and "offsets.fmt_offset_arg" not in fact_store:
            r = tool_fmt_measure_write_offset(binary)
            if r.measured_facts:
                fact_store.update(dict(r.measured_facts))
            else:
                r = tool_fmt_scan_stack(binary)
                if r.measured_facts:
                    fact_store.update(dict(r.measured_facts))
                else:
                    # Manual fallback: send AAAA%p.%p... and find 0x41414141
                    try:
                        manual = tool_run_binary_with_payload(
                            binary,
                            payload=b"AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p",
                            timeout_s=2.0,
                        )
                        if manual.measured_facts:
                            out = str(manual.measured_facts.get("probe_artifacts.binary_output", ""))
                            # Find offset where 0x41414141 appears
                            parts = out.replace(".", " ").replace("\n", " ").split()
                            for idx, part in enumerate(parts):
                                if "41414141" in part or "AAAA" in part:
                                    fact_store["offsets.fmt_write_arg"] = idx + 1
                                    fact_store["offsets.fmt_offset_arg"] = idx + 1
                                    measured["offsets.fmt_write_arg"] = idx + 1
                                    break
                    except Exception:
                        pass

        # GOT entries for key functions
        for sym in ["printf", "puts", "exit", "__stack_chk_fail"]:
            r = tool_pwntools_got(binary, symbol=sym)
            if r.measured_facts:
                fact_store.update(dict(r.measured_facts))

    return measured


# ---------------------------------------------------------------------------
# Agent Loop
# ---------------------------------------------------------------------------

def _parse_llm_json(raw: str) -> dict:
    """Robustly extract JSON from LLM response."""
    raw = raw.strip()
    # Try direct parse
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except Exception:
            pass
    # Try to find JSON block
    m = re.search(r'\{[^{}]*"strategy_summary"[^{}]*\}', raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    # Try any JSON object
    m = re.search(r'\{.*\}', raw, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group(0))
            if "strategy_summary" in obj or "measurements" in obj:
                return obj
        except Exception:
            pass
    return {}


def run_agent_loop(
    evidence,
    problem_text: str,
    run_dir: Path,
    max_iters: int = 6,
    strategy_context: str = "",
) -> Dict[str, Any]:
    challenge_type = evidence.challenge_type or ""
    fact_store: Dict[str, Any] = {}
    history: List[Dict] = []
    success = False
    epath = run_dir / "candidate_exploit.py"
    binary_abs = evidence.binary.path

    from automation.llm_client import chat_complete_detailed

    for iteration in range(1, max_iters + 1):
        # ── Pre-measurement gate (iteration 1 only) ──
        if iteration == 1 and not fact_store:
            _auto_measure_critical_facts(evidence, fact_store, challenge_type)
            if fact_store:
                auto_keys = list(fact_store.keys())
                (run_dir / "auto_measurements.json").write_text(
                    json.dumps({"auto_measured": auto_keys}, ensure_ascii=False, indent=2))

        ev_text = evidence_to_text(evidence, fact_store)
        ctx = "## Iteration {}/{}\n## Problem\n{}\n\n## Evidence\n{}".format(
            iteration, max_iters, problem_text, ev_text)

        # ── STEP 1: Planner ──
        meas_hint = ""
        if not fact_store:
            meas_hint = (
                "\nWARNING: fact_store is EMPTY. You MUST request measurements. "
                "For {}: use {}.".format(
                    challenge_type,
                    "measure_offset, find_gadgets" if challenge_type == "rop" else "measure_fmt_offset, get_got"
                )
            )
        strategy_prompt = ctx + """
You are the PLANNING phase. Propose a strategy and request measurements.
Respond with JSON:
{
  "strategy_summary": "...",
  "measurements": [
    {"name": "measure_offset", "args": {"binary_path": "<<BINARY>>"}},
    {"name": "find_gadgets", "args": {"binary_path": "<<BINARY>>"}},
    {"name": "get_got", "args": {"binary_path": "<<BINARY>>", "symbol": "puts"}}
  ]
}
Available tools: measure_offset, find_gadgets, measure_fmt_offset, scan_fmt_stack, get_got, get_symbols, disassemble
Use <<BINARY>> as the binary_path placeholder — it will be replaced automatically.
""" + meas_hint
        # Replace placeholder with actual path
        strategy_prompt = strategy_prompt.replace("<<BINARY>>", binary_abs)

        try:
            res_s = chat_complete_detailed(strategy_prompt, AGENT_SYSTEM_PROMPT, temperature=0.1)
            strategy_text = res_s.raw_content
        except Exception as exc:
            strategy_text = json.dumps({"strategy_summary": "LLM call failed: {}".format(exc), "measurements": []})

        planner_fb = {"iteration": iteration, "strategy_summary": "", "measurements": [], "notes": []}
        plan = _parse_llm_json(strategy_text)
        if plan:
            planner_fb["strategy_summary"] = str(plan.get("strategy_summary", ""))[:500]
            planner_fb["notes"] = ["agent_strategy_response"]
        (run_dir / "planner_feedback_iter{}.json".format(iteration)).write_text(
            json.dumps(planner_fb, ensure_ascii=False, indent=2))

        # ── STEP 2: Executor ──
        if plan.get("measurements"):
            for t in plan["measurements"]:
                name = t.get("name", "")
                args = t.get("args", {})
                fn_info = TOOLS.get(name)
                if fn_info:
                    fn = fn_info[1]
                    try:
                        kwargs = {}
                        for k, v in args.items():
                            if k != "binary_path":
                                kwargs[k] = v
                        result = fn(binary_abs, **kwargs)
                        if isinstance(result, str):
                            try:
                                result = json.loads(result)
                            except Exception:
                                pass
                        if isinstance(result, dict):
                            fact_store.update(result)
                    except Exception:
                        pass

        # ── STEP 2b: Gap check — if still no facts, force basic tools ──
        if iteration == 1 and not fact_store:
            _auto_measure_critical_facts(evidence, fact_store, challenge_type)

        # ── STEP 3: Write exploit ──
        facts_str = json.dumps(fact_store, ensure_ascii=False)
        code_prompt = (
            ctx
            + "\nYou are the EXPLOIT WRITING phase. Write a complete pwntools exploit.\n"
            + "Fact store (MEASURED values — USE THESE EXACTLY):\n"
            + facts_str
            + "\n\nRULES:\n"
            + "- Use the MEASURED offset/gadgets from fact_store — do NOT guess.\n"
            + "- If fact_store is empty, request measurements first.\n"
            + "- i386 ret2libc: padding + write@plt + vuln_func + 1 + write@got + 4, then padding + system + exit + binsh\n"
            + "- amd64 ret2libc: padding + pop_rdi_ret + puts@got + puts@plt + vuln_func, then padding + ret + pop_rdi_ret + binsh + system\n"
            + "- fmt: use measured fmt_offset. Output ONLY Python code, no markdown.\n"
        )
        try:
            res_e = chat_complete_detailed(code_prompt, AGENT_SYSTEM_PROMPT, temperature=0.1)
            exploit_code = res_e.raw_content
        except Exception:
            exploit_code = 'from pwn import *\nprint("[STAGE] exploit_start")\np = process(binary.path)\np.interactive()'
        save_exploit_code(str(epath), exploit_code)
        (run_dir / "candidate_exploit_iter{}.py".format(iteration)).write_text(
            epath.read_text() if epath.exists() else exploit_code)

        # ── STEP 4: Verify ──
        from automation.verify.verifier import verify_exploit
        v = verify_exploit(epath, run_dir)
        (run_dir / "verify_iter{}.txt".format(iteration)).write_text(v.to_json())

        if v.success:
            success = True
            history.append({
                "iteration": iteration,
                "planner_strategy": planner_fb.get("strategy_summary", ""),
                "verify": {"success": True, "exit_code": v.exit_code},
                "decider": {"failure": "", "next_action": "", "notes": ["success"]},
                "fact_store_size": len(fact_store),
            })
            break

        # ── STEP 5: Decider ──
        diag_text = verify_result_to_text({
            "success": v.success, "exit_code": v.exit_code,
            "stdout_tail": v.stdout_tail, "stderr_tail": v.stderr_tail,
        })
        key_diag = diag_text[-3000:]
        failed_code = epath.read_text()[:3000] if epath.exists() else ""

        # Build missing-measurement awareness
        missing_meas_hint = ""
        if not fact_store:
            missing_meas_hint = (
                "\n\n=== CRITICAL: fact_store is EMPTY ===\n"
                "The exploit failed because no measurements were taken. "
                "You MUST request measurements (measure_offset, etc.) "
                "BEFORE writing code. Use the JSON planning format."
            )
        elif challenge_type == "rop" and "offset" not in fact_store:
            missing_meas_hint = (
                "\n\n=== MISSING MEASUREMENT: offset ===\n"
                "The offset to return address has NOT been measured. "
                "Request measure_offset first."
            )

        # Auto-search for error patterns
        search_context = ""
        err_keywords = re.findall(
            r"(SIGSEGV|SIGABRT|KeyError|NameError|TypeError|struct\.error|"
            r"BrokenPipeError|EOFError|offset|alignment|canary|wrong address)",
            key_diag
        )
        if err_keywords:
            dq = "{} exploit fix pwntools".format(" ".join(err_keywords[:3]))
            try:
                sr = _web_search(dq)
                search_context = "\n\n=== WEB SEARCH (auto) ===\nQuery: {}\nResults:\n{}".format(
                    dq, sr[:2000])
            except Exception:
                pass

        decider_prompt = """Exploit FAILED.

=== RUNTIME ERROR ===
{RUNTIME_ERROR}
{WEB_SEARCH}
{MISSING_MEAS}

=== FAILED EXPLOIT CODE ===
```python
{FAILED_CODE}
```

=== INSTRUCTIONS ===
1. Check the WEB SEARCH and MISSING MEASUREMENT hints above.
2. If a measurement is missing, STOP — you MUST request it instead of guessing.
3. If offset is wrong: request measure_offset again.
4. Find the EXACT bug in the code. Fix ONLY that bug.
5. Output ONLY the corrected Python code."""
        decider_prompt = decider_prompt.replace("{RUNTIME_ERROR}", key_diag)
        decider_prompt = decider_prompt.replace("{WEB_SEARCH}", search_context)
        decider_prompt = decider_prompt.replace("{MISSING_MEAS}", missing_meas_hint)
        decider_prompt = decider_prompt.replace("{FAILED_CODE}", failed_code)
        try:
            res_f = chat_complete_detailed(decider_prompt, AGENT_SYSTEM_PROMPT, temperature=0.1)
            save_exploit_code(str(epath), res_f.raw_content)
        except Exception:
            pass

        v2 = verify_exploit(epath, run_dir)
        if v2.success:
            success = True

        history.append({
            "iteration": iteration,
            "planner_strategy": planner_fb.get("strategy_summary", ""),
            "plan_measurements": [],
            "verify": {
                "success": v2.success, "exit_code": v2.exit_code,
                "stdout_tail": v2.stdout_tail, "stderr_tail": v2.stderr_tail,
                "failure_signals": [],
            },
            "decider": {"failure": str(v2.stderr_tail or "")[:500], "next_action": "", "notes": []},
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

    ev = collect_evidence(
        problem_path=args.problem,
        binary_path=args.binary,
        challenge_type=args.challenge_type,
        repo_root=root,
    )

    # Binary runtime fix
    import shutil as _shutil
    bin_abs = str(root / args.binary)
    _ld = None
    for _cand in [f"{bin_abs}/../ld-linux.so.2", f"{bin_abs}/../ld-linux-x86-64.so.2"]:
        if Path(_cand).exists():
            _ld = _cand
            break
    if _ld and _shutil.which("patchelf"):
        _bk = bin_abs + ".orig"
        if not Path(_bk).exists():
            _shutil.copy2(bin_abs, _bk)
        import subprocess as _sp
        _sp.run(["patchelf", "--set-interpreter", _ld, bin_abs], capture_output=True, timeout=10)

    (rd / "evidence.json").write_text(ev.to_json())
    pt = problem_text_summary(str(root / args.problem))

    # ── RETRIEVE_STRATEGIES ──
    strategy_context = ""
    try:
        from retrieve.retrieve_main import run as retrieve_run
        sc_path = rd / "strategy_candidates.json"
        res = retrieve_run(
            evidence_path=str(rd / "evidence.json"),
            out_path=str(sc_path),
            top_k=5,
            use_llm=False,
        )
        if res.candidates:
            top = res.candidates[0]
            candidates_text = []
            for c in res.candidates[:3]:
                candidates_text.append(
                    f"  [{c.priority.upper()}] {c.id} (score={c.score:.2f}, technique={c.technique})\n"
                    f"    measurements: {', '.join(c.required_measurements)}\n"
                    f"    payload: {'; '.join(c.payload_shape)}"
                )
            strategy_context = (
                "\n\n=== STRATEGY CANDIDATES (from RETRIEVE_STRATEGIES) ===\n"
                "Use these as your exploitation guide. Follow the recommended technique.\n"
                + "\n".join(candidates_text) + "\n"
            )
    except Exception:
        pass

    rpt = run_agent_loop(ev, pt, rd, args.max_iters, strategy_context)

    status = "PASS" if rpt["success"] else "FAIL"
    print(f"[{status}] iteration={rpt['final_iteration']}")
    print(f"evidence={rd / 'evidence.json'}")
    print(f"report={rd / 'run_report.json'}")
    print(f"exploit={rd / 'candidate_exploit.py'}")


if __name__ == "__main__":
    main()
