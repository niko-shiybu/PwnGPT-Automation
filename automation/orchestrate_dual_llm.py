from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
import os
import re
from typing import Any, Dict, Optional

if __package__ is None or __package__ == "":
    repo_root_for_imports = Path(__file__).resolve().parents[1]
    if str(repo_root_for_imports) not in sys.path:
        sys.path.insert(0, str(repo_root_for_imports))

from automation import local_config
from automation.collect.evidence_collector import collect_evidence
from automation.decider.decider_agent import decide_next_step
from automation.exploit.guards import (
    enforce_absolute_binary_path,
    enforce_exploit_contract,
    strip_shell_check_logic,
)
from automation.executor.executor_agent import (
    apply_measured_facts_to_evidence,
    build_measure_actions_for_facts,
    build_probe_script_for_facts,
    extract_measured_facts_from_output,
)
from automation.logging_utils import append_run_log
from automation.tools.tool_runner import run_actions
from automation.planner.planner_agent import (
    fix_exploit_code_with_feedback,
    generate_exploit_with_plan,
    propose_strategy_and_requirements,
)
from automation.schemas import MeasurementRequest, VerifyResult
from automation.verify.verifier import verify_exploit


def _save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _syntax_check_script(script_path: Path, cwd: Path, python_exec: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [python_exec, "-m", "py_compile", str(script_path)],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        return False, f"syntax_check_exception:{exc}"
    if proc.returncode == 0:
        return True, ""
    details = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    return False, details[-2000:]


def _build_retry_hint(summary: str) -> Dict[str, Any]:
    if summary in {"failed_syntax_error", "failed_syntax_or_logic_error"}:
        return {"category": "exploit_syntax_error", "message": "Fix syntax and rerun."}
    if summary == "failed_sigsegv":
        return {"category": "offset_mismatch", "message": "Likely wrong offset/address."}
    if summary in {"failed_eof", "failed_no_shell_probe_marker", "failed_shell_not_alive"}:
        return {"category": "io_desync", "message": "Likely prompt sync mismatch."}
    if summary == "failed_hang_after_probe":
        return {"category": "shell_not_stable", "message": "Hang after probe, bound reads and exits."}
    return {"category": "probe_incomplete", "message": "Need more measurements and strategy adjustment."}


def _harden_exploit_code(
    code: str, evidence: Any, libc_path: str = "", problem_text: str = "",
    fact_store: dict = None,
) -> str:
    if fact_store is None:
        fact_store = {}
    """Apply deterministic fixes to LLM-generated exploit code.

    Fixes patterns that qwen-max repeatedly gets wrong despite hints:
    - BINARY_AS_LIBC: libc = ELF(binary_path) instead of ELF(libc_path)
    - Static binary: remove libc loading when binary has no dynamic section
    - Fake parameters: replace 0xdeadbeef/0xcafebabe with values from problem text
    - Wrong API: binary.symbols_map.plt['X'] instead of binary.plt['X']
    - Hallucinated remote(): using remote() for local challenges
    """
    binary_path = getattr(evidence.binary, "path", "")
    if not binary_path:
        return code

    if not libc_path:
        libc_path = (evidence.runtime or {}).get("libc_path", "")
    symbols_map = evidence.symbols_map or {}
    plt_entries = symbols_map.get("plt", {})
    bf = evidence.binary_features or {}
    is_static = (not plt_entries) and (not libc_path)

    # If dynamic binary but libc_path is empty, use arch-based default
    if not is_static and not libc_path:
        arch_bits = bf.get("arch_bits", 64)
        libc_path = "/lib/x86_64-linux-gnu/libc.so.6" if arch_bits == 64 else "/lib32/libc.so.6"

    # === Fix 1: Static binary — remove libc loading entirely ===
    if is_static:
        code = re.sub(
            r'^\s*libc\s*=\s*ELF\([^)]+\).*$',
            '# [FIXED] static binary — all symbols are in the binary itself, no libc needed',
            code, flags=re.MULTILINE,
        )
        code = re.sub(r'\blibc\.symbols\[', 'context.binary.symbols[', code)
        code = re.sub(r'\blibc\.search\(', 'context.binary.search(', code)
        code = re.sub(r"\blibc\.plt\[", "context.binary.plt[", code)
        code = re.sub(r"\blibc\.got\[", "context.binary.got[", code)
        # Also remove `from pwn import *` libc-only imports (just in case)
        code = re.sub(r'^\s*from pwnlib.*import.*\n', '', code, flags=re.MULTILINE)

    # === Fix 2: BINARY_AS_LIBC (dynamic binary) ===
    if libc_path and binary_path:
        bin_name = Path(binary_path).name
        # Pattern A: libc = ELF("/abs/path/to/binary")
        code = re.sub(
            r"(\blibc\s*=\s*ELF\()r?[\"']" + re.escape(binary_path) + r"[\"']\)",
            f'\\1"{libc_path}")',
            code,
        )
        # Pattern B: libc = ELF("./binary_name") or libc = ELF("binary_name")
        if re.search(r"libc\s*=\s*ELF\(r?[\"'][^\"']*" + re.escape(bin_name) + r"[\"']\)", code):
            code = re.sub(
                r"(\blibc\s*=\s*ELF\()r?[\"'][^\"']*" + re.escape(bin_name) + r"[\"']\)",
                f'\\1"{libc_path}")',
                code,
            )
        # Pattern C: libc = ELF(evidence.runtime.libc_path) — literal string, replace with actual
        code = re.sub(
            r"libc\s*=\s*ELF\(evidence\.runtime\.libc_path\)",
            f'libc = ELF("{libc_path}")  # FIXED: was literal string, now uses actual path',
            code,
        )
        # Pattern D: any libc = ELF() that still points to a path containing the binary name
        # (catch-all for unusual formats)
        remaining = re.findall(r"libc\s*=\s*ELF\([^)]+\)", code)
        for match in remaining:
            if bin_name in match and libc_path not in match:
                code = code.replace(match, f'libc = ELF("{libc_path}")  # FIXED: was binary path')

    # === Fix 3: binary.symbols_map.plt/got/funcs → binary.plt/got/symbols ===
    code = re.sub(r"\.symbols_map\.(plt|got)\[", r".\1[", code)
    code = re.sub(r"\.symbols_map\.(plt|got)\.", r".\1.", code)
    code = re.sub(r"\.symbols_map\.funcs", r".symbols", code)

    # === Fix 4: Hallucinated remote() → process() for local challenges ===
    code = re.sub(
        r"io\s*=\s*remote\([\"']\d+\.\d+\.\d+\.\d+[\"'],\s*\d+\)",
        f'io = process(["{binary_path}"])  # was remote(), fixed automatically',
        code,
    )

    # === Fix 5: replace hardcoded gadget addresses with measured values ===
    for key, value in fact_store.items():
        if not key.startswith("gadgets.") or not value:
            continue
        label = key.split(".", 1)[1]  # e.g., "pop_rdi_ret"
        measured_val = str(value)
        # Replace hardcoded gadget addresses that don't match measured value
        # Match both "pop_rdi_ret = 0xNNNN" and "pop_rdi = 0xNNNN"
        for var_name in {label, label.replace("_ret", ""), label.replace("_ret", "_ret")}:
            code = re.sub(
                rf"\b{re.escape(var_name)}\s*=\s*0x[0-9a-fA-F]+\b",
                f"{var_name} = {measured_val}  # FIXED: was hallucinated, now uses measured value",
                code,
            )

    # === Fix 6: fix function names that don't exist in evidence ===
    funcs_set = set((evidence.symbols_map or {}).get("funcs", {}).keys())
    plt_set = set((evidence.symbols_map or {}).get("plt", {}).keys())
    all_known = funcs_set | plt_set
    for m in re.finditer(r"binary\.symbols\['(\w+)'\]", code):
        sym = m.group(1)
        if sym not in all_known and sym != "main":
            # Try to find a replacement from evidence funcs (e.g. exec_the_string → call_me_with_two_args)
            for candidate in sorted(funcs_set):
                if "call_me" in candidate or "win" in candidate or "flag" in candidate or "exec" in candidate or "magic" in candidate:
                    code = code.replace(f"binary.symbols['{sym}']", f"binary.symbols['{candidate}']")
                    break

    # === Fix 6: binary.symbols['X'] → libc.symbols['X'] if X not in binary PLT ===
    if libc_path and plt_entries:
        for sym in ["system", "execve", "execvp", "execl", "popen"]:
            if sym not in plt_entries:
                code = re.sub(
                    rf"binary\.(?:symbols|plt)\[['\"]?\b{sym}\b['\"]?\]",
                    f'libc.symbols["{sym}"]  # FIXED: {sym} not in binary PLT',
                    code,
                )

    # === Fix 6: Replace fake placeholder parameters with real values from problem text ===
    if problem_text:
        # get_flag / call_me_with_two_args / exec_string patterns
        m = re.search(
            r'if\s*\(\s*\w+\s*==\s*(\d+)\s*&&\s*\w+\s*==\s*(\d+)\s*\)',
            problem_text,
        )
        if m:
            real_arg1, real_arg2 = m.group(1), m.group(2)
            for fake in ["0xdeadbeef", "0xcafebabe", "0xbadf00d", "0xc001d00d"]:
                code = re.sub(
                    r'\b' + re.escape(fake) + r'\b', real_arg1, code,
                )
            code = re.sub(
                r'\b0xcafebabe\b', real_arg2, code,
            )
            # Fix hex-for-decimal confusion: LLM writes 0x81453627 instead of 814536271
            # 814536271 in hex is 0x308F43CF, 425138641 in hex is 0x1956D9D1
            for dec_val in [real_arg1, real_arg2]:
                dec_str = str(dec_val)
                # Match 0x followed by dec digits (LLM confused decimal with hex)
                code = re.sub(
                    r'\b0x' + dec_str + r'\b', dec_str, code,
                )
                # Also match partial prefix: 0x81453627 when looking for 814536271
                for prefix_len in range(6, 9):
                    prefix = dec_str[:prefix_len]
                    if len(prefix) >= 6:
                        code = re.sub(
                            r'\b0x' + re.escape(prefix) + r'\w*\b',
                            dec_str + '  # FIXED: was hex, should be decimal',
                            code,
                        )

    return code


def _ensure_binary_runnable(binary_path: str) -> bool:
    """Fix binary with absolute NEEDED paths that reference non-existent directories.

    Common issue: binaries compiled on WSL have RUNPATH/NEEDED pointing to
    /mnt/d/project/... which doesn't exist on native Linux. Use patchelf
    to rewrite the interpreter and library paths to point to local copies.
    """
    import shutil
    binary_dir = os.path.dirname(binary_path)
    binary_name = os.path.basename(binary_path)

    # Find local ld-linux
    ld_path = None
    for candidate in [
        os.path.join(binary_dir, "ld-linux-x86-64.so.2"),
        os.path.join(binary_dir, "ld-linux.so.2"),
    ]:
        if os.path.exists(candidate):
            ld_path = candidate
            break
    if not ld_path:
        return False  # No local ld, can't fix

    # Find patchelf
    patchelf_bin = shutil.which("patchelf")
    if not patchelf_bin:
        for candidate in [
            ".venv/bin/patchelf",
        ]:
            candidate_abs = os.path.join(os.path.dirname(__file__), "..", candidate)
            if os.path.exists(candidate_abs):
                patchelf_bin = os.path.abspath(candidate_abs)
                break
    if not patchelf_bin or not os.path.exists(patchelf_bin):
        return False

    # Backup original
    backup = binary_path + ".orig"
    if not os.path.exists(backup):
        shutil.copy2(binary_path, backup)

    try:
        subprocess.run(
            [patchelf_bin, "--set-interpreter", ld_path, binary_path],
            capture_output=True, text=True, timeout=10,
            check=True,
        )
        # Fix absolute NEEDED paths
        readelf = subprocess.run(
            ["readelf", "-d", binary_path], capture_output=True, text=True, timeout=5,
        )
        for line in readelf.stdout.split("\n"):
            m = re.search(r"\(NEEDED\).*\[(.+\.so[^\]]*)\]", line)
            if m and m.group(1).startswith("/"):
                old_path = m.group(1)
                lib_name = os.path.basename(old_path)
                subprocess.run(
                    [patchelf_bin, "--replace-needed", old_path, lib_name, binary_path],
                    capture_output=True, text=True, timeout=5, check=True,
                )
        # Set rpath to binary directory
        subprocess.run(
            [patchelf_bin, "--set-rpath", binary_dir, binary_path],
            capture_output=True, text=True, timeout=5, check=True,
        )
        return True
    except Exception:
        # Restore backup on failure
        if os.path.exists(backup):
            shutil.copy2(backup, binary_path)
        return False


def _build_critical_fixes(
    notes: list[str], failure: str, next_action: str, fact_store: dict,
) -> list[str]:
    """Build concrete REPLACE instructions from fact_store values that the LLM hallucinated."""
    fixes: list[str] = []
    for key, value in fact_store.items():
        if value is None or not str(value):
            continue
        val_str = str(value)
        # Gadget addresses: measured but LLM used a different one
        if key.startswith("gadgets."):
            label = key.split(".", 1)[1]  # e.g. "pop_rdi_ret"
            # Find the hallucinated address from decider notes
            for note in notes:
                if label in note and "used=" in note:
                    m = re.search(r"used=(\S+)", note)
                    if m and m.group(1) != val_str:
                        fixes.append(
                            f"REPLACE {label} address: your code uses {m.group(1)}, "
                            f"the MEASURED value is {val_str}. Write `{label} = {val_str}`"
                        )
                        break
        # Libc path
        if key == "runtime.libc_path" or key.endswith(".libc_path"):
            fixes.append(f"Use libc path: {val_str} (NOT the binary path)")
        # Offset
        if key == "offsets.ret_offset_bytes":
            fixes.append(f"Use offset = {val_str} (measured), do NOT use pattern_len or guessed values")
    return fixes


def _parse_decider_hint(hint_msg: str) -> tuple:
    """Extract failure and next_action from decider hint text."""
    failure = ""
    next_action = ""
    # Pattern: "DECIDER_MANDATORY\nfailure:\n...\n\nnext_action:\n..."
    m = re.search(r"failure:\n(.+?)\n\nnext_action:\n(.+)", hint_msg, re.DOTALL)
    if m:
        failure = m.group(1).strip()
        next_action = m.group(2).strip()
    else:
        # Fallback: use the whole message
        failure = hint_msg
        next_action = hint_msg
    return failure, next_action


def _sanitize_case_id(case_id: str) -> str:
    s = (case_id or "").strip()
    if not s:
        return ""
    # Keep folder name stable and safe across shells/filesystems.
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s[:80]


def main() -> None:
    parser = argparse.ArgumentParser(description="Tri-LLM pwn orchestration (planner + executor + decider)")
    parser.add_argument("--problem", required=True, help="Problem file path relative to repo root")
    parser.add_argument("--binary", required=True, help="Binary path relative to repo root")
    parser.add_argument("--challenge-type", required=True, choices=["fmt", "int", "heap", "rop"])
    parser.add_argument("--repo-root", default=".", help="Repository root path")
    parser.add_argument("--max-iters", type=int, default=4)
    parser.add_argument("--probe-timeout", type=int, default=30)
    parser.add_argument("--max-syntax-fix-attempts", type=int, default=3)
    parser.add_argument(
        "--case-id",
        default="",
        help="Optional case identifier to embed into run folder name (e.g., fmt-2 or 03-rop-1).",
    )
    parser.add_argument(
        "--engine",
        choices=["dual", "openhands"],
        default="dual",
        help="Engine mode: dual (tri-LLM) or openhands (OpenHands SDK agent).",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    case_suffix = _sanitize_case_id(str(args.case_id))
    engine_tag = args.engine
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + engine_tag
    if case_suffix:
        run_id = f"{run_id}-{case_suffix}"
    run_dir = repo_root / "automation" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    run_log = run_dir / "run.log"

    def log_event(event: str, data: dict) -> None:
        append_run_log(run_log, event, data)

    if args.engine == "openhands":
        from automation.openhands_runner import run_openhands_agent, _load_problem_text

        evidence = collect_evidence(
            problem_path=args.problem,
            binary_path=args.binary,
            challenge_type=args.challenge_type,
            repo_root=repo_root,
        )
        binary_abs = str(repo_root / args.binary)
        _ensure_binary_runnable(binary_abs)
        (run_dir / "evidence.json").write_text(evidence.to_json())

        problem_text = _load_problem_text(str(repo_root / args.problem))
        report = run_openhands_agent(evidence, problem_text, run_dir, log_event)

        _save_json(run_dir / "run_report.json", report)
        status = "PASS" if report.get("success") else "FAIL"
        print(f"[{status}] iteration={report.get('final_iteration', 0)}")
        print(f"evidence={run_dir / 'evidence.json'}")
        print(f"report={run_dir / 'run_report.json'}")
        print(f"exploit={run_dir / 'candidate_exploit.py'}")
        return

    python_exec = (
        getattr(local_config, "AUTOMATION_PYTHON", "")
        or "python3"
    )

    evidence = collect_evidence(
        problem_path=args.problem,
        binary_path=args.binary,
        challenge_type=args.challenge_type,
        repo_root=repo_root,
    )
    # === Fix binary RUNPATH/NEEDED issues (e.g. WSL-compiled binaries) ===
    binary_abs = str(repo_root / args.binary)
    _ensure_binary_runnable(binary_abs)
    # Re-collect evidence after binary fix (libc_path may now be resolvable)
    if not evidence.runtime.get("libc_path"):
        evidence2 = collect_evidence(
            problem_path=args.problem,
            binary_path=args.binary,
            challenge_type=args.challenge_type,
            repo_root=repo_root,
        )
        if evidence2.runtime.get("libc_path"):
            evidence.runtime["libc_path"] = evidence2.runtime["libc_path"]
            evidence.runtime["libc_version"] = evidence2.runtime.get("libc_version", "")
    evidence_path = run_dir / "evidence.json"
    evidence_path.write_text(evidence.to_json(), encoding="utf-8")

    fact_store: Dict[str, Any] = {}
    retry_hint: Dict[str, Any] = {"category": "", "message": ""}
    last_verify: Optional[Dict[str, Any]] = None
    iteration_history = []
    planner_rounds = 0
    executor_rounds = 0
    planner_model = ""
    executor_model = ""
    decider_model = ""
    decider_rounds = 0
    decider_scores: list[int] = []
    decider_forced_measurements: list[dict[str, Any]] = []
    problem_text = Path(evidence.problem_path).read_text(encoding="utf-8", errors="ignore")[:12000]
    same_idea_fail_streak = 0
    last_strategy_fingerprint = ""
    last_executor_feedback: Dict[str, Any] = {}
    last_planner_feedback: Dict[str, Any] = {}
    # Circuit breaker: track consecutive failures per tool
    tool_failure_history: Dict[str, int] = {}
    # Carry previous iteration's code + static audit to the next exploit writer call
    previous_exploit_code = ""
    previous_static_audit: Optional[Dict[str, Any]] = None
    previous_decider_notes: list[str] = []
    previous_decider_failure = ""
    previous_decider_next_action = ""

    for iteration in range(1, args.max_iters + 1):
        planner_rounds += 1
        plan = propose_strategy_and_requirements(
            evidence,
            fact_store=fact_store,
            last_verify=last_verify,
            hint=retry_hint.get("message", ""),
            log_event=log_event,
            executor_feedback=last_executor_feedback,
        )
        last_planner_feedback = {
            "iteration": iteration,
            "strategy_summary": plan.strategy_summary,
            "measurements": [x.__dict__ for x in plan.measurements],
            "notes": list(plan.notes),
        }
        planner_feedback_path = run_dir / f"planner_feedback_iter{iteration}.json"
        _save_json(planner_feedback_path, last_planner_feedback)
        log_event("planner_feedback_saved", {"iteration": iteration, "path": str(planner_feedback_path)})
        if decider_forced_measurements:
            existing_descriptions = [x.description for x in plan.measurements]
            forced: list[MeasurementRequest] = []
            for item in decider_forced_measurements:
                desc = str(item.get("description", "")).strip()
                if desc and desc not in existing_descriptions:
                    forced.append(
                        MeasurementRequest(
                            id=int(item.get("id", len(forced) + 1)),
                            description=desc,
                            reason=str(item.get("reason", "decider_mandatory")),
                            priority=str(item.get("priority", "high")),
                        )
                    )
            plan.measurements = forced + plan.measurements
            log_event(
                "decider_mandatory_measurements_applied",
                {"iteration": iteration, "forced_measurements": decider_forced_measurements},
            )
        strategy_fingerprint = (plan.strategy_summary or "").strip().lower()[:400]

        if plan.measurements:
            # Prefer tool-based measurement; fall back to script-based probing.
            actions, measurement_requests, used_executor_model = build_measure_actions_for_facts(
                evidence, plan=plan, fact_store=fact_store, max_facts=1, log_event=log_event,
                tool_failure_history=tool_failure_history,
            )
            executor_model = executor_model or used_executor_model
            executor_rounds += 1

            measured: Dict[str, Any] = {}
            unresolved_facts = []
            notes = []
            measurement_task = (measurement_requests[0] if measurement_requests else {})
            measurement_id = int(measurement_task.get("id", 0) or 0)
            request_id = f"iter{iteration}-m{measurement_id}-{uuid.uuid4().hex[:8]}"
            task_dir = run_dir / "measurement_tasks" / request_id
            task_dir.mkdir(parents=True, exist_ok=True)

            if actions:
                for idx, action in enumerate(actions, 1):
                    action["request_id"] = request_id
                    action["action_id"] = f"{request_id}-a{idx}"
                tool_res = run_actions(actions, binary_path=evidence.binary.path)
                measured = tool_res.measured_facts
                unresolved_facts = tool_res.unresolved_facts
                notes = tool_res.notes

                # Circuit breaker: track tool failures
                for action in actions:
                    tool_name = str(action.get('tool', ''))
                    if not measured and unresolved_facts:
                        tool_failure_history[tool_name] = tool_failure_history.get(tool_name, 0) + 1
                        log_event(
                            'tool_failure_tracked',
                            {'tool': tool_name, 'consecutive_failures': tool_failure_history[tool_name]},
                        )
                    else:
                        # Reset failure count on success
                        tool_failure_history[tool_name] = 0
                (task_dir / "probe_output.log").write_text(
                    "TOOL_ACTIONS\n" + json.dumps({"actions": actions}, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                log_event(
                    "executor_tools_executed",
                    {
                        "iteration": iteration,
                        "request_id": request_id,
                        "measurement": measurement_task,
                        "actions": actions,
                        "measured_keys": sorted(measured.keys()),
                    },
                )
                last_executor_feedback = {
                    "iteration": iteration,
                    "request_id": request_id,
                    "task_context_dir": str(task_dir),
                    "mode": "tools",
                    "actions": actions,
                    "measurement": measurement_task,
                    "measured_facts": measured,
                    "unresolved_facts": unresolved_facts,
                    "notes": notes,
                    "action_results": tool_res.action_results or [],
                }
            else:
                script_code, measurement_requests, used_executor_model2 = build_probe_script_for_facts(
                    evidence,
                    plan=plan,
                    fact_store=fact_store,
                    max_facts=1,
                    log_event=log_event,
                )
                executor_model = executor_model or used_executor_model2
                probe_path = task_dir / "probe_script.py"
                probe_path.write_text(script_code, encoding="utf-8")
                proc = subprocess.run(
                    [python_exec, str(probe_path)],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    timeout=args.probe_timeout,
                    check=False,
                )
                probe_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
                (task_dir / "probe_output.log").write_text(probe_output, encoding="utf-8")
                parsed = extract_measured_facts_from_output(probe_output)
                measured = parsed.get("measured_facts", {}) or {}
                unresolved_facts = parsed.get("unresolved_facts", [])
                notes = parsed.get("notes", [])

                # Circuit breaker: track probe script failures
                probe_tool_name = 'probe_script'
                if not measured and unresolved_facts:
                    tool_failure_history[probe_tool_name] = tool_failure_history.get(probe_tool_name, 0) + 1
                    log_event(
                        'probe_failure_tracked',
                        {'consecutive_failures': tool_failure_history[probe_tool_name]},
                    )
                else:
                    tool_failure_history[probe_tool_name] = 0

                for item in unresolved_facts:
                    if isinstance(item, dict):
                        item.setdefault("request_id", request_id)
                last_executor_feedback = {
                    "iteration": iteration,
                    "request_id": request_id,
                    "task_context_dir": str(task_dir),
                    "mode": "script",
                    "measurement": (measurement_requests[0] if measurement_requests else {}),
                    "measured_facts": measured,
                    "unresolved_facts": unresolved_facts,
                    "notes": notes,
                    "probe_output_full": probe_output,
                    "action_results": [
                        {
                            "request_id": request_id,
                            "action_id": f"{request_id}-script-1",
                            "tool": "probe_script",
                            "status": "ok" if not unresolved_facts else "partial",
                            "measured_keys": sorted(measured.keys()),
                            "unresolved_count": len(unresolved_facts),
                        }
                    ],
                }

            for k, v in measured.items():
                fact_store[k] = v
            evidence = apply_measured_facts_to_evidence(evidence, measured)
            for note in notes:
                evidence.notes.append(f"executor:{note}")
            log_event(
                "fact_store_updated",
                {
                    "iteration": iteration,
                    "request_id": request_id,
                    "measurement": measurement_task,
                    "measured_keys": sorted(measured.keys()),
                    "unresolved_facts": unresolved_facts,
                },
            )
            evidence_path.write_text(evidence.to_json(), encoding="utf-8")
            executor_feedback_path = task_dir / "executor_feedback.json"
            _save_json(executor_feedback_path, last_executor_feedback)
            log_event("executor_feedback_saved", {"iteration": iteration, "path": str(executor_feedback_path)})

        candidate_path = run_dir / "candidate_exploit.py"
        syntax_ok = False
        syntax_err = ""
        syntax_fix_attempt = 0

        # P1: Skip exploit generation when all measurements failed (no data to work with)
        # measured is defined inside the if plan.measurements block
        total_measured = len(measured) if ('measured' in dir() and isinstance(measured, dict)) else 0
        unresolved_executor_items = list((last_executor_feedback.get("unresolved_facts", []) or []))
        if not total_measured and unresolved_executor_items:
            log_event(
                'skip_exploit_generation_no_measurements',
                {'iteration': iteration, 'unresolved_count': len(unresolved_executor_items)},
            )
            # Synthesize a verify failure so decider can give better guidance
            verify = VerifyResult(
                success=False,
                exit_code=3,
                failure_signals=["all_measurements_failed"],
                stdout_tail="",
                stderr_tail=json.dumps(
                    [{'key': str(i.get('key', '')), 'reason': str(i.get('reason', ''))[:200]}
                     for i in unresolved_executor_items if isinstance(i, dict)],
                    ensure_ascii=False,
                )[:2000],
                stdout_full="",
                stderr_full=json.dumps(last_executor_feedback, ensure_ascii=False),
                summary="failed_all_measurements_empty",
            )
            # Build a better retry hint that forces measurement change
            blocked = [t for t, c in tool_failure_history.items() if c >= 2]
            retry_hint = {
                'category': 'all_measurements_failed',
                'message': (
                    'DECIDER_MANDATORY\n'
                    f'ALL measurement tools failed to produce data. Blocked tools: {blocked}. '
                    'MUST try a DIFFERENT measurement approach. '
                    'For fmt challenges: try fmt_scan_stack or run_binary_with_payload to manually scan offsets. '
                    'For stack challenges: try disassemble(main) or run_binary_with_payload with a cyclic pattern.'
                ),
            }
        else:
            unresolved_executor_items = list((last_executor_feedback.get("unresolved_facts", []) or []))
        if unresolved_executor_items:
            unresolved_summary = []
            for item in unresolved_executor_items:
                if not isinstance(item, dict):
                    continue
                unresolved_summary.append(
                    {
                        "request_id": str(item.get("request_id", last_executor_feedback.get("request_id", ""))),
                        "key": str(item.get("key", "")),
                        "reason": str(item.get("reason", ""))[:300],
                    }
                )
            verify = VerifyResult(
                success=False,
                exit_code=2,
                failure_signals=["executor_measurement_error"],
                stdout_tail="",
                stderr_tail=json.dumps(unresolved_summary, ensure_ascii=False)[:2000],
                stdout_full="",
                stderr_full=json.dumps(last_executor_feedback, ensure_ascii=False),
                summary="failed_executor_measurement_error",
            )
            log_event(
                "executor_measurement_blocking",
                {"iteration": iteration, "request_id": last_executor_feedback.get("request_id", ""), "unresolved_facts": unresolved_summary},
            )
        else:
            while syntax_fix_attempt < max(1, args.max_syntax_fix_attempts):
                syntax_fix_attempt += 1
                syntax_hint = retry_hint.get("message", "")
                if syntax_err:
                    syntax_hint = (
                        f"{syntax_hint}\n"
                        f"Previous candidate had Python syntax error. Fix it strictly.\n"
                        f"Syntax error tail:\n{syntax_err[-800:]}"
                    ).strip()

                # Decide which function to use: fix mode (retry) or generate mode (first attempt)
                retry_msg = retry_hint.get("message", "")
                # Check if previous decider flagged a strategy mismatch
                has_strategy_mismatch = any(
                    "strategy=MISMATCH" in n or "strategy=PARTIAL" in n
                    for n in previous_decider_notes
                )
                if previous_exploit_code and "DECIDER_MANDATORY" in retry_msg:
                    if has_strategy_mismatch:
                        # Strategy error: use full regenerate with forced strategy change hint
                        strategy_hint = (
                            "DECIDER_MANDATORY — STRATEGY CHANGE REQUIRED\n"
                            f"The previous strategy is WRONG. Decider diagnosis:\n"
                            f"failure: {previous_decider_failure}\n\n"
                            f"next_action: {previous_decider_next_action}\n\n"
                            f"notes: {'; '.join(previous_decider_notes)}\n\n"
                            "CRITICAL: You MUST use a DIFFERENT exploitation strategy. "
                            "Do NOT repeat the same approach as the previous code."
                        )
                        exploit_code, used_planner_model = generate_exploit_with_plan(
                            evidence,
                            plan=plan,
                            fact_store=fact_store,
                            hint=strategy_hint,
                            log_event=log_event,
                        )
                        log_event("strategy_force_regenerate", {"iteration": iteration})
                    else:
                        # Fix mode: pass code + decider diagnosis + notes + concrete fact values
                        _critical_fixes = _build_critical_fixes(
                            previous_decider_notes, previous_decider_failure,
                            previous_decider_next_action, fact_store,
                        )
                        exploit_code, used_planner_model = fix_exploit_code_with_feedback(
                            previous_exploit_code,
                            decider_failure=previous_decider_failure,
                            decider_next_action=previous_decider_next_action,
                            decider_notes=previous_decider_notes,
                            critical_fixes=_critical_fixes,
                            log_event=log_event,
                        )
                        log_event("exploit_fixer_used", {"iteration": iteration, "critical_fixes": len(_critical_fixes)})
                else:
                    # First attempt: full generation with evidence + plan + facts
                    exploit_code, used_planner_model = generate_exploit_with_plan(
                        evidence,
                        plan=plan,
                        fact_store=fact_store,
                        hint=syntax_hint,
                        log_event=log_event,
                    )
                planner_model = planner_model or used_planner_model
                if used_planner_model == "fallback":
                    last_planner_feedback.setdefault("errors", []).append("exploit_generation_fallback")
                exploit_code = enforce_absolute_binary_path(exploit_code, evidence.binary.path)
                exploit_code, _ = enforce_exploit_contract(exploit_code, evidence)
                exploit_code, _ = strip_shell_check_logic(exploit_code)
                # Deterministic hardening: fix BINARY_AS_LIBC, wrong API calls, etc.
                exploit_code = _harden_exploit_code(exploit_code, evidence, problem_text=problem_text, fact_store=fact_store)
                candidate_path.write_text(exploit_code, encoding="utf-8")

                syntax_ok, syntax_err = _syntax_check_script(candidate_path, repo_root, python_exec)
                log_event(
                    "candidate_syntax_check",
                    {
                        "iteration": iteration,
                        "attempt": syntax_fix_attempt,
                        "ok": syntax_ok,
                        "error_tail": "" if syntax_ok else syntax_err[-1000:],
                    },
                )
                if syntax_ok:
                    break

            if not syntax_ok:
                last_planner_feedback.setdefault("errors", []).append(syntax_err)
                verify = VerifyResult(
                    success=False,
                    exit_code=1,
                    failure_signals=["syntax_or_logic_error"],
                    stdout_tail="",
                    stderr_tail=syntax_err,
                    stdout_full="",
                    stderr_full=syntax_err,
                    summary="failed_syntax_or_logic_error",
                )
            else:
                verify = verify_exploit(candidate_path, repo_root, python_exec=python_exec, log_event=log_event)
        verify_raw_path = run_dir / f"verify_output_iter{iteration}.log"
        verify_raw_path.write_text(
            "=== STDOUT ===\n"
            + (verify.stdout_full or "")
            + "\n\n=== STDERR ===\n"
            + (verify.stderr_full or ""),
            encoding="utf-8",
        )
        log_event("verify_raw_output_saved", {"iteration": iteration, "path": str(verify_raw_path)})
        if verify.forensics_full:
            forensics_path = run_dir / f"forensics_iter{iteration}.log"
            forensics_path.write_text(verify.forensics_full, encoding="utf-8")
            log_event("verify_forensics_saved", {"iteration": iteration, "path": str(forensics_path)})

        last_verify = json.loads(verify.to_json())
        decider_verify_payload = {
            "success": bool(last_verify.get("success", False)),
            "stdout_full": str(last_verify.get("stdout_full", "")),
            "stderr_full": str(last_verify.get("stderr_full", "")),
            "forensics_full": str(last_verify.get("forensics_full", "")),
        }
        base_retry_hint = _build_retry_hint(verify.summary)
        if verify.success:
            retry_hint = {"category": "", "message": ""}
            decision_payload = {
                "failure": "",
                "value_score": 100,
                "next_action": "继续当前路线：验证已成功。",
                "missing_measurements": [],
                "notes": ["auto_success"],
            }
            same_idea_fail_streak = 0
        else:
            if strategy_fingerprint and strategy_fingerprint == last_strategy_fingerprint:
                same_idea_fail_streak += 1
            else:
                same_idea_fail_streak = 1
            last_strategy_fingerprint = strategy_fingerprint
            decider_rounds += 1
            force_new_idea = same_idea_fail_streak >= 3
            augmented_retry_hint = dict(base_retry_hint)
            augmented_retry_hint["same_idea_fail_streak"] = same_idea_fail_streak
            augmented_retry_hint["force_new_idea"] = force_new_idea

            # --- STATIC AUDIT (disabled — false positives outweighed benefits) ---
            static_audit_payload = None

            decision, used_decider_model = decide_next_step(
                evidence,
                plan_measurements=[x.__dict__ for x in plan.measurements],
                fact_store=fact_store,
                last_verify=decider_verify_payload,
                retry_hint=augmented_retry_hint,
                executor_feedback=last_executor_feedback,
                planner_feedback=last_planner_feedback,
                problem_text=problem_text,
                candidate_code=candidate_path.read_text(encoding="utf-8", errors="ignore")
                if candidate_path.exists()
                else "",
                tool_failure_history=tool_failure_history,
                log_event=log_event,
                static_audit=static_audit_payload,
            )
            decider_model = decider_model or used_decider_model
            decider_scores.append(int(decision.value_score))
            decider_forced_measurements = [x.__dict__ for x in decision.missing_measurements]
            if force_new_idea:
                decision.next_action = (
                    "HARD RULE TRIGGERED: same idea failed 3 times. "
                    "MUST switch to a materially different exploitation approach now."
                    + ("\nDecider suggested new approach:\n" + decision.next_action if decision.next_action else "")
                )
            planner_hint = (
                "DECIDER_MANDATORY\n"
                f"failure:\n{decision.failure}\n\n"
                f"next_action:\n{decision.next_action}\n"
            ).strip()
            # === Augment hint with concrete code fix for common patterns ===
            binary_path = evidence.binary.path
            libc_path = evidence.runtime.get("libc_path", "")
            if libc_path and binary_path:
                failure_lower = decision.failure.lower()
                if "binary_as_libc" in failure_lower or "错误的 libc 路径" in decision.failure or "加载了二进制" in decision.failure:
                    planner_hint += (
                        "\n\nCODE_FIX (apply this exact change):\n"
                        f"  FIND:    libc = ELF(\"{binary_path}\")\n"
                        f"  REPLACE: libc = ELF(\"{libc_path}\")\n"
                    )
                if "binary_as_libc" in failure_lower or "libc" in failure_lower:
                    if "remote(" in decision.failure or "127.0.0.1" in decision.failure:
                        planner_hint += (
                            "\nCODE_FIX: Replace remote(\"127.0.0.1\", ...) with process(binary.path)"
                        )

            # === Inject measured fact_store values into next_action for FACT_MISMATCH ===
            _fact_injections: list[str] = []
            for note in (decision.notes or []):
                if "[FACT_MISMATCH]" not in note:
                    continue
                # Extract potential key names from the note
                for _candidate_key in list(fact_store.keys()):
                    _key_suffix = _candidate_key.split(".", 1)[-1] if "." in _candidate_key else _candidate_key
                    if _key_suffix in note or _candidate_key in note:
                        _val = fact_store[_candidate_key]
                        if _val is not None and str(_val):
                            _fact_injections.append(
                                f"MEASURED VALUE for {_candidate_key} = {_val}\n"
                                f"  → You MUST use this exact value. Do NOT fabricate a different address."
                            )
                            break
            # Also inject gadget values if code hallucinated a different pop_rdi
            if "pop_rdi" in decision.failure.lower() or "gadget" in decision.failure.lower():
                for _gk in sorted(fact_store.keys()):
                    if _gk.startswith("gadgets.") and _gk not in [f.split(" = ")[0].split(" for ")[-1] for f in _fact_injections]:
                        _val = fact_store[_gk]
                        if _val is not None and str(_val):
                            _fact_injections.append(
                                f"MEASURED VALUE for {_gk} = {_val}\n"
                                f"  → Use this exact address in your code."
                            )
            if _fact_injections:
                planner_hint += "\n\n=== MEASURED FACTS FROM EXECUTOR (fact_store) ===\n" + "\n".join(_fact_injections)

            retry_hint = {
                "category": "decider",
                "message": planner_hint,
            }
            # Save for next iteration's exploit writer
            if candidate_path.exists():
                previous_exploit_code = candidate_path.read_text(encoding="utf-8", errors="ignore")
            previous_static_audit = static_audit_payload
            previous_decider_notes = list(decision.notes or [])
            previous_decider_failure = str(decision.failure or "")
            previous_decider_next_action = str(decision.next_action or "")
            decision_payload = {
                "value_score": decision.value_score,
                "failure": decision.failure,
                "next_action": decision.next_action,
                "missing_measurements": [x.__dict__ for x in decision.missing_measurements],
                "mandatory_enforced": True,
                "same_idea_fail_streak": same_idea_fail_streak,
                "notes": decision.notes,
            }

        iter_report = {
            "iteration": iteration,
            "planner_strategy": plan.strategy_summary,
            "plan_measurements": [x.__dict__ for x in plan.measurements],
            "verify": last_verify,
            "decider": decision_payload,
            "retry_hint": retry_hint,
            "fact_store_size": len(fact_store),
        }
        iteration_history.append(iter_report)
        log_event("iteration_report", iter_report)
        if verify.success:
            break

    final_success = bool(iteration_history and iteration_history[-1].get("verify", {}).get("success"))
    report = {
        "run_id": run_id,
        "pipeline": "tri_llm",
        "challenge_type": args.challenge_type,
        "problem": args.problem,
        "binary": args.binary,
        "success": final_success,
        "final_iteration": len(iteration_history),
        "model_roles": {
            "planner_model": planner_model,
            "executor_model": executor_model,
            "decider_model": decider_model,
        },
        "metrics": {
            "planner_to_executor_rounds": {"planner_rounds": planner_rounds, "executor_rounds": executor_rounds},
            "decider_rounds": decider_rounds,
            "avg_value_score": round(sum(decider_scores) / max(1, len(decider_scores)), 2),
            "fact_coverage_ratio": round(len(fact_store) / max(1, len(fact_store) + 1), 3),
            "final_failure_class": "" if final_success else retry_hint.get("category", ""),
        },
        "fact_store": fact_store,
        "iterations": iteration_history,
    }
    report_path = run_dir / "run_report.json"
    _save_json(report_path, report)

    if final_success:
        print(f"[PASS] iteration={len(iteration_history)}")
    else:
        print("[FAIL] max iterations reached")
    print(f"evidence={evidence_path}")
    print(f"report={report_path}")
    print(f"exploit={run_dir / 'candidate_exploit.py'}")


if __name__ == "__main__":
    main()

