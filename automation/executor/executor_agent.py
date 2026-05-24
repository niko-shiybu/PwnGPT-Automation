from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from automation.llm_client import LLMClientError, ROLE_EXECUTOR, chat_complete_detailed
from automation.schemas import Evidence, MeasurementRequest, PlannerPlan

EXECUTOR_TOOL_SYSTEM_PROMPT = """You are the executor LLM for pwn measurement.
You DO NOT write probe scripts in this mode.
Instead you output a JSON tool-action plan for the orchestrator to execute.

Output strict JSON only:
{
  "actions": [
    {"tool":"fmt_measure_s_offset", "args":{"min_idx":1,"max_idx":40,"repeats":2}},
    {"tool":"fmt_measure_p_offset", "args":{"min_idx":1,"max_idx":40,"repeats":2}},
    {"tool":"pwntools_got", "args":{"symbol":"printf"}}
  ]
}

Rules:
- Use only the tools listed below.
- Requested work is expressed as numbered natural-language measurements, not internal field names.
- Choose the simplest tools that can satisfy the natural-language measurement descriptions.
- Execute exactly ONE measurement task per request (single-task boundary).
- Return exactly ONE action whenever possible.
- Do NOT request gdb unless absolutely needed.

Available tools:
- run_command(command, timeout_s, output_key) -> run shell command and capture structured result.
- disassemble(function) -> collect function disassembly text.
- decompile(function) -> collect function pseudo-source text (best-effort fallback).
- create_file(path, content) -> create helper scripts/files for measurement tasks.
"""

EXECUTOR_SYSTEM_PROMPT = """You are the executor LLM for pwn measurement.
Write a Python3 probe script to satisfy numbered natural-language measurements.
Rules:
1) Prefer pwntools when available.
2) Use bounded timeouts and no infinite loops.
3) Path rule (STRICT): NEVER use relative paths like ./fmt2 or ../bin/chal.
   You MUST use the absolute binary path from evidence.binary.path.
   - Good: process("/abs/path/to/bin"), ELF("/abs/path/to/bin")
   - Bad: process("./fmt2"), ELF("./fmt2")
4) `contextlib.timeout` is forbidden.
   - Do NOT write `from contextlib import timeout`.
   - If timeout context is needed, implement your own helper.
5) Emit strict markers:
PROBE_RESULT_JSON_START
<one line JSON>
PROBE_RESULT_JSON_END
6) JSON schema:
{
  "measured_facts": {"offsets.fmt_offset_arg": 9, "symbols.win":"0x4011d6"},
  "unresolved_facts": [{"key":"...", "reason":"timeout|not_found|crash"}],
  "notes": ["..."]
}
7) You MUST include `import json`.
8) You MUST print markers as STRING LITERALS exactly:
   print("PROBE_RESULT_JSON_START")
   print(json.dumps(result, ensure_ascii=False))
   print("PROBE_RESULT_JSON_END")
9) If any exception happens, you MUST still print valid JSON with unresolved_facts.
10) Never output marker tokens as Python identifiers (e.g. bare PROBE_RESULT_JSON_START is forbidden).
11) Output ONLY Python code.
"""

ALLOWED_TOOLS_BY_CHALLENGE = {
    "fmt": {"fmt_measure_write_offset", "fmt_measure_s_offset", "fmt_measure_p_offset", "fmt_scan_stack", "pwntools_got", "pwntools_symbols", "run_binary_with_payload", "run_command", "disassemble", "decompile", "create_file"},
    "int": {"stack_measure_ret_offset_gdb", "int_boundary_sweep", "pwntools_symbols", "run_binary_with_payload", "run_command", "disassemble", "decompile", "create_file"},
    "rop": {"stack_measure_ret_offset_gdb", "pwntools_got", "pwntools_symbols", "run_binary_with_payload", "run_command", "disassemble", "decompile", "create_file"},
    "heap": {"heap_ltrace_malloc_free", "pwntools_symbols", "run_binary_with_payload", "run_command", "disassemble", "decompile", "create_file"},
}

# Fallback chain: when primary tool fails, try next tool for the same measurement
MEASUREMENT_FALLBACK_CHAIN: Dict[str, List[str]] = {
    "fmt": ["fmt_measure_write_offset", "fmt_measure_s_offset", "fmt_measure_p_offset", "fmt_scan_stack", "run_binary_with_payload"],
    "int": ["stack_measure_ret_offset_gdb", "disassemble", "run_binary_with_payload"],
    "rop": ["stack_measure_ret_offset_gdb", "disassemble", "run_binary_with_payload"],
    "heap": ["heap_ltrace_malloc_free", "run_binary_with_payload"],
}

# Maximum consecutive failures for the same tool before forcing fallback
MAX_CONSECUTIVE_TOOL_FAILURES = 2


def _infer_internal_keys(challenge_type: str, description: str) -> List[str]:
    text = (description or "").lower()
    keys: List[str] = []
    if challenge_type == "fmt":
        if ("参数位置" in description or "offset" in text or "位置" in description) and ("写" in description or "fmtstr" in text or "%n" in text):
            keys.extend(["offsets.fmt_write_arg", "offsets.fmt_offset_arg"])
        if "目标地址" in description or ("x" in text and "地址" in description):
            keys.append("symbols.x")
        if "提示" in description or "交互" in description or "同步" in description:
            keys.extend(["io.prompts", "interaction_model.prompt_sequence"])
        if "printf" in text and "got" in text:
            keys.append("offsets.printf_got")
        if ("%s" in text) or ("字符串参数位置" in description):
            keys.append("offsets.fmt_arg_s")
        if ("%p" in text) or ("指针参数位置" in description):
            keys.append("offsets.fmt_arg_p")
    elif challenge_type in {"int", "rop"}:
        if "返回地址" in description or "偏移" in description:
            keys.append("offsets.ret_offset_bytes")
        if "位数" in description or "指针宽度" in description or "体系结构" in description:
            keys.append("constraints.pointer_width")
        if "崩溃" in description or "证据" in description:
            keys.append("probe_artifacts.crash_offset_proof")
        if challenge_type == "rop" and ("gadget" in text or "rop" in text or "原语" in description):
            keys.append("gadgets.pop_rdi_ret")
    elif challenge_type == "heap":
        if "菜单" in description or "交互顺序" in description:
            keys.append("constraints.heap_menu_model")
        if "漏洞原语" in description or "原语" in description:
            keys.append("constraints.heap_primitive")
        if "轨迹" in description or "分配" in description or "释放" in description:
            keys.append("probe_artifacts.heap_trace_raw")
    return list(dict.fromkeys(keys))


def _has_internal_key(evidence: Evidence, fact_store: Dict[str, Any], key: str) -> bool:
    if key in fact_store:
        return True
    if key.startswith("offsets."):
        return key.split(".", 1)[1] in evidence.offsets
    if key.startswith("symbols."):
        return key.split(".", 1)[1] in evidence.symbols
    if key.startswith("constraints."):
        return key.split(".", 1)[1] in evidence.constraints
    if key.startswith("probe_artifacts."):
        return key.split(".", 1)[1] in evidence.probe_artifacts
    if key.startswith("interaction_model."):
        return key.split(".", 1)[1] in evidence.interaction_model
    if key == "io.prompts":
        return bool(evidence.io_prompts)
    return False


def _collect_needed_measurements(plan: PlannerPlan, evidence: Evidence, fact_store: Dict[str, Any], max_facts: int) -> List[MeasurementRequest]:
    needed: List[MeasurementRequest] = []
    for item in plan.measurements:
        internal_keys = _infer_internal_keys(evidence.challenge_type, item.description)
        if internal_keys and all(_has_internal_key(evidence, fact_store, key) for key in internal_keys):
            continue
        needed.append(item)
        if len(needed) >= max_facts:
            break
    return needed


def _deterministic_action_for_measurement(challenge_type: str, measurement: MeasurementRequest, binary_path: str, failed_tools: Optional[List[str]] = None) -> Dict[str, Any]:
    failed = set(failed_tools or [])
    internal_keys = _infer_internal_keys(challenge_type, measurement.description)
    if any(k in {"offsets.fmt_write_arg", "offsets.fmt_offset_arg"} for k in internal_keys):
        if "fmt_measure_write_offset" not in failed:
            return {"tool": "fmt_measure_write_offset", "args": {}}
        if "fmt_scan_stack" not in failed:
            return {"tool": "fmt_scan_stack", "args": {"min_idx": 1, "max_idx": 20}}
        return {"tool": "run_binary_with_payload", "args": {"payload": "AAAA%1$p.%2$p.%3$p.%4$p.%5$p.%6$p.%7$p.%8$p"}}
    if "offsets.printf_got" in internal_keys or "symbols." in str(measurement.description).lower() or "目标地址" in measurement.description:
        if "pwntools_symbols" not in failed:
            return {"tool": "pwntools_symbols", "args": {}}
        return {"tool": "pwntools_got", "args": {"symbol": "printf"}}
    if any(k.startswith("gadgets.") for k in internal_keys):
        return {"tool": "rop_find_gadgets", "args": {}}
    if "offsets.ret_offset_bytes" in internal_keys:
        if "stack_measure_ret_offset_gdb" not in failed:
            return {"tool": "stack_measure_ret_offset_gdb", "args": {"pattern_len": 512}}
        return {"tool": "disassemble", "args": {"function": "main"}}
    if "probe_artifacts.heap_trace_raw" in internal_keys:
        return {"tool": "heap_ltrace_malloc_free", "args": {}}
    if "symbols.x" in internal_keys or "全局变量" in measurement.description:
        return {"tool": "pwntools_symbols", "args": {"names": ["x"]}}
    # Default: try to disassemble main for analysis
    return {
        "tool": "disassemble",
        "args": {
            "function": "main",
        },
    }


def _sanitize_probe_script(code: str, binary_path: str) -> tuple[str, List[str]]:
    """
    Best-effort protocol repair to guarantee JSON marker output shape.
    """
    out = code
    fixes: List[str] = []

    # Ensure json import exists.
    if "import json" not in out:
        lines = out.splitlines()
        insert_at = 0
        for idx, line in enumerate(lines):
            if line.startswith("from __future__ import "):
                insert_at = idx + 1
                break
        lines.insert(insert_at, "import json")
        out = "\n".join(lines) + ("\n" if out.endswith("\n") else "")
        fixes.append("added_import_json")

    # Forbid `from contextlib import timeout`; inject safe local timeout helper.
    contextlib_timeout_pat = r"(?m)^\s*from\s+contextlib\s+import\s+timeout\s*$"
    out, n_ctx = re.subn(contextlib_timeout_pat, "", out)
    if n_ctx:
        fixes.append(f"removed_contextlib_timeout_import:{n_ctx}")
        timeout_helper = """
from contextlib import contextmanager

@contextmanager
def timeout(*args, **kwargs):
    yield
"""
        # Insert helper after import block.
        lines = out.splitlines()
        insert_at = 0
        for idx, line in enumerate(lines):
            if line.startswith("import ") or line.startswith("from "):
                insert_at = idx + 1
        lines.insert(insert_at, timeout_helper.rstrip("\n"))
        out = "\n".join(lines) + ("\n" if out.endswith("\n") else "")
        fixes.append("inserted_local_timeout_helper")

    # Enforce absolute binary path for common pwntools calls.
    bp = binary_path.replace("\\", "\\\\")
    out, n_proc = re.subn(r"process\(\s*r?['\"]\./[^'\"]+['\"]\s*\)", f'process(r"{bp}")', out)
    if n_proc:
        fixes.append(f"fixed_relative_process_path:{n_proc}")
    out, n_elf = re.subn(r"ELF\(\s*r?['\"]\./[^'\"]+['\"]\s*\)", f'ELF(r"{bp}")', out)
    if n_elf:
        fixes.append(f"fixed_relative_elf_path:{n_elf}")

    # Replace bare marker identifiers with string print statements.
    def _replace_bare_marker(text: str, marker: str) -> tuple[str, int]:
        pat = rf"(?m)^(?P<indent>\s*){re.escape(marker)}\s*$"
        repl = rf'\g<indent>print("{marker}")'
        return re.subn(pat, repl, text)

    out2, n1 = _replace_bare_marker(out, "PROBE_RESULT_JSON_START")
    out = out2
    if n1:
        fixes.append(f"fixed_bare_start_marker:{n1}")
    out2, n2 = _replace_bare_marker(out, "PROBE_RESULT_JSON_END")
    out = out2
    if n2:
        fixes.append(f"fixed_bare_end_marker:{n2}")

    has_start = 'print("PROBE_RESULT_JSON_START")' in out
    has_end = 'print("PROBE_RESULT_JSON_END")' in out
    has_json_dump = "json.dumps(" in out

    # If script does not guarantee marker+json protocol, append a fallback trailer.
    if not (has_start and has_end and has_json_dump):
        trailer = """

if __name__ == "__main__":
    try:
        result  # type: ignore[name-defined]
    except Exception:
        result = {"measured_facts": {}, "unresolved_facts": [{"key": "*", "reason": "sanitizer_result_missing"}], "notes": ["sanitized_fallback"]}
    if not isinstance(result, dict):
        result = {"measured_facts": {}, "unresolved_facts": [{"key": "*", "reason": "sanitizer_result_not_dict"}], "notes": ["sanitized_fallback"]}
    if "measured_facts" not in result:
        result["measured_facts"] = {}
    if "unresolved_facts" not in result:
        result["unresolved_facts"] = []
    if "notes" not in result:
        result["notes"] = []
    print("PROBE_RESULT_JSON_START")
    print(json.dumps(result, ensure_ascii=False))
    print("PROBE_RESULT_JSON_END")
"""
        out = out.rstrip() + "\n" + trailer.lstrip("\n")
        fixes.append("appended_protocol_fallback_trailer")

    return out, fixes


def build_probe_script_for_facts(
    evidence: Evidence,
    *,
    plan: PlannerPlan,
    fact_store: Dict[str, Any],
    max_facts: int = 1,
    log_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Tuple[str, List[Dict[str, Any]], str]:
    needed = _collect_needed_measurements(plan, evidence, fact_store, max_facts)
    prompt_obj = {
        "challenge_type": evidence.challenge_type,
        "binary_path": evidence.binary.path,
        "problem_path": evidence.problem_path,
        "measurements": [x.__dict__ for x in needed],
        "strategy_summary": plan.strategy_summary,
        "existing_evidence": json.loads(evidence.to_json()),
        "fact_store": fact_store,
    }
    if log_event:
        log_event("executor_request", {"measurements": prompt_obj["measurements"], "prompt_preview": json.dumps(prompt_obj, ensure_ascii=False)[:4000]})
    try:
        res = chat_complete_detailed(
            json.dumps(prompt_obj, ensure_ascii=False),
            EXECUTOR_SYSTEM_PROMPT,
            temperature=0.0,
            role=ROLE_EXECUTOR,
        )
        sanitized, fixes = _sanitize_probe_script(res.extracted_content, evidence.binary.path)
        if log_event:
            log_event(
                "executor_response",
                {
                    "model": res.model,
                    "raw_preview": res.raw_content[:3000],
                    "sanitizer_fixes": fixes,
                },
            )
        return sanitized, prompt_obj["measurements"], res.model
    except LLMClientError as exc:
        if log_event:
            log_event("executor_error", {"error": str(exc)})
        fallback = (
            "import json\n"
            'print("PROBE_RESULT_JSON_START")\n'
            'print(json.dumps({"measured_facts": {}, "unresolved_facts": [], "notes": ["executor_fallback"]}, ensure_ascii=False))\n'
            'print("PROBE_RESULT_JSON_END")\n'
        )
        return fallback, prompt_obj["measurements"], "fallback"


def build_measure_actions_for_facts(
    evidence: Evidence,
    *,
    plan: PlannerPlan,
    fact_store: Dict[str, Any],
    max_facts: int = 1,
    log_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    tool_failure_history: Optional[Dict[str, int]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    needed = _collect_needed_measurements(plan, evidence, fact_store, max_facts)
    prompt_obj = {
        "challenge_type": evidence.challenge_type,
        "binary_path": evidence.binary.path,
        "measurements": [x.__dict__ for x in needed],
        "strategy_summary": plan.strategy_summary,
        "existing_evidence": json.loads(evidence.to_json()),
        "fact_store": fact_store,
    }
    if needed:
        failures = tool_failure_history or {}
        # Collect tools that have failed too many times
        blocked_tools = [t for t, c in failures.items() if c >= MAX_CONSECUTIVE_TOOL_FAILURES]
        action = _deterministic_action_for_measurement(
            evidence.challenge_type, needed[0], evidence.binary.path, failed_tools=blocked_tools
        )
        if log_event:
            log_event(
                "executor_deterministic_action",
                {"measurement": needed[0].description, "action": action, "blocked_tools": blocked_tools},
            )
        return [action], [needed[0].__dict__], "deterministic"
    if log_event:
        log_event(
            "executor_tools_request",
            {"measurements": prompt_obj["measurements"], "prompt_preview": json.dumps(prompt_obj, ensure_ascii=False)[:4000]},
        )
    try:
        res = chat_complete_detailed(
            json.dumps(prompt_obj, ensure_ascii=False),
            EXECUTOR_TOOL_SYSTEM_PROMPT,
            temperature=0.0,
            role=ROLE_EXECUTOR,
        )
        raw = (res.extracted_content or "").strip()
        data = json.loads(raw) if raw.startswith("{") else json.loads(raw[raw.find("{") : raw.rfind("}") + 1])
        actions = data.get("actions", []) if isinstance(data, dict) else []
        if not isinstance(actions, list):
            actions = []
        actions = [a for a in actions if isinstance(a, dict) and a.get("tool")]
        allowed_tools = ALLOWED_TOOLS_BY_CHALLENGE.get(evidence.challenge_type, set())
        filtered_actions: List[Dict[str, Any]] = []
        for action in actions:
            tool_name = str(action.get("tool", ""))
            if not allowed_tools or tool_name in allowed_tools:
                filtered_actions.append(action)
        actions = filtered_actions
        if log_event:
            log_event(
                "executor_tools_response",
                {"model": res.model, "actions": actions[:20], "raw_preview": res.raw_content[:2500]},
            )
        return actions, prompt_obj["measurements"], res.model
    except Exception as exc:
        if log_event:
            log_event("executor_tools_error", {"error": str(exc)})
        return [], prompt_obj["measurements"], "fallback"


def extract_measured_facts_from_output(output: str) -> Dict[str, Any]:
    start = "PROBE_RESULT_JSON_START"
    end = "PROBE_RESULT_JSON_END"
    if start not in output or end not in output:
        return {"measured_facts": {}, "unresolved_facts": [{"key": "*", "reason": "missing_json_markers"}], "notes": []}
    content = output.split(start, 1)[1].split(end, 1)[0].strip()
    try:
        data = json.loads(content)
    except Exception as exc:
        return {"measured_facts": {}, "unresolved_facts": [{"key": "*", "reason": f"json_decode_error:{exc}"}], "notes": []}
    measured = data.get("measured_facts", {}) or {}
    unresolved = data.get("unresolved_facts", []) or []
    notes = data.get("notes", []) or []
    if not isinstance(measured, dict):
        measured = {}
    if not isinstance(unresolved, list):
        unresolved = []
    if not isinstance(notes, list):
        notes = []
    return {"measured_facts": measured, "unresolved_facts": unresolved, "notes": notes}


def apply_measured_facts_to_evidence(evidence: Evidence, measured_facts: Dict[str, Any]) -> Evidence:
    for key, value in measured_facts.items():
        if not isinstance(key, str):
            continue
        if key.startswith("offsets."):
            evidence.offsets[key.split(".", 1)[1]] = value
            evidence.provenance[key] = "measured"
        elif key.startswith("symbols."):
            evidence.symbols[key.split(".", 1)[1]] = str(value)
            evidence.provenance[key] = "measured"
        elif key.startswith("constraints."):
            evidence.constraints[key.split(".", 1)[1]] = value
            evidence.provenance[key] = "measured"
        elif key.startswith("probe_artifacts."):
            evidence.probe_artifacts[key.split(".", 1)[1]] = value
            evidence.provenance[key] = "measured"
        elif key.startswith("interaction_model."):
            evidence.interaction_model[key.split(".", 1)[1]] = value
            evidence.provenance[key] = "measured"
        elif key == "io.prompts":
            vals = value if isinstance(value, list) else [str(value)]
            evidence.io_prompts = list(dict.fromkeys(evidence.io_prompts + [str(v) for v in vals]))[:40]
            evidence.provenance[key] = "measured"
    return evidence

