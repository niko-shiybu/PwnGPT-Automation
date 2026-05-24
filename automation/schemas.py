from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BinaryInfo:
    path: str
    exists: bool
    executable: bool
    sha256: Optional[str] = None
    arch: Optional[str] = None
    checksec_raw: Optional[str] = None


@dataclass
class Evidence:
    challenge_type: str
    problem_path: str
    binary: BinaryInfo
    # Backward-compatible flat symbol map (name -> "0x...")
    symbols: Dict[str, str] = field(default_factory=dict)
    # Structured symbols: globals/funcs/got/plt (values usually "0x..." strings)
    symbols_map: Dict[str, Dict[str, str]] = field(default_factory=dict)
    strings: Dict[str, str] = field(default_factory=dict)
    # Optional raw strings scan lines (may be large; keep short)
    strings_raw: List[str] = field(default_factory=list)
    # C source bundles: {path: content}
    sources: Dict[str, str] = field(default_factory=dict)
    # Optional extracted struct definitions for heap/struct reasoning
    struct_defs: List[Dict[str, Any]] = field(default_factory=list)
    offsets: Dict[str, Any] = field(default_factory=dict)
    io_prompts: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    binary_features: Dict[str, Any] = field(default_factory=dict)
    runtime: Dict[str, Any] = field(default_factory=dict)
    interaction_model: Dict[str, Any] = field(default_factory=dict)
    crash_signals: Dict[str, Any] = field(default_factory=dict)
    probe_artifacts: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, str] = field(default_factory=dict)
    missing_fields: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    def to_trimmed_dict(self) -> Dict[str, Any]:
        """Convert to dict and trim large fields to stay within LLM token limits.
        Removes redundant sources (already in problem_text), truncates strings_raw,
        and filters symbols_map to keep only relevant entries for exploitation."""
        d = asdict(self)
        d.pop("sources", None)
        if isinstance(d.get("strings_raw"), list) and len(d["strings_raw"]) > 10:
            d["strings_raw"] = d["strings_raw"][:10]
        if isinstance(d.get("symbols_map"), dict):
            _priority_keywords = (
                "main", "system", "exec", "puts", "printf", "read", "write",
                "gets", "fgets", "scanf", "flag", "win", "shell", "backdoor",
                "magic", "vuln", "get_flag", "not_called", "call_me",
                "exec_the_string", "exec_string", "vulnerable",
                "pop_rdi", "pop_rsi", "ret", "gadget",
                "system@plt", "puts@plt", "read@plt", "write@plt",
                "printf@plt", "gets@plt", "exit@plt", "setbuf@plt",
                "alarm@plt", "signal@plt", "getegid", "setresgid",
                "execl", "execve", "execlp", "execvp",
            )
            for category in ("funcs", "globals"):
                entries = d["symbols_map"].get(category, {})
                if isinstance(entries, dict) and len(entries) > 50:
                    retained = {}
                    for name, addr in entries.items():
                        name_lower = name.lower()
                        if any(kw in name_lower for kw in _priority_keywords):
                            retained[name] = addr
                            continue
                        if name_lower.startswith(("_dl_", "__libc_", "_IO_", "_dl_")):
                            continue
                        if name_lower.startswith("_") and len(name) >= 12:
                            continue
                        retained[name] = addr
                    if len(retained) > 50:
                        sorted_entries = sorted(retained.items(), key=lambda x: len(x[0]))
                        d["symbols_map"][category] = dict(sorted_entries[:50])
        return d

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Evidence":
        binary_data = data.get("binary", {})
        binary = BinaryInfo(**binary_data)
        return Evidence(
            challenge_type=data.get("challenge_type", ""),
            problem_path=data.get("problem_path", ""),
            binary=binary,
            symbols=data.get("symbols", {}),
            symbols_map=data.get("symbols_map", {}) or {},
            strings=data.get("strings", {}),
            strings_raw=data.get("strings_raw", []) or [],
            sources=data.get("sources", {}) or {},
            struct_defs=data.get("struct_defs", []) or [],
            offsets=data.get("offsets", {}),
            io_prompts=data.get("io_prompts", []),
            constraints=data.get("constraints", {}),
            binary_features=data.get("binary_features", {}),
            runtime=data.get("runtime", {}),
            interaction_model=data.get("interaction_model", {}),
            crash_signals=data.get("crash_signals", {}),
            probe_artifacts=data.get("probe_artifacts", {}),
            provenance=data.get("provenance", {}),
            missing_fields=data.get("missing_fields", []),
            notes=data.get("notes", []),
        )


@dataclass
class VerifyResult:
    success: bool
    exit_code: Optional[int]
    success_signals: List[str] = field(default_factory=list)
    failure_signals: List[str] = field(default_factory=list)
    stdout_tail: str = ""
    stderr_tail: str = ""
    stdout_full: str = ""
    stderr_full: str = ""
    forensics_full: str = ""
    summary: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


@dataclass
class MeasurementRequest:
    id: int
    description: str
    reason: str = ""
    priority: str = "medium"


@dataclass
class PlannerPlan:
    strategy_summary: str = ""
    vulnerability_logic: str = ""
    exploit_primitives: List[str] = field(default_factory=list)
    measurements: List[MeasurementRequest] = field(default_factory=list)
    exploit_constraints: Dict[str, Any] = field(default_factory=dict)
    need_more_measurements: bool = True
    notes: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "PlannerPlan":
        items = data.get("measurements", []) or []
        if not items:
            # Backward-compatible read for older planner responses.
            combined = []
            for old in (data.get("required_measurements", []) or []):
                if isinstance(old, dict) and old.get("key"):
                    combined.append(
                        {
                            "id": len(combined) + 1,
                            "description": str(old.get("key")),
                            "reason": str(old.get("reason", "")),
                            "priority": str(old.get("priority", "medium")),
                        }
                    )
            for old in (data.get("required_facts", []) or []):
                if isinstance(old, dict) and old.get("key"):
                    combined.append(
                        {
                            "id": len(combined) + 1,
                            "description": str(old.get("key")),
                            "reason": str(old.get("reason", "")),
                            "priority": str(old.get("priority", "medium")),
                        }
                    )
            items = combined
        measurements = []
        for item in items:
            if isinstance(item, dict) and item.get("description"):
                measurements.append(
                    MeasurementRequest(
                        id=int(item.get("id", len(measurements) + 1)),
                        description=str(item.get("description", "")),
                        reason=str(item.get("reason", "")),
                        priority=str(item.get("priority", "medium")),
                    )
                )
        return PlannerPlan(
            strategy_summary=str(data.get("strategy_summary", "")),
            vulnerability_logic=str(data.get("vulnerability_logic", "")),
            exploit_primitives=[str(x) for x in (data.get("exploit_primitives", []) or [])],
            measurements=measurements,
            exploit_constraints=data.get("exploit_constraints", {}) or {},
            need_more_measurements=bool(data.get("need_more_measurements", True)),
            notes=[str(x) for x in (data.get("notes", []) or [])],
        )


@dataclass
class DeciderDecision:
    failure: str = ""
    next_action: str = ""
    missing_measurements: List[MeasurementRequest] = field(default_factory=list)
    value_score: int = 0
    notes: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "DeciderDecision":
        items = data.get("missing_measurements", []) or []
        if not items:
            items = [
                {"id": idx + 1, "description": str(x), "reason": "", "priority": "high"}
                for idx, x in enumerate(data.get("missing_facts", []) or [])
            ]
        missing_measurements = []
        for item in items:
            if isinstance(item, dict) and item.get("description"):
                missing_measurements.append(
                    MeasurementRequest(
                        id=int(item.get("id", len(missing_measurements) + 1)),
                        description=str(item.get("description", "")),
                        reason=str(item.get("reason", "")),
                        priority=str(item.get("priority", "medium")),
                    )
                )
        return DeciderDecision(
            failure=str(data.get("failure", "")),
            next_action=str(data.get("next_action", "")),
            missing_measurements=missing_measurements,
            value_score=int(data.get("value_score", 0)),
            notes=[str(x) for x in (data.get("notes", []) or [])],
        )
