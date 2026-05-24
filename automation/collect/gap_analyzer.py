from __future__ import annotations

from typing import List

from automation.schemas import Evidence


REQUIRED_BY_TYPE = {
    "fmt": [
        "binary.exists",
        "binary.executable",
        "offsets.fmt_offset_arg",
        "symbols.x",
        "interaction_model.prompt_sequence",
    ],
    "int": [
        "binary.exists",
        "binary.executable",
        "offsets.ret_offset_bytes",
        "constraints.pointer_width",
        "probe_artifacts.crash_offset_proof",
    ],
    "heap": [
        "binary.exists",
        "binary.executable",
        "constraints.heap_menu_model",
        "constraints.heap_primitive",
        "probe_artifacts.heap_trace",
    ],
    "rop": [
        "binary.exists",
        "binary.executable",
        "offsets.ret_offset_bytes",
        "constraints.pointer_width",
        "probe_artifacts.gadget_inventory",
    ],
}


def get_required_fields(challenge_type: str) -> List[str]:
    return list(REQUIRED_BY_TYPE.get(challenge_type, ["binary.exists", "binary.executable"]))


def _has_nonempty(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, bytes)):
        s = value.decode() if isinstance(value, bytes) else value
        return bool(s.strip()) and s.strip().lower() not in {"unknown", "unk", "n/a", "none", "todo"}
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


def _has_field(e: Evidence, key: str) -> bool:
    parts = key.split(".")
    root = parts[0]
    rest = parts[1:]

    if root == "binary":
        cur = e.binary
    elif root == "symbols":
        cur = e.symbols
    elif root == "offsets":
        cur = e.offsets
    elif root == "constraints":
        cur = e.constraints
    elif root == "binary_features":
        cur = e.binary_features
    elif root == "runtime":
        cur = e.runtime
    elif root == "interaction_model":
        cur = e.interaction_model
    elif root == "probe_artifacts":
        cur = e.probe_artifacts
    else:
        return False

    for part in rest:
        if isinstance(cur, dict):
            if part not in cur:
                return False
            cur = cur.get(part)
            continue
        if not hasattr(cur, part):
            return False
        cur = getattr(cur, part)
    return _has_nonempty(cur)


def analyze_missing_fields(evidence: Evidence) -> List[str]:
    required = get_required_fields(evidence.challenge_type)
    missing = [k for k in required if not _has_field(evidence, k)]

    # Generic quality checks.
    if not evidence.binary.checksec_raw:
        missing.append("binary.checksec_raw")
    if not evidence.binary_features:
        missing.append("binary_features")
    if not evidence.runtime:
        missing.append("runtime")
    if not evidence.io_prompts:
        missing.append("io.prompts")
    return list(dict.fromkeys(missing))
