from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_run_log(log_path: Path, event: str, data: Dict[str, Any]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": _ts(),
        "event": event,
        "data": data,
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
