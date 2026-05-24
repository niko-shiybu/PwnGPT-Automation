from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuditFinding:
    type: str          # e.g. "MISSING_POP_RDI", "OFFSET_MISMATCH"
    severity: str      # "CRITICAL" | "ERROR" | "WARNING" | "INFO"
    category: str      # "generic" | "rop" | "fmt" | "int" | "heap"
    location: str      # "payload construction, line 18"
    detail: str        # Human-readable explanation
    suggestion: str    # Fix recommendation


@dataclass
class CodeSummary:
    arch_bits: Optional[int] = None
    pack_function: Optional[str] = None           # "p32" | "p64" | "mixed"
    offset_used: Optional[int] = None
    strategy: Optional[str] = None                # "ret2text" | "ret2libc" | ...
    has_pop_rdi: bool = False
    has_rop_builder: bool = False
    uses_fmtstr_payload: bool = False
    fmt_offset_used: Optional[int] = None
    elf_lookups: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class AuditReport:
    findings: List[AuditFinding] = field(default_factory=list)
    code_summary: Optional[CodeSummary] = None
    raw_analysis: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_actionable(self) -> bool:
        return any(
            f.severity in ("CRITICAL", "ERROR", "WARNING") for f in self.findings
        )

    def to_json_payload(self) -> Dict[str, Any]:
        return {
            "static_audit": {
                "findings": [
                    {
                        "type": f.type,
                        "severity": f.severity,
                        "category": f.category,
                        "location": f.location,
                        "detail": f.detail,
                        "suggestion": f.suggestion,
                    }
                    for f in self.findings
                ],
                "code_summary": {
                    "arch_bits": self.code_summary.arch_bits if self.code_summary else None,
                    "pack_function": self.code_summary.pack_function if self.code_summary else None,
                    "offset_used": self.code_summary.offset_used if self.code_summary else None,
                    "strategy": self.code_summary.strategy if self.code_summary else None,
                    "has_pop_rdi": self.code_summary.has_pop_rdi if self.code_summary else False,
                    "has_rop_builder": self.code_summary.has_rop_builder if self.code_summary else False,
                    "uses_fmtstr_payload": self.code_summary.uses_fmtstr_payload if self.code_summary else False,
                    "fmt_offset_used": self.code_summary.fmt_offset_used if self.code_summary else None,
                    "elf_lookups": self.code_summary.elf_lookups if self.code_summary else [],
                },
            }
        }
