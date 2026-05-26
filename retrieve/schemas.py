from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Mitigations:
    canary: bool = False
    nx: bool = True
    pie: bool = False
    relro: str = "unknown"
    _uncertain: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary": self.canary,
            "nx": self.nx,
            "pie": self.pie,
            "relro": self.relro,
        }


@dataclass
class VulnerabilityInfo:
    function: str = ""
    type: str = "stack_overflow"
    candidate_eip_offset: Optional[int] = None
    offset_verified: bool = False
    # For format-string: candidate offset on the stack
    candidate_fmt_offset: Optional[int] = None
    # For integer overflow: boundary values that trigger
    candidate_int_boundary: Optional[int] = None
    description: str = ""


@dataclass
class LibcInfo:
    available: bool = False
    path: str = ""
    version: str = ""


@dataclass
class NormalizedEvidence:
    arch: str = "unknown"
    bits: int = 32
    endian: str = "little"
    bug_type: str = "unknown"
    mitigations: Mitigations = field(default_factory=Mitigations)
    imports: List[str] = field(default_factory=list)
    symbols: Dict[str, Dict[str, str]] = field(default_factory=lambda: {"functions": {}, "plt": {}, "got": {}})
    vulnerability: VulnerabilityInfo = field(default_factory=VulnerabilityInfo)
    libc: LibcInfo = field(default_factory=LibcInfo)
    warnings: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "bug_type": self.bug_type,
            "mitigations": self.mitigations.to_dict(),
            "imports": self.imports,
            "symbols": self.symbols,
            "vulnerability": {
                "function": self.vulnerability.function,
                "type": self.vulnerability.type,
                "candidate_eip_offset": self.vulnerability.candidate_eip_offset,
                "offset_verified": self.vulnerability.offset_verified,
                "candidate_fmt_offset": self.vulnerability.candidate_fmt_offset,
                "candidate_int_boundary": self.vulnerability.candidate_int_boundary,
                "description": self.vulnerability.description,
            },
            "libc": {
                "available": self.libc.available,
                "path": self.libc.path,
                "version": self.libc.version,
            },
            "warnings": self.warnings,
        }


@dataclass
class SearchQuery:
    query: str
    priority: float = 0.5
    purpose: str = ""
    expected_strategy: str = ""
    must_include_terms: List[str] = field(default_factory=list)
    avoid_terms: List[str] = field(default_factory=list)


@dataclass
class SearchResult:
    title: str = ""
    url: str = ""
    snippet: str = ""
    source: str = ""
    query: str = ""
    source_score: float = 0.0


@dataclass
class StrategyRecipe:
    id: str = ""
    name: str = ""
    technique: str = ""
    arch: List[str] = field(default_factory=list)
    base_score: float = 0.5
    preconditions: List[str] = field(default_factory=list)
    required_measurements: List[str] = field(default_factory=list)
    payload_shape: List[str] = field(default_factory=list)
    failure_signatures: Dict[str, str] = field(default_factory=dict)
    source_refs: List[Dict[str, Any]] = field(default_factory=list)
    why_relevant: str = ""
    not_applicable_if: List[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_snippet: str = ""


@dataclass
class StrategyCandidate:
    id: str = ""
    name: str = ""
    technique: str = ""
    score: float = 0.0
    priority: str = "medium"
    reason: str = ""
    preconditions: List[str] = field(default_factory=list)
    required_measurements: List[str] = field(default_factory=list)
    payload_shape: List[str] = field(default_factory=list)
    failure_signatures: Dict[str, str] = field(default_factory=dict)
    source_refs: List[Dict[str, Any]] = field(default_factory=list)
    not_applicable_if: List[str] = field(default_factory=list)
    scoring_breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class StrategyCandidatesOutput:
    challenge_fingerprint: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    search_plan: Dict[str, Any] = field(default_factory=dict)
    candidates: List[StrategyCandidate] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge_fingerprint": self.challenge_fingerprint,
            "warnings": self.warnings,
            "search_plan": self.search_plan,
            "candidates": [c.__dict__ for c in self.candidates],
        }
