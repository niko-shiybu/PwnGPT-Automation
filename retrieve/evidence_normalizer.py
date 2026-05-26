from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from retrieve.schemas import (
    LibcInfo,
    Mitigations,
    NormalizedEvidence,
    VulnerabilityInfo,
)


def _parse_checksec(checksec_raw: str) -> Tuple[Mitigations, List[str]]:
    """Parse checksec output into Mitigations. Returns (mitigations, warnings)."""
    warnings: List[str] = []
    canary = False
    nx = False
    pie = False
    relro = "unknown"

    if not checksec_raw:
        warnings.append("checksec_raw is empty, mitigations may be incorrect")
        return Mitigations(), warnings

    text = checksec_raw

    # Canary
    if re.search(r"canary\s*found", text, re.IGNORECASE) and not re.search(r"no canary", text, re.IGNORECASE):
        canary = True
    elif re.search(r"no canary", text, re.IGNORECASE):
        canary = False

    # NX
    if re.search(r"NX\s*enabled", text, re.IGNORECASE):
        nx = True
    elif re.search(r"NX\s*disabled", text, re.IGNORECASE):
        nx = False

    # PIE
    if re.search(r"PIE\s*enabled", text, re.IGNORECASE):
        pie = True
    elif re.search(r"No PIE", text, re.IGNORECASE) or re.search(r"PIE\s*disabled", text, re.IGNORECASE):
        pie = False

    # RELRO
    if re.search(r"Full RELRO", text, re.IGNORECASE):
        relro = "full"
    elif re.search(r"Partial RELRO", text, re.IGNORECASE):
        relro = "partial"
    elif re.search(r"No RELRO", text, re.IGNORECASE):
        relro = "none"

    return Mitigations(canary=canary, nx=nx, pie=pie, relro=relro), warnings


def _merge_mitigations(
    from_checksec: Mitigations,
    from_features: Dict[str, Any],
) -> Tuple[Mitigations, List[str]]:
    """Merge mitigations from checksec and binary_features. checksec takes priority."""
    warnings: List[str] = []
    result = Mitigations(
        canary=from_checksec.canary,
        nx=from_checksec.nx,
        pie=from_checksec.pie,
        relro=from_checksec.relro,
    )

    feature_map = {
        "canary": ("canary", bool),
        "nx": ("nx", bool),
        "pie": ("pie", bool),
        "relro": ("relro", str),
    }

    for feat_key, (mit_key, _) in feature_map.items():
        feat_val = from_features.get(feat_key)
        if feat_val is None:
            continue
        mit_val = getattr(from_checksec, mit_key)
        if feat_val != mit_val and mit_val is not None:
            warnings.append(
                f"Mitigation conflict: binary_features.{feat_key}={feat_val} "
                f"vs checksec={mit_val}; using checksec"
            )

    return result, warnings


def _detect_bug_type(
    sources: Dict[str, str],
    symbols_map: Dict[str, Any],
    imports: List[str],
) -> Tuple[str, VulnerabilityInfo]:
    """Detect bug type from source code and symbols."""
    vuln = VulnerabilityInfo()

    all_source = ""
    for content in sources.values():
        all_source += content + "\n"

    # Strategy 1: look for stack overflow patterns in source
    # char buf[N]; read(0, buf, M) where M > N
    # Prefer blocks with Hex-Rays annotations for more accurate offset computation.
    if all_source:
        func_blocks = _split_functions(all_source)

        # Two-pass: first collect all candidates, then pick the best
        candidates: List[Tuple[VulnerabilityInfo, int]] = []  # (vuln, annotation_quality)

        for block in func_blocks:
            buf_match = re.search(r"char\s+(\w+)\s*\[(\d+)\]", block)
            if not buf_match:
                buf_match = re.search(r"(?:char|int|void)\s*\*\s*(\w+)\s*=.*malloc", block)
            if not buf_match:
                continue

            buf_name = buf_match.group(1)

            read_match = re.search(rf"read\s*\(\s*(?:\d+|STDIN_FILENO|stdin|STDIN)\s*,\s*(?:&?{buf_name}|\w+)\s*,\s*(0x[0-9a-fA-F]+u?|\d+)\s*\)", block)
            gets_match = re.search(rf"gets\s*\(\s*(?:&?{buf_name}|\w+)\)", block)

            if read_match:
                raw_size = read_match.group(1).rstrip("uU")
                read_size = int(raw_size, 16) if raw_size.startswith("0x") else (int(raw_size) if raw_size.isdigit() else 256)
                buf_size = int(buf_match.group(2)) if buf_match.group(2).isdigit() else 0
                if buf_size > 0 and read_size > buf_size:
                    v = VulnerabilityInfo()
                    v.type = "stack_overflow"
                    v.description = f"{buf_name}[{buf_size}] with read({read_size})"
                    v.function = _extract_func_name(block)
                    v.candidate_eip_offset = _compute_candidate_offset(block, buf_size)
                    # Higher quality if it has Hex-Rays stack annotation
                    has_hex_rays = bool(re.search(r"\[([er])bp-[0-9a-fA-F]+h\]", block))
                    candidates.append((v, 10 if has_hex_rays else 5))
                    continue  # check other blocks too

            if gets_match:
                buf_size = int(buf_match.group(2)) if buf_match.group(2).isdigit() else 0
                v = VulnerabilityInfo()
                v.type = "stack_overflow"
                v.description = f"{buf_name}[{buf_size}] with gets()"
                v.function = _extract_func_name(block)
                if buf_size > 0:
                    v.candidate_eip_offset = _compute_candidate_offset(block, buf_size)
                has_hex_rays = bool(re.search(r"\[([er])bp-[0-9a-fA-F]+h\]", block))
                candidates.append((v, 10 if has_hex_rays else 5))

        if candidates:
            candidates.sort(key=lambda x: -x[1])
            best_vuln, _ = candidates[0]
            return "stack_overflow", best_vuln

        # Fallback: look for any char buf[N] with sprintf/scanf
        for block in func_blocks:
            if re.search(r"(?:sprintf|scanf)\s*\(", block) and re.search(r"char\s+\w+\s*\[", block):
                vuln.type = "stack_overflow"
                func_name = _extract_func_name(block)
                vuln.function = func_name
                return "stack_overflow", vuln

        # Strategy 2: format string vuln detection
        if re.search(r"printf\s*\(\s*\w+\s*\)", all_source) and not re.search(r"printf\s*\(\s*\"", all_source):
            vuln.type = "format_string"
            return "format_string", vuln

        # Strategy 3: integer overflow (uint8 + strlen)
        if re.search(r"unsigned\s+__int8", all_source) and "strlen" in all_source:
            vuln.type = "integer_overflow"
            return "integer_overflow", vuln

    # Strategy 4: infer from challenge_type in symbols/imports
    if "printf" in imports and "system" not in imports:
        # Might be format string
        vuln.type = "format_string"
    elif "read" in imports or "gets" in imports:
        vuln.type = "stack_overflow"

    return vuln.type, vuln


def _split_functions(source: str) -> List[str]:
    """Split C source into function blocks using Hex-Rays or normal C syntax."""
    # Hex-Rays: //----- (ADDR) -----\n return_type func_name(args)
    blocks = re.split(r"//----- \(0?x?[0-9a-fA-F]+\) -+\n", source)
    if len(blocks) >= 2:
        return blocks[1:]
    # Fallback: split on function definitions
    parts = re.split(r"\n(?=\w[\w\s*]+\s+\w+\s*\([^)]*\)\s*\{)", source)
    return parts


def _extract_func_name(block: str) -> str:
    """Extract function name from a C function block."""
    # Match C function definitions: return_type func_name(args)
    # Handle both "void func()" and "ssize_t func()"
    m = re.search(r"(?:\w[\w\s*]+)\s+(\w+)\s*\([^)]*\)", block)
    if m and m.group(1) not in ("if", "while", "for", "switch", "return", "sizeof"):
        return m.group(1)
    return ""


def _compute_candidate_offset(block: str, buf_size: int) -> int:
    """Compute candidate EIP offset from Hex-Rays stack annotations.

    Annotation format: char buf[136]; // [esp+10h] [ebp-88h]
    Offset to return addr = ebp_offset + 4.
    """
    # Try Hex-Rays annotation first
    m = re.search(r"\[([er])bp-([0-9a-fA-F]+)h\]", block)
    if m:
        saved_bp = 8 if m.group(1) == "r" else 4
        off = int(m.group(2), 16) + saved_bp
        if 8 <= off <= 2048:
            return off
    # Fallback: buf_size + saved_ebp (8 for 64-bit, 4 for 32-bit)
    # This is less precise; prefer the annotation.
    # Guess arch from block context
    if re.search(r"\[rbp-", block) or re.search(r"rsp", block):
        return buf_size + 8
    return buf_size + 4


def _extract_imports(strings_raw: List[str], symbols_map: Dict[str, Any]) -> List[str]:
    """Extract imported function names from strings_raw and symbols_map."""
    imports: List[str] = []
    seen = set()

    # From PLT entries in symbols_map
    plt = symbols_map.get("plt", {})
    for name in plt:
        if name not in seen:
            imports.append(name)
            seen.add(name)

    # From strings_raw: look for func@@GLIBC patterns
    for line in (strings_raw or []):
        m = re.search(r"(\w+)@@\w+", line)
        if m:
            name = m.group(1)
            if name not in seen:
                imports.append(name)
                seen.add(name)

    # From got entries
    got = symbols_map.get("got", {})
    for name in got:
        if name not in seen:
            imports.append(name)
            seen.add(name)

    return imports


def normalize(evidence: Dict[str, Any]) -> NormalizedEvidence:
    """Normalize raw evidence.json into NormalizedEvidence."""
    warnings: List[str] = []
    raw = evidence

    # ── Architecture ──────────────────────────────────────────
    binary = evidence.get("binary", {})
    checksec_raw = binary.get("checksec_raw", "")
    binary_features = evidence.get("binary_features", {})

    arch = binary.get("arch", "") or binary_features.get("arch", "")
    if not arch:
        arch = "unknown"

    # Normalize arch name
    arch_lower = arch.lower()
    if "i386" in arch_lower or "i686" in arch_lower or "80386" in arch_lower:
        arch = "i386"
        bits = 32
        endian = "little"
    elif "amd64" in arch_lower or "x86_64" in arch_lower or "x86-64" in arch_lower:
        arch = "amd64"
        bits = 64
        endian = "little"
    elif "arm" in arch_lower and "64" in arch_lower:
        arch = "aarch64"
        bits = 64
        endian = "little"
    elif "arm" in arch_lower:
        arch = "arm"
        bits = 32
        endian = "little"
    else:
        bits = binary_features.get("arch_bits", 32)
        endian = "little"
        warnings.append(f"Unknown architecture: {arch}; assuming {bits}-bit")

    # ── Mitigations ───────────────────────────────────────────
    checksec_mits, checksec_warnings = _parse_checksec(checksec_raw)
    warnings.extend(checksec_warnings)
    mitigations, merge_warnings = _merge_mitigations(checksec_mits, binary_features)
    warnings.extend(merge_warnings)

    # ── Symbols ───────────────────────────────────────────────
    symbols_map = evidence.get("symbols_map", {}) or {}
    symbols = {
        "functions": dict(symbols_map.get("funcs", {})),
        "plt": dict(symbols_map.get("plt", {})),
        "got": dict(symbols_map.get("got", {})),
    }

    # ── Imports ───────────────────────────────────────────────
    strings_raw = evidence.get("strings_raw", []) or []
    imports = _extract_imports(strings_raw, symbols_map)

    # ── Bug Type ──────────────────────────────────────────────
    sources = evidence.get("sources", {}) or {}
    bug_type, vuln = _detect_bug_type(sources, symbols_map, imports)

    # If we already know challenge_type, use it to refine
    challenge_type = evidence.get("challenge_type", "")
    if challenge_type == "rop" and bug_type == "unknown":
        bug_type = "stack_overflow"
    elif challenge_type == "fmt":
        bug_type = "format_string"
    elif challenge_type in ("int", "integer"):
        bug_type = "integer_overflow"
    elif challenge_type == "heap":
        bug_type = "heap"

    # ── Check for existing offsets ────────────────────────────
    offsets = evidence.get("offsets", {}) or {}
    if offsets.get("ret_offset_bytes"):
        vuln.candidate_eip_offset = int(offsets["ret_offset_bytes"])
        vuln.offset_verified = True

    # ── Check for fmt offsets ─────────────────────────────────
    if offsets.get("fmt_write_arg"):
        vuln.candidate_fmt_offset = int(offsets["fmt_write_arg"])

    # ── Libc ──────────────────────────────────────────────────
    runtime = evidence.get("runtime", {}) or {}
    libc_path = runtime.get("libc_path", "")
    libc_version = runtime.get("libc_version", "")
    libc_available = bool(libc_path and ("libc" in libc_path.lower() or "linux" in libc_path.lower()))

    libc = LibcInfo(
        available=libc_available,
        path=libc_path,
        version=libc_version,
    )

    if not libc_available and libc_path:
        warnings.append(f"libc path does not look like a standard libc: {libc_path}")

    # ── Probe artifacts ───────────────────────────────────────
    probe = evidence.get("probe_artifacts", {}) or {}
    if probe.get("crash_offset_proof"):
        try:
            import json as _json
            proof = _json.loads(probe["crash_offset_proof"]) if isinstance(probe["crash_offset_proof"], str) else probe["crash_offset_proof"]
            if proof.get("method") in ("source_annotation", "corefile", "gdb_fallback"):
                if vuln.candidate_eip_offset is None:
                    vuln.candidate_eip_offset = proof.get("estimated")
        except Exception:
            pass

    # ── Assemble ──────────────────────────────────────────────
    return NormalizedEvidence(
        arch=arch,
        bits=bits,
        endian=endian,
        bug_type=bug_type,
        mitigations=mitigations,
        imports=imports,
        symbols=symbols,
        vulnerability=vuln,
        libc=libc,
        warnings=warnings,
        raw=raw,
    )
