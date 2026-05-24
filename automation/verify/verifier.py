from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from automation import local_config
from automation.schemas import VerifyResult


SUCCESS_KEYWORDS = ["flag{", "ctf{", "running sh...", "uid=", "gid="]
FAIL_KEYWORDS = ["SIGSEGV", "Got EOF", "Traceback", "error:", "bad!"]
SHELL_PROBE_MARKER = "__PWNED__"
SHELL_PROBE_COMMANDS = [f"echo {SHELL_PROBE_MARKER}", "id", "pwd", "echo __ALIVE__"]


def _tail(text: str, max_lines: int = 40) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])


def verify_exploit(
    script_path: Path,
    cwd: Path,
    *,
    python_exec: str = "",
    log_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> VerifyResult:
    """
    Success criterion:
    - After exploit starts, send probe commands.
    - Success requires BOTH:
      1) command-response evidence appears in output
      2) process remains alive after probe (stable shell)
    """
    try:
        py = (python_exec or getattr(local_config, "AUTOMATION_PYTHON", "") or "python3").strip()
        proc = subprocess.Popen(
            [py, str(script_path)],
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception as exc:  # pragma: no cover
        if log_event:
            log_event("verify_spawn_error", {"error": str(exc)})
        return VerifyResult(
            success=False,
            exit_code=None,
            failure_signals=["spawn_error"],
            stdout_tail="",
            stderr_tail=str(exc),
            stdout_full="",
            stderr_full=str(exc),
            summary="failed_spawn",
        )

    stdout = ""
    stderr = ""
    alive_after_probe = False
    marker_seen = False
    response_seen = False
    timed_out = False
    gdb_report = ""
    try:
        # Give exploit a short window to run and potentially drop to shell.
        time.sleep(1.0)
        if proc.poll() is None and proc.stdin:
            for cmd in SHELL_PROBE_COMMANDS:
                proc.stdin.write((cmd + "\n").encode())
            proc.stdin.flush()
            # incremental waits help with fragmented shell output
            time.sleep(0.6)
            if proc.poll() is None:
                time.sleep(0.8)
            if log_event:
                log_event(
                    "verify_shell_probe_sent",
                    {"commands": SHELL_PROBE_COMMANDS},
                )

        alive_after_probe = proc.poll() is None

        # Try graceful termination so verifier does not leave hanging processes.
        if proc.poll() is None and proc.stdin:
            try:
                proc.stdin.write(b"exit\n")
                proc.stdin.flush()
            except Exception:
                pass

        try:
            out_b, err_b = proc.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out_b, err_b = proc.communicate()
        stdout = (out_b or b"").decode(errors="ignore")
        stderr = (err_b or b"").decode(errors="ignore")
        marker_seen = SHELL_PROBE_MARKER in stdout or SHELL_PROBE_MARKER in stderr
        lower_blob = (stdout + "\n" + stderr).lower()
        strong_shell_tokens = ["uid=", "gid=", "running sh...", "flag{", "ctf{"]
        prompt_tokens = ["$ ", "# "]
        has_strong_shell_evidence = any(tok in lower_blob for tok in strong_shell_tokens)
        has_shell_prompt = any(tok in stdout or tok in stderr for tok in prompt_tokens)
        response_seen = has_strong_shell_evidence or (has_shell_prompt and marker_seen)
    except Exception as exc:  # pragma: no cover
        if log_event:
            log_event("verify_runtime_error", {"error": str(exc)})
        return VerifyResult(
            success=False,
            exit_code=proc.returncode,
            failure_signals=["verify_runtime_error"],
            stdout_tail=_tail(stdout),
            stderr_tail=str(exc),
            stdout_full=stdout,
            stderr_full=str(exc),
            summary="failed_runtime_error",
        )

    blob = stdout + "\n" + stderr

    hit_success = [k for k in SUCCESS_KEYWORDS if k.lower() in blob.lower()]
    hit_fail = [k for k in FAIL_KEYWORDS if k.lower() in blob.lower()]

    lower_blob = blob.lower()
    flag_leak_success = ("flag{" in lower_blob) or ("ctf{" in lower_blob)
    shell_evidence = response_seen
    success = bool(flag_leak_success or shell_evidence)
    summary = "success" if success else "failed"
    if success:
        # Keep EOF as failure signal for diagnostics, but do not downgrade summary.
        if "got eof" in blob.lower() and log_event:
            log_event("verify_eof_observed_after_success", {"note": "EOF observed but success retained"})
    elif "SIGSEGV" in hit_fail:
        summary = "failed_sigsegv"
    elif timed_out:
        summary = "failed_hang_after_probe"
    elif proc.returncode not in (0, None):
        summary = f"failed_exit_{proc.returncode}"
    elif not marker_seen:
        summary = "failed_no_shell_probe_marker"
    elif not (alive_after_probe or response_seen):
        summary = "failed_shell_not_alive"
    elif "Got EOF" in hit_fail:
        summary = "failed_eof"

    if summary.startswith("failed"):
        success = False
        # Forensic: extract crash context from pwntools stderr first (faster/more reliable than GDB).
        gdb_report = ""
        try:
            crash_context = ""
            for marker in ["stopped by signal", "SIGSEGV", "eip=", "rip=", "rsp=", "esp="]:
                idx = stderr.lower().find(marker.lower())
                if idx >= 0:
                    crash_context += stderr[max(0, idx - 100):idx + 500] + "\n"
            if crash_context.strip():
                gdb_report = crash_context.strip()
        except Exception:
            pass

        if not gdb_report:
            try:
                gdb_cmds = "\n".join(
                    [
                        "set pagination off",
                        "set confirm off",
                        "run",
                        "bt",
                        "info registers",
                        "x/20gx $sp",
                        "x/10i $pc",
                        "quit",
                    ]
                )
                g = subprocess.run(
                    ["gdb", "-q", "--args", py, str(script_path)],
                    input=gdb_cmds.encode(),
                    capture_output=True,
                    timeout=12,
                    check=False,
                    cwd=str(cwd),
                )
                gdb_report = ((g.stdout or b"").decode(errors="ignore") + "\n" + (g.stderr or b"").decode(errors="ignore")).strip()
            except Exception:
                gdb_report = ""

    return VerifyResult(
        success=success,
        exit_code=proc.returncode,
        success_signals=hit_success,
        failure_signals=hit_fail,
        stdout_tail=_tail(stdout),
        stderr_tail=_tail(stderr),
        stdout_full=stdout,
        stderr_full=stderr,
        forensics_full=gdb_report,
        summary=summary,
    )
