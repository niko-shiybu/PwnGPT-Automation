# OpenHands SDK Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `automation/openhands_agent.py` (self-built CodeAct agent) with the official OpenHands Software Agent SDK, while keeping PwnGPT's evidence collection, verification, and benchmark orchestration intact.

**Architecture:** PwnGPT collects evidence (checksec, ROPgadgets, problem.txt) on the host, then delegates exploit writing + debugging to an OpenHands SDK Agent running inside a DockerWorkspace. Custom CTF tools (GDB offset, ROPgadget, fmt scan) are exposed via MCP server from the host. Results are extracted from the SDK event stream into the existing `run_report.json` format.

**Tech Stack:** OpenHands SDK (`openhands-ai`), MCP (Model Context Protocol via `mcp` package), existing `pwntools`, `automation/tools/tool_runner.py`

---

### Task 1: Install OpenHands SDK and verify API shape

**Files:**
- Modify: `requirements.txt`
- Read: SDK module structure

- [ ] **Step 1: Install the package**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && pip install openhands-ai
```

- [ ] **Step 2: Verify import and inspect API**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && python3 -c "
import openhands.sdk
from openhands.sdk import LLM, Agent, Conversation, Tool
print('LLM signature:', LLM.__init__.__doc__[:200] if LLM.__init__.__doc__ else 'no doc')
print('Agent signature:', Agent.__init__.__doc__[:200] if Agent.__init__.__doc__ else 'no doc')
print('Conversation signature:', Conversation.__init__.__doc__[:200] if Conversation.__init__.__doc__ else 'no doc')

# Check workspace imports
from openhands.workspace import DockerWorkspace, LocalWorkspace
print('DockerWorkspace:', DockerWorkspace.__init__.__doc__[:200] if DockerWorkspace.__init__.__doc__ else 'no doc')
print('LocalWorkspace:', LocalWorkspace.__init__.__doc__[:200] if LocalWorkspace.__init__.__doc__ else 'no doc')

# Check tool imports
from openhands.tools.terminal import TerminalTool
from openhands.tools.file_editor import FileEditorTool
print('TerminalTool OK')
print('FileEditorTool OK')

# Check MCP config support on Agent
import inspect
sig = inspect.signature(Agent.__init__)
print('Agent params:', list(sig.parameters.keys()))
"
```

Expected: imports succeed, signatures printed. Note the actual parameter names for use in Task 4.

- [ ] **Step 3: Verify LLM connection works with DeepSeek**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && python3 -c "
from openhands.sdk import LLM
from pydantic import SecretStr
import os

llm = LLM(
    model='deepseek/deepseek-chat',
    api_key='sk-test-not-real-key',
    base_url='https://api.deepseek.com/anthropic',
)
print('LLM created OK')
"
```

Expected: LLM object created without error.

- [ ] **Step 4: Add to requirements.txt**

Read the installed version and add to requirements:

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && pip show openhands-ai | grep -E '^Name:|^Version:'
```

Edit `requirements.txt`: append `openhands-ai>=X.Y.Z` (replace with actual version).

- [ ] **Step 5: Commit**

```bash
git add requirements.txt
git commit -m "deps: add openhands-ai SDK dependency

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2: Add OpenHands config fields to local_config.py

**Files:**
- Modify: `automation/local_config.py`

- [ ] **Step 1: Add OpenHands configuration fields**

In `automation/local_config.py`, after the existing `OPENHANDS_MODEL = "qwen-max"` line, add:

```python
# OpenHands SDK configuration (new)
OPENHANDS_ENABLED = True
# LiteLLM model string: deepseek/deepseek-chat, qwen/qwen-max, anthropic/claude-sonnet-4-20250514
# OPENHANDS_MODEL is already defined above; reuse it
OPENHANDS_API_KEY = OPENAI_API_KEY  # reuse existing key by default
OPENHANDS_BASE_URL = OPENAI_BASE_URL  # reuse DashScope base URL for Qwen
OPENHANDS_SANDBOX = "local"  # "docker" or "local"; start with local for testing
OPENHANDS_MAX_ITERATIONS = 30
```

- [ ] **Step 2: Commit**

```bash
git add automation/local_config.py
git commit -m "config: add OpenHands SDK settings to local_config.py

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3: Create MCP server exposing CTF tools

**Files:**
- Create: `automation/tools/mcp_server.py`

- [ ] **Step 1: Write the MCP server**

```python
"""MCP server exposing PwnGPT CTF tools to OpenHands SDK Agent."""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make repo root importable
_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationCapabilities
from mcp.server.stdio import stdio_server
from mcp.types import Tool as MCPTool, TextContent

from automation.tools.tool_runner import (
    tool_stack_measure_ret_offset_gdb,
    tool_rop_find_gadgets,
    tool_fmt_measure_write_offset,
    tool_fmt_scan_stack,
    tool_pwntools_got,
    tool_pwntools_symbols,
    tool_disassemble,
)

TOOL_DEFS = [
    {
        "name": "measure_offset",
        "description": "Measure stack offset to return address using GDB. Returns offset in bytes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"}
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "find_gadgets",
        "description": "Find ROP gadgets (pop_rdi, pop_rsi, ret) in the binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"}
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "measure_fmt_offset",
        "description": "Measure format string write offset using pwntools FmtStr. Returns offset value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"}
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "scan_fmt_stack",
        "description": "Scan format string stack positions using AAAA%i$p technique.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"}
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "get_got",
        "description": "Get a GOT entry address for a symbol (default: printf).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"},
                "symbol": {"type": "string", "description": "Symbol name (e.g., printf, puts, system)"},
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "get_symbols",
        "description": "Get binary symbols (win, flag, main, etc.) via pwntools ELF.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"}
            },
            "required": ["binary_path"],
        },
    },
    {
        "name": "disassemble_func",
        "description": "Disassemble a function in the binary (default: main).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Absolute path to the binary"},
                "function": {"type": "string", "description": "Function name to disassemble"},
            },
            "required": ["binary_path"],
        },
    },
]

HANDLERS = {
    "measure_offset": lambda path, **kw: _result_to_text(tool_stack_measure_ret_offset_gdb(path)),
    "find_gadgets": lambda path, **kw: _result_to_text(tool_rop_find_gadgets(path)),
    "measure_fmt_offset": lambda path, **kw: _result_to_text(tool_fmt_measure_write_offset(path)),
    "scan_fmt_stack": lambda path, **kw: _result_to_text(tool_fmt_scan_stack(path)),
    "get_got": lambda path, **kw: _result_to_text(tool_pwntools_got(path, symbol=kw.get("symbol", "printf"))),
    "get_symbols": lambda path, **kw: _result_to_text(tool_pwntools_symbols(path)),
    "disassemble_func": lambda path, **kw: _result_to_text(tool_disassemble(path, function=kw.get("function", "main"))),
}


def _result_to_text(result) -> str:
    """Convert ToolResult to JSON string."""
    return json.dumps(
        {
            "measured_facts": result.measured_facts,
            "unresolved_facts": [dict(x) for x in result.unresolved_facts],
            "notes": result.notes,
        },
        ensure_ascii=False,
    )


async def main():
    server = Server("pwn-tools")

    @server.list_tools()
    async def list_tools():
        return [MCPTool(**t) for t in TOOL_DEFS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        handler = HANDLERS.get(name)
        if not handler:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown_tool:{name}"}))]
        try:
            result_text = handler(**arguments)
        except Exception as exc:
            return [TextContent(type="text", text=json.dumps({"error": str(exc)}))]
        return [TextContent(type="text", text=result_text)]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

- [ ] **Step 2: Verify MCP server starts**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && pip install mcp 2>/dev/null || echo "mcp package check"
python3 -c "from mcp.server import Server; print('MCP SDK OK')"
```

- [ ] **Step 3: Commit**

```bash
git add automation/tools/mcp_server.py
git commit -m "feat: add MCP server exposing CTF tools for OpenHands SDK

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4: Create OpenHandsRunner

**Files:**
- Create: `automation/openhands_runner.py`

- [ ] **Step 1: Write the runner**

```python
"""OpenHands SDK runner — replaces openhands_agent.py."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_repo_root = Path(__file__).resolve().parents[1]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from automation import local_config
from automation.collect.evidence_collector import collect_evidence
from automation.logging_utils import append_run_log
from automation.schemas import Evidence
from automation.verify.verifier import verify_exploit


def _load_problem_text(problem_path: str) -> str:
    try:
        text = Path(problem_path).read_text(encoding="utf-8", errors="ignore")
        if len(text) > 15000:
            text = text[:15000] + "\n... (truncated)\n"
        return text
    except Exception:
        return "(problem text not available)"


def _evidence_to_text(evidence: Evidence, fact_store: Dict[str, Any]) -> str:
    parts = [
        f"Challenge type: {evidence.challenge_type}",
        f"Binary path: {evidence.binary.path}",
        f"Architecture: {evidence.binary.arch}",
        f"Checksec: {evidence.binary.checksec_raw or 'N/A'}",
    ]
    sm = evidence.symbols_map or {}
    plt = sm.get("plt", {})
    got = sm.get("got", {})
    funcs = sm.get("funcs", {})
    if plt:
        parts.append(f"PLT entries: {json.dumps(list(plt.keys()))}")
    if got:
        parts.append(f"GOT entries: {json.dumps(list(got.keys()))}")
    important_funcs = {k: v for k, v in funcs.items()
                       if any(kw in k.lower() for kw in ("main", "win", "flag", "magic", "backdoor",
                                                          "vuln", "call_me", "exec_", "system"))}
    if important_funcs:
        parts.append(f"Key functions: {json.dumps(important_funcs)}")
    bf = evidence.binary_features or {}
    if bf:
        parts.append(f"Binary features: {json.dumps(bf, ensure_ascii=False)}")
    runtime = evidence.runtime or {}
    if runtime.get("libc_path"):
        parts.append(f"Libc path: {runtime['libc_path']}")
    if fact_store:
        parts.append(f"\n=== MEASURED FACTS (fact_store) ===")
        for k, v in fact_store.items():
            parts.append(f"  {k}: {v}")
    return "\n".join(parts)


def _build_system_prompt(challenge_type: str) -> str:
    return """You are a CTF binary exploitation agent.
You have tools available and must iteratively craft a working pwntools exploit.

=== WORKFLOW ===
1. Read the problem text to understand the vulnerability.
2. Plan exploitation strategy based on challenge type.
3. Use MCP tools to MEASURE facts (offsets, gadgets, format string offsets).
4. Write candidate_exploit.py with your exploit code.
5. Run the exploit with: python3 candidate_exploit.py
6. If it fails, read the output, diagnose, FIX the code.
7. Repeat until success.

=== ROP (stack overflow) ===
- ret2text: payload = b"A" * OFFSET + p32/p64(win_addr)
- ret2libc 64-bit: MUST use pop_rdi for first argument. Use rop.call(func, [args]).
- ret2shellcode (NX disabled): shellcode = asm(shellcraft.sh())
- ALWAYS load libc from evidence.runtime.libc_path, NOT binary path.
- Use measured offset/gadget values from fact_store.

=== FMT (format string) ===
- Overwrite var: fmtstr_payload(OFFSET, {addr: value})
- Overwrite GOT (RELRO != full): fmtstr_payload(OFFSET, {binary.got['printf']: libc.symbols['system']})
- Full RELRO: leak libc via %s, overwrite return address instead.
- Use measured fmt_offset from fact_store.

=== GENERAL RULES ===
- from pwn import * includes everything needed.
- Use process(binary.path), NOT remote().
- Stage markers: print("[STAGE] exploit_start") / print("[STAGE] before_interactive").
- Avoid unbounded recv/recvall. Use sendlineafter() with IO prompts.
- Output Python code in a file called candidate_exploit.py."""


def _build_initial_prompt(evidence: Evidence, problem_text: str, fact_store: dict) -> str:
    return f"""## Problem
{problem_text}

## Evidence
{_evidence_to_text(evidence, fact_store)}

## Instructions
FIRST: Use MCP tools to measure any facts you need (offsets, gadgets, format string positions).
THEN: Write your exploit to candidate_exploit.py using FileEditorTool.
FINALLY: Run the exploit with TerminalTool: python3 candidate_exploit.py

If it crashes, read the error, diagnose, and fix. Iterate until you get a shell or flag."""


def run_openhands_agent(
    evidence: Evidence,
    problem_text: str,
    run_dir: Path,
    event_logger: Callable[[str, dict], None],
) -> Dict[str, Any]:
    """Run OpenHands SDK agent to generate exploit. Returns run report dict."""
    from openhands.sdk import LLM, Agent, Conversation, Tool
    from openhands.tools.terminal import TerminalTool
    from openhands.tools.file_editor import FileEditorTool

    sandbox_type = getattr(local_config, "OPENHANDS_SANDBOX", "local")

    if sandbox_type == "docker":
        from openhands.workspace import DockerWorkspace
        workspace = DockerWorkspace()
    else:
        from openhands.workspace import LocalWorkspace
        workspace = LocalWorkspace()

    model = getattr(local_config, "OPENHANDS_MODEL", "qwen-max")
    api_key = getattr(local_config, "OPENHANDS_API_KEY", "")
    base_url = getattr(local_config, "OPENHANDS_BASE_URL", "")
    max_iters = getattr(local_config, "OPENHANDS_MAX_ITERATIONS", 30)

    llm_kwargs = {"model": model, "api_key": api_key}
    if base_url:
        llm_kwargs["base_url"] = base_url

    llm = LLM(**llm_kwargs)

    agent = Agent(
        llm=llm,
        tools=[Tool(name=TerminalTool.name), Tool(name=FileEditorTool.name)],
        mcp_config={
            "pwn_tools": {
                "command": sys.executable,
                "args": ["-m", "automation.tools.mcp_server"],
                "cwd": str(_repo_root),
            }
        },
    )

    initial_prompt = _build_initial_prompt(evidence, problem_text, {})

    events_file = run_dir / "events.jsonl"

    def on_event(event):
        events_file.write_text(
            json.dumps(event, ensure_ascii=False, default=str) + "\n"
        )

    conversation = Conversation(agent=agent, workspace=workspace)
    conversation.send_message(initial_prompt)

    try:
        conversation.run(max_iterations=max_iters)
    except Exception as exc:
        event_logger("sdk_error", {"error": str(exc)})
        return {
            "run_id": run_dir.name,
            "pipeline": "openhands_sdk",
            "engine": "openhands",
            "challenge_type": evidence.challenge_type,
            "problem": evidence.problem_path,
            "binary": evidence.binary.path,
            "success": False,
            "final_iteration": 0,
            "model_roles": {"agent_model": model},
            "fact_store": {},
            "iterations": [],
            "metrics": {"final_failure_class": "sdk_error"},
        }

    final_response = conversation.agent_final_response() or ""

    # Extract exploit code
    try:
        ws = workspace
        code = ws.read_file("candidate_exploit.py") or ""
    except Exception:
        import re
        m = re.search(r"```(?:python)?\s*\n(.*?)```", final_response, re.DOTALL)
        code = m.group(1).strip() if m else final_response

    epath = run_dir / "candidate_exploit.py"
    epath.write_text(code, encoding="utf-8")

    # Verify
    v = verify_exploit(epath, cwd=_repo_root)
    (run_dir / f"verify_final.txt").write_text(v.to_json())

    iterations = [{"verify": {"success": v.success, "exit_code": v.exit_code}}]

    return {
        "run_id": run_dir.name,
        "pipeline": "openhands_sdk",
        "engine": "openhands",
        "challenge_type": evidence.challenge_type,
        "problem": evidence.problem_path,
        "binary": evidence.binary.path,
        "success": v.success,
        "final_iteration": len(iterations),
        "model_roles": {"agent_model": model},
        "fact_store": {},
        "iterations": iterations,
        "metrics": {
            "final_failure_class": "" if v.success else v.summary,
        },
    }


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="OpenHands SDK agent for CTF pwn")
    p.add_argument("--problem", required=True)
    p.add_argument("--binary", required=True)
    p.add_argument("--challenge-type", required=True, choices=["fmt", "int", "heap", "rop"])
    p.add_argument("--repo-root", required=True)
    p.add_argument("--max-iters", type=int, default=30)
    p.add_argument("--case-id", default="")
    args = p.parse_args()

    root = Path(args.repo_root).resolve()
    sid = args.case_id.strip().replace("/", "-")
    rid = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-ohsdk")
    if sid:
        rid = f"{rid}-{sid}"
    rd = root / "automation" / "runs" / rid
    rd.mkdir(parents=True, exist_ok=True)
    run_log = rd / "run.log"

    def log_event(event: str, data: dict) -> None:
        append_run_log(run_log, event, data)

    ev = collect_evidence(
        problem_path=args.problem,
        binary_path=args.binary,
        challenge_type=args.challenge_type,
        repo_root=root,
    )
    from automation.orchestrate_dual_llm import _ensure_binary_runnable
    _ensure_binary_runnable(str(root / args.binary))

    (rd / "evidence.json").write_text(ev.to_json())
    pt = _load_problem_text(str(root / args.problem))

    rpt = run_openhands_agent(ev, pt, rd, log_event)

    _save_json = lambda p, d: Path(p).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    _save_json(rd / "run_report.json", rpt)

    status = "PASS" if rpt["success"] else "FAIL"
    print(f"[{status}] iteration={rpt['final_iteration']}")
    print(f"evidence={rd / 'evidence.json'}")
    print(f"report={rd / 'run_report.json'}")
    print(f"exploit={rd / 'candidate_exploit.py'}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Syntax check**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && python3 -m py_compile automation/openhands_runner.py
```

Expected: no output (compile succeeds).

- [ ] **Step 3: Commit**

```bash
git add automation/openhands_runner.py
git commit -m "feat: add OpenHandsRunner using official SDK

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 5: Add --engine flag to orchestrate_dual_llm.py

**Files:**
- Modify: `automation/orchestrate_dual_llm.py`

- [ ] **Step 1: Add --engine argument**

In `main()`, after the `--case-id` argument (around line 382), add:

```python
parser.add_argument(
    "--engine",
    choices=["dual", "openhands"],
    default="dual",
    help="Engine mode: dual (tri-LLM planner+executor+decider) or openhands (OpenHands SDK agent).",
)
```

- [ ] **Step 2: Add engine dispatch at the top of main()**

After `args = parser.parse_args()` (line 383), add:

```python
if args.engine == "openhands":
    from automation.openhands_runner import run_openhands_agent, _load_problem_text

    evidence = collect_evidence(
        problem_path=args.problem,
        binary_path=args.binary,
        challenge_type=args.challenge_type,
        repo_root=repo_root,
    )
    _ensure_binary_runnable(str(repo_root / args.binary))
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
```

- [ ] **Step 3: Verify compile and test dry-run**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && python3 -m py_compile automation/orchestrate_dual_llm.py
```

- [ ] **Step 4: Commit**

```bash
git add automation/orchestrate_dual_llm.py
git commit -m "feat: add --engine openhands flag to orchestrator

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 6: Update evaluate.py for SDK engine

**Files:**
- Modify: `automation/evaluate.py`

- [ ] **Step 1: Add SDK orchestrator path for --agent openhands**

In `main()`, replace the existing `--agent openhands` handling (lines 198-199) with:

```python
if args.agent == "openhands":
    args.orchestrator = "automation/openhands_runner.py"
```

And update `--agent` choices and help text:

```python
parser.add_argument(
    "--agent",
    choices=["tri-llm", "openhands"],
    default="tri-llm",
    help="Agent mode: tri-llm (planner+executor+decider) or openhands (OpenHands SDK, single agent).",
)
```

- [ ] **Step 2: Verify run_report.json compat**

The SDK runner already outputs `"engine": "openhands"` in the report. The `_aggregate()` function in evaluate.py reads `report.get("success")` and `report.get("metrics", {})`, which works with both formats. No changes needed in `_aggregate()`.

- [ ] **Step 3: Commit**

```bash
git add automation/evaluate.py
git commit -m "feat: wire --agent openhands to OpenHands SDK runner

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 7: Integration test

**Files:**
- Read: `automation/benchmarks/manifest.example.json`

- [ ] **Step 1: Check for an existing test manifest**

```bash
ls /home/fyc/PwnGPT/automation/benchmarks/
```

If no test manifest exists, create a minimal one:

```bash
cat > /tmp/test_openhands_manifest.json << 'EOF'
[{"problem": "pwn/string/fmt-1/problems.txt", "binary": "pwn/string/fmt-1/fmt1", "challenge_type": "fmt", "name": "fmt-1"}]
EOF
```

- [ ] **Step 2: Run a single test case**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && cd /home/fyc/PwnGPT && python3 automation/orchestrate_dual_llm.py \
  --engine openhands \
  --problem pwn/string/fmt-1/problems.txt \
  --binary pwn/string/fmt-1/fmt1 \
  --challenge-type fmt \
  --repo-root /home/fyc/PwnGPT \
  --max-iters 6 \
  --case-id fmt-1-quick 2>&1 | tail -20
```

- [ ] **Step 3: Verify output files exist**

```bash
# Find the latest run directory
LATEST=$(ls -td /home/fyc/PwnGPT/automation/runs/*ohsdk* | head -1)
echo "Latest run: $LATEST"
ls -la "$LATEST/"
# Check events.jsonl exists and is non-empty
wc -l "$LATEST/events.jsonl" 2>/dev/null || echo "events.jsonl not found (may be in workspace)"
cat "$LATEST/run_report.json" | python3 -m json.tool | head -20
```

- [ ] **Step 4: Debug and fix any issues**

If the test fails, check `run.log` and `events.jsonl` for error messages. Common issues:
- MCP server connection: verify `mcp` package is installed
- LLM authentication: verify API key in `local_config.py`
- Workspace file access: if using LocalWorkspace, verify cwd is correct

Document any fixes needed in `openhands_runner.py`.

- [ ] **Step 5: Commit**

```bash
git add -A  # add any test results or fixes
git commit -m "test: integration test results and fixes for SDK runner

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 8: Cleanup deprecated files

**Files:**
- Deprecate: `automation/openhands_agent.py`
- Deprecate: `automation/openhands_adapter.py`

- [ ] **Step 1: Verify nothing imports the deprecated files**

```bash
grep -r "openhands_agent\|openhands_adapter" /home/fyc/PwnGPT/automation/ --include="*.py" | grep -v "openhands_runner" | grep -v ".pyc"
```

Expected: no results (or only self-references in the deprecated files themselves, and the reference in evaluate.py which we already updated).

- [ ] **Step 2: Move old files to a deprecation notice**

Add a comment at the top of `openhands_agent.py`:

```python
# DEPRECATED: Replaced by openhands_runner.py (OpenHands SDK integration).
# This file is kept for reference only. Use --engine openhands instead.
# See docs/superpowers/specs/2026-05-19-openhands-sdk-integration-design.md
```

And in `openhands_adapter.py`:

```python
# DEPRECATED: Adapter logic merged into openhands_runner.py.
# This file is kept for reference only.
```

- [ ] **Step 3: Commit**

```bash
git add automation/openhands_agent.py automation/openhands_adapter.py
git commit -m "chore: deprecate openhands_agent.py and openhands_adapter.py

These are replaced by automation/openhands_runner.py using the official
OpenHands SDK. Kept for reference.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 9: Final verification and documentation update

**Files:**
- Modify: `automation/README.md`

- [ ] **Step 1: Update README with SDK usage**

After the "Quick Start" section in `automation/README.md`, add:

```markdown
## OpenHands SDK Mode (New)

Uses the official OpenHands Software Agent SDK for exploit generation with Docker sandboxing:

```bash
python3 automation/orchestrate_dual_llm.py \
  --problem pwn/stack/rop-1/problems.txt \
  --binary pwn/stack/rop-1/rop1 \
  --challenge-type rop \
  --engine openhands
```

Or directly:

```bash
python3 automation/openhands_runner.py \
  --problem pwn/stack/rop-1/problems.txt \
  --binary pwn/stack/rop-1/rop1 \
  --challenge-type rop \
  --repo-root /home/fyc/PwnGPT
```

CTF tools are exposed via MCP. The agent can measure offsets, find gadgets, scan format strings.
Output is compatible with `evaluate.py`.
```

- [ ] **Step 2: Run one batch evaluation to confirm compat**

```bash
source /home/fyc/PwnGPT/.venv/bin/activate && cd /home/fyc/PwnGPT && python3 automation/evaluate.py \
  --manifest /tmp/test_openhands_manifest.json \
  --repo-root /home/fyc/PwnGPT \
  --max-iters 2 \
  --agent openhands 2>&1
```

- [ ] **Step 3: Commit**

```bash
git add automation/README.md
git commit -m "docs: document OpenHands SDK mode in README

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```
