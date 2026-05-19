# OpenHands SDK Integration Design

**Date:** 2026-05-19
**Status:** Ready for implementation

## Goal

Replace `automation/openhands_agent.py` (self-built CodeAct agent) with the official OpenHands Software Agent SDK. PwnGPT retains evidence collection, benchmark orchestration, and result aggregation; OpenHands SDK handles exploit generation + debugging inside Docker sandboxes.

## Architecture

```
PwnGPT (host)                         OpenHands SDK (Docker)
───────────────                       ──────────────────────
EvidenceCollector ──┐
  checksec          │
  ROPgadgets        │── evidence.json ──→ DockerWorkspace
  strings           │   problem.txt            │
  PLT               │   binary              CodeAct Agent
                    │                         ├─ read problem
OpenHandsRunner ────┘                         ├─ call MCP tools (→ host)
                                              ├─ write exploit
ResultCollector ←── events.jsonl ←────────────├─ execute → debug → fix
                    run_report.json           └─ output final exploit
```

### What stays

| Module | Rationale |
|---|---|
| `collect/evidence_collector.py` | Rule-based measurement, stable, no LLM dependency |
| `verify/verifier.py` | Final exploit verification, simple and reliable |
| `schemas.py` | `Evidence` / `VerifyResult` unchanged |
| `evaluate.py` | Batch orchestration, add `--engine openhands` flag |
| `tools/tool_runner.py` | Existing GDB/ROPgadget/fmt tools, exposed via MCP |

### What changes

| Module | Change |
|---|---|
| `local_config.py` | Add `OPENHANDS_MODEL`, `OPENHANDS_API_KEY`, `OPENHANDS_SANDBOX`, `OPENHANDS_MAX_ITERATIONS` |
| `orchestrate_dual_llm.py` | Add `--engine` flag (default `dual`, new `openhands`) |
| `evaluate.py` | Branch on `engine` field in report, minor compat handling |

### What's added

| File | Purpose | Est. lines |
|---|---|---|
| `automation/openhands_runner.py` | Core runner: config → Agent/Conversation/DockerWorkspace → result extraction | ~150 |
| `automation/tools/mcp_server.py` | MCP wrapper exposing existing tools (measure_offset, find_gadgets, etc.) | ~50 |

### What's deprecated

| File | Reason |
|---|---|
| `automation/openhands_agent.py` | Replaced by `openhands_runner.py` |
| `automation/openhands_adapter.py` | Adapter logic merged into runner |

## Custom CTF Tools

Tools are exposed via MCP protocol. The MCP server runs on the host, Agent runs in Docker, communication via JSON-RPC.

| Tool | Purpose |
|---|---|
| `measure_offset` | GDB measure ret address offset |
| `find_gadgets` | ROPgadget search (pop_rdi, ret, etc.) |
| `measure_fmt_offset` | Format string write offset |
| `scan_fmt_stack` | Format string stack scan (AAAA%i$p) |
| `get_got` | Read GOT entry address |
| `get_symbols` | pwntools symbol table |
| `disassemble` | Disassemble a function |

## Data Flow

```
1. COLLECT (host, ~5s)
   inputs: binary, problems.txt
   outputs: runs/<id>/evidence.json

2. SETUP (host)
   assemble system prompt + task prompt
   create DockerWorkspace, copy files in

3. AGENT LOOP (Docker, multi-turn)
   LLM calls (DeepSeek/Qwen API via LiteLLM)
   tool calls → MCP → host GDB/ROPgadget
   write → execute → observe → diagnose → fix
   events streamed to events.jsonl

4. EXTRACT (host)
   parse events.jsonl for final exploit code
   save to runs/<id>/candidate_exploit.py

5. VERIFY (host, ~3s)
   run final verification
   output runs/<id>/run_report.json
```

## File Layout per Run

```
automation/runs/<run_id>/
├── evidence.json          # collected binary metadata
├── problem.txt            # copy of problem description
├── events.jsonl           # OpenHands event stream (JSONL)
├── candidate_exploit.py   # final exploit code
├── run_report.json        # compatible with evaluate.py
└── run.log                # human-readable stage trace
```

## Configuration

```python
# automation/local_config.py additions
OPENHANDS_ENABLED = True
OPENHANDS_MODEL = "deepseek/deepseek-chat"     # LiteLLM model string
OPENHANDS_API_KEY = "sk-..."                   # LLM API key
OPENHANDS_BASE_URL = "..."                     # optional, for custom endpoints
OPENHANDS_SANDBOX = "docker"                   # "docker" | "local"
OPENHANDS_MAX_ITERATIONS = 30
```

## Error Handling

| Scenario | Handling |
|---|---|
| Agent exceeds max iterations | `conversation.run()` honors `max_iterations`; mark `failure_reason: max_iterations` |
| LLM rate limit (429) | LiteLLM auto-retry, no PwnGPT intervention needed |
| Docker unavailable | Catch `DockerWorkspace` init error, fallback to `LocalWorkspace` |
| No exploit code in output | Regex extract from last file_edit event; fallback `failure_reason: no_code` |
| Sandbox resource exhaustion | Docker default limits; catch exception, mark `failure_reason: sandbox_error` |
| Empty events.jsonl | Mark `failure_reason: empty_output` |

## Backward Compatibility

`orchestrate_dual_llm.py` and `evaluate.py` default to existing behavior:

```bash
# Existing tri-LLM pipeline (unchanged)
python3 automation/orchestrate_dual_llm.py --problem ... --binary ... --challenge-type fmt

# New OpenHands SDK path
python3 automation/orchestrate_dual_llm.py --problem ... --binary ... --challenge-type fmt --engine openhands
```

`run_report.json` adds `"engine": "openhands"` field; `evaluate.py` branches on this field without breaking existing report parsing.

## Dependencies

- `openhands-sdk` (new pip dependency)
- Docker (for DockerWorkspace; optional with LocalWorkspace fallback)
- Existing: `pwntools`, `openai`, `langchain`
