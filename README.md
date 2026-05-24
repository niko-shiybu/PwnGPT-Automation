# PwnGPT
Caputre the flag with Large Language Models. Constructed by langgraph, and I learn a lot from langgraph doument, thanks for them.

## New: Tri-LLM Automation Framework (`automation/`)

A modular pipeline for automatic exploit generation with Planner, Executor, ExploitWriter, Verifier, and Decider stages.

### Quick Start

```bash
source .venv/bin/activate
pip install -r requirements.txt

# Single challenge
python3 automation/openhands_agent.py \
  --problem pwn/stack/rop-1/problems.txt \
  --binary pwn/stack/rop-1/rop1 \
  --challenge-type rop --max-iters 5 \
  --repo-root /path/to/PwnGPT


```

### Configuration

Edit `automation/local_config.py` for API keys and model settings.

### Framework Architecture

```
automation/
├── openhands_agent.py          # 5-step pipeline (Planner→Executor→ExploitWriter→Verify→Decider)
├── orchestrator_dual_llm.py    # Original tri-LLM orchestrator
├── evaluate.py                 # Batch evaluation runner
├── llm_client.py               # LLM client (OpenAI-compatible API)
├── local_config.py             # Configuration
├── schemas.py                  # Data structures
├── tools/tool_runner.py        # Deterministic measurement tools
├── collector/evidence_collector.py  # Binary evidence collection
├── planner/planner_agent.py    # Strategy planning prompts
├── executor/executor_agent.py  # Measurement dispatch
├── decider/decider_agent.py    # Failure diagnosis (tri-LLM)
├── verify/verifier.py          # Exploit verification
└── audit/                      # Static code audit
```


