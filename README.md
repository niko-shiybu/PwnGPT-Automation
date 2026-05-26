# PwnGPT

LLM-based automatic CTF binary exploitation.

## Quick Start

```bash
source .venv/bin/activate
pip install -r requirements.txt

# Single challenge
python3 automation/openhands_agent.py \
  --problem pwn/stack/rop-1/problems.txt \
  --binary pwn/stack/rop-1/rop1 \
  --challenge-type rop --max-iters 5 \
  --repo-root /path/to/PwnGPT

# Batch evaluation
python3 automation/evaluate.py \
  --manifest automation/benchmarks/manifest_rop.json \
  --agent openhands --max-iters 5 --timeout 0
```

## Configuration

Copy `automation/local_config.example.py` to `automation/local_config.py` and fill in API keys.

## Architecture

```
automation/
├── openhands_agent.py          # Main pipeline: COLLECT → RETRIEVE → PLAN → MEASURE → WRITE → VERIFY → FIX
├── evaluate.py                 # Batch evaluation runner
├── llm_client.py               # LLM client (OpenAI-compatible)
├── schemas.py                  # Data structures
├── openhands_adapter.py        # Evidence/text conversion + exploit hardening
├── collect/evidence_collector.py  # Binary evidence collection
├── executor/executor_agent.py  # Measurement dispatch
├── verify/verifier.py          # Exploit verification
├── audit/                      # Static code audit
├── exploit/harden.py           # Deterministic exploit code hardening
└── tools/tool_runner.py        # Measurement tools (GDB offset, ROP gadgets, FMT offset)

retrieve/
├── retrieve_main.py            # Strategy retrieval from knowledge base
├── web_search.py               # Web search client
├── query_builder.py            # Evidence → search query construction
├── strategy_scorer.py          # Candidate strategy scoring
└── recipe_extractor.py         # Exploit recipe extraction
```

## Challenge Dataset

19 CTF challenges under `pwn/`: ROP (1-10), FMT (1-5), INT (1-2), HEAP (1-2).
