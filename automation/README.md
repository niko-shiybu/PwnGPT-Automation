# Automation MVP

This folder contains a local-first tri-LLM automation pipeline for pwn task solving:

1. Collect evidence from binary and runtime prompts.
2. Analyze missing fields by challenge type.
3. Probe missing fields (placeholder for LLM-driven probing).
4. Generate exploit (placeholder for LLM-driven generation).
5. Verify exploit run output and classify failures.
6. Retry with updated evidence.

## Runtime Requirements

- Python environment with:
  - `openai` package (for dynamic Probe/Exploit LLM mode)
  - `pwntools` package (for running generated exploit scripts)
- Config priority:
  1. `automation/local_config.py` (recommended for your local machine)
  2. Environment variables (fallback)

In `automation/local_config.py`, set:
- `OPENAI_API_KEY` (required for LLM mode)
- `OPENAI_BASE_URL` (optional; OpenRouter/OpenAI-compatible endpoint)
- `AUTOMATION_MODEL` (optional; default `openai/gpt-4o-2024-11-20`)

## Quick Start

```bash
python3 automation/orchestrate_dual_llm.py \
  --problem pwn/string/fmt-1/problems.txt \
  --binary pwn/string/fmt-1/fmt1 \
  --challenge-type fmt
```

Outputs are stored under:

- `automation/runs/<timestamp>/evidence.json`
- `automation/runs/<timestamp>/run_report.json`
- `automation/runs/<timestamp>/candidate_exploit.py`
- `automation/runs/<timestamp>/run.log` (full stage-by-stage trace)

## Batch Evaluation (Phase 8)

Run a benchmark suite across multiple challenge cases:

```bash
python3 automation/evaluate.py \
  --manifest automation/benchmarks/manifest.example.json \
  --max-iters 2
```

Benchmark output JSON will be written to:

- `automation/benchmarks/<timestamp>-benchmark.json`

Each benchmark report includes:

- success rate and median retries
- dominant failure class
- evidence completeness ratio
- deterministic probe coverage ratio
- per-case run report references and output tails

## Notes

- This pipeline is local-only and rule-first for evidence collection.
- The default orchestrator is `orchestrate_dual_llm.py`.
- If an LLM role is unavailable or fails, that stage falls back to a minimal safe result.
- Full pipeline events (LLM request/response preview, execution output, verify results)
  are appended as JSON-lines into `run.log`.
