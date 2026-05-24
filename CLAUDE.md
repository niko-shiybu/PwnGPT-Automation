# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
请始终使用简体中文与我对话，并在回答时保持专业、简洁。

## Project overview

PwnGPT is a research system for automatic CTF binary exploitation (pwn) exploit generation using LLMs. It takes decompiled C code (from Hex-Rays 8.3), constructs a problem description with binary metadata (checksec, ROPgadgets, strings, PLT), and uses a LangGraph agent to iteratively generate + check + reflect on pwntools exploit scripts.

A companion paper was published at ACL 2025: [PwnGPT: Automatic Exploit Generation Based on Large Language Models](https://aclanthology.org/2025.acl-long.562/).

## Environment setup

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

The project uses the virtual environment at `.venv/`. Dependencies: langchain, langgraph, pydantic, chromadb, dashscope, pwntools.

### Required environment variables

- `OPENAI_API_KEY` — used for both OpenAI-compatible APIs and DashScope embeddings (Qwen models go through DashScope's OpenAI-compatible endpoint)
- `INFO_EXTRACTION_KEY` (optional) — separate key for information extraction LLM calls; falls back to `OPENAI_API_KEY` if unset. Set to `0` to use library-default env handling.
- `CHECKSEC_CMD` (optional) — override path to the checksec binary (e.g. `~/.local/bin/checksec`). Falls back to `~/.local/bin/checksec` (Go version) then `checksec` on PATH.

### checksec

A Go-based checksec binary is included in [checksec.sh/](checksec.sh/). Build with:

```bash
cd checksec.sh && make
```

Install into `~/.local/bin/checksec` or set `CHECKSEC_CMD`.

## Running evaluations

The main entry points for benchmark evaluation are [llm4ctf.py](llm4ctf.py) and [benchmark.py](benchmark.py). Both edit `processing/llmgraph.py` globals (`expt_llm`, `base`, `max_iterations`, `flag`) to configure the model and behavior.

```bash
# Run the main structured-output evaluation (all categories: stack/string/integer/heap)
python llm4ctf.py

# Run benchmark evaluations (analysis-only stages, no code generation)
python benchmark.py
```

**Resume behavior:** `evaluate_llm_structured_output()` skips cases where `result_4_raw.txt` or `error.txt` already exists. Pass `force_rerun=True` to re-run.

## Architecture

### Two-stage pipeline (evaluation path)

1. **Information extraction** ([preprocessing/constructInfo.py](preprocessing/constructInfo.py)): Given a decompiled C file, the LLM identifies key functions. Then binary metadata is gathered via shell commands (checksec, strings, ROPgadget, readelf for PLT). These are assembled into a `problem.txt` with numbered sections.

2. **Exploit generation** ([processing/llmgraph.py](processing/llmgraph.py)): A LangGraph `StateGraph` with nodes:
   - `generate` — LLM produces structured output (`prefix`, `imports`, `code`) via `with_structured_output`
   - `check_code` — writes the generated code to [ctftest.py](ctftest.py) and [ctftest_import.py](ctftest_import.py), runs them in a subprocess with a 20s timeout
   - `reflect` — LLM reflects on errors before retrying
   - Loop controlled by `max_iterations` and the `flag` variable (`"reflect"` or `"do not reflect"`)

   The model and API base are configured via globals `expt_llm` and `base` at the top of [processing/llmgraph.py](processing/llmgraph.py#L26-L28). Qwen models use `https://dashscope.aliyuncs.com/compatible-mode/v1`, OpenAI models use their native endpoint or OpenRouter.

### Key modules

| Module | Purpose |
|--------|---------|
| [preprocessing/file.py](preprocessing/file.py) | `PwnInfo` class: enumerates challenge directories (e.g., `pwn/stack/rop-1`, `rop-2`, ...) and resolves paths to C files and binaries |
| [preprocessing/analysis.py](preprocessing/analysis.py) | Regex-based C function extraction: parses function boundaries by brace counting, builds call graphs |
| [preprocessing/retrieval.py](preprocessing/retrieval.py) | Chroma vector store with DashScope embeddings for retrieving similar challenge solutions |
| [preprocessing/constructInfo.py](preprocessing/constructInfo.py) | Assembles the problem description: function extraction, checksec, strings, ROPgadgets, PLT entries |
| [processing/llmgraph.py](processing/llmgraph.py) | Core LangGraph agent: `MainChain` for structured code generation, `run_graph()` / `run_direct()` entry points, `subprocess_check()` for sandboxed exploit execution |

### Challenge benchmark layout

Challenges live under `pwn/{category}/{type}-{n}/`. Categories:
- **stack/** — ROP (ret2text, ret2libc, ret2shellcode, canary) — `rop-1` through `rop-10`
- **string/** — Format string (write, read, hijack retaddr, GOT overwrite) — `fmt-1` through `fmt-5`
- **integer/** — Integer overflow — `int-1`, `int-2`
- **heap/** — UAF, heap overflow — `heap-1`, `heap-2`

Each challenge directory contains: the binary, `de.c` (decompiled), `problems.txt` (assembled problem description), and subdirectories per model with `result_*.txt` files.

### Interactive sessions

[interactive_session.py](interactive_session.py) provides human-in-the-loop multi-turn exploit generation. Each round runs the full LangGraph pipeline; after the first automatic round, the user provides hints via `/dev/tty`. Sessions are logged to `sessions/<id>/interaction_log.txt`.

```bash
python interactive_session.py pwn/stack/rop-1/rop1de.c --binary pwn/stack/rop-1/rop1
```

### automation/ — tri-LLM pipeline

A newer, more modular pipeline ([automation/README.md](automation/README.md)) with collect → analyze → probe → exploit → verify → retry stages. Uses its own LLM client ([automation/llm_client.py](automation/llm_client.py)) with config from [automation/local_config.py](automation/local_config.py).

```bash
python3 automation/orchestrate_dual_llm.py \
  --problem pwn/string/fmt-1/problems.txt \
  --binary pwn/string/fmt-1/fmt1 \
  --challenge-type fmt
```

Batch evaluation:
```bash
python3 automation/evaluate.py --manifest automation/benchmarks/manifest.example.json --max-iters 2
```

### nyuctf_agents/ — NYU CTF agents (separate project)

A separate sub-project for the NYU CTF Bench. Contains D-CIPHER (multi-agent: planner + executor + auto-prompter) and the NYU baseline agent. Runs CTF challenges inside Docker containers. See [nyuctf_agents/README.md](nyuctf_agents/README.md) for setup.

### cve/ — CVE exploit cases

Dockerized vulnerable environments for CVE-2011-2523 (vsftpd backdoor) and CVE-2018-10933 (libssh auth bypass). These are treated as pwn challenges with decompiled binaries.

## Important implementation details

- The model config is in [processing/llmgraph.py](processing/llmgraph.py) globals `expt_llm` and `base` — not command-line flags. Change these directly to switch models.
- Qwen models don't support `json_schema` structured output mode, so the code uses OpenAI-style tool calling for `with_structured_output`. Some models (like o1-preview) also lack this support — the code falls back to `run_direct()` which returns raw text.
- When decompiled code exceeds 128k tokens, the pipeline falls back to `static_analysis()` which extracts only key functions via regex parsing + LLM relevance filtering, rather than sending the full file.
- The `code` Pydantic model expects three fields: `prefix` (explanation), `imports` (import statements), `code` (the exploit logic). Generated code is written to temporary files ([ctftest.py](ctftest.py), [ctftest_import.py](ctftest_import.py)) and executed in a subprocess for validation.
