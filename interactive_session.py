#!/usr/bin/env python3
"""
Human-in-the-loop exploit generation: each outer round runs the full LangGraph
(generate -> check_code -> reflect/loop). Logs to sessions/<id>/interaction_log.txt.
Round 1 runs automatically (default pwntools question). Round 2+ require a non-empty
hint read from /dev/tty (Linux) so stdin buffering does not skip prompts.
Exit: Ctrl+C or EOF on hint input.
"""
from __future__ import annotations

import argparse
import json
import os
import select
import sys
import uuid
from datetime import datetime

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _ensure_repo_cwd() -> None:
    os.chdir(_REPO_ROOT)


def _append_jsonl(path: str, record: dict) -> None:
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)


def _read_hint_from_tty(prompt: str) -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        tty = open("/dev/tty", "r", encoding="utf-8", errors="replace")
    except OSError:
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\r\n")
    try:
        fd = tty.fileno()
        parts: list[str] = []
        while True:
            line = tty.readline()
            if line == "":
                raise EOFError
            parts.append(line.rstrip("\r\n"))
            readable, _, _ = select.select([fd], [], [], 0)
            if not readable:
                break
        return "\n".join(parts)
    finally:
        tty.close()


def load_problem_text(llmgraph, path: str) -> str:
    doc = llmgraph.get_decompilefile(path)[0]
    return doc.page_content


def _resolve_binary_under_repo(repo_root: str, binary_arg: str) -> str:
    b = binary_arg.strip()
    if not b:
        return ""
    if os.path.isabs(b):
        return os.path.normpath(b)
    return os.path.normpath(os.path.join(repo_root, b.lstrip("./")))


def _format_generation(gen) -> str:
    if gen is None:
        return "(none)"
    if hasattr(gen, "prefix"):
        return f"[prefix]\n{gen.prefix}\n\n[imports]\n{gen.imports}\n\n[code]\n{gen.code}\n"
    return repr(gen)


def _format_messages(msgs) -> str:
    if not isinstance(msgs, list):
        return repr(msgs)
    lines = []
    for m in msgs:
        if isinstance(m, tuple) and len(m) == 2:
            role, content = m[0], m[1]
            c = content if isinstance(content, str) else repr(content)
            lines.append(
                f"  ({role!r}, {c[:2000]!r}...)"
                if len(c) > 2000
                else f"  ({role!r}, {c!r})"
            )
        else:
            lines.append(f"  {m!r}")
    return "\n".join(lines)


def main() -> None:
    _ensure_repo_cwd()
    from processing import llmgraph

    ap = argparse.ArgumentParser(description="Interactive multiturn PwnGPT session")
    ap.add_argument(
        "problem",
        nargs="?",
        default="./pwn/stack/rop-1/rop1de.c",
        help="Path to decompiled C (e.g. pwn/stack/rop-1/rop1de.c)",
    )
    ap.add_argument(
        "--binary",
        default="",
        help="Challenge binary path (relative to repo root or absolute); injected into info for the model",
    )
    ap.add_argument(
        "--jsonl",
        default="",
        help="Optional JSONL log path (append one JSON object per event)",
    )
    args = ap.parse_args()

    info = load_problem_text(llmgraph, args.problem)
    bin_abs = _resolve_binary_under_repo(_REPO_ROOT, args.binary)
    if bin_abs:
        info = (
            f"The binary path for this challenge is: {bin_abs}\n"
            f"(run exploit code from repo root {_REPO_ROOT} so paths match.)\n\n"
            + info
        )

    session_id = str(uuid.uuid4())[:8]
    session_root = os.path.join(_REPO_ROOT, "sessions", session_id)
    os.makedirs(session_root, exist_ok=True)
    interaction_log = os.path.join(session_root, "interaction_log.txt")
    jsonl_path = args.jsonl.strip() or None

    with open(interaction_log, "w", encoding="utf-8") as f:
        f.write(
            f"session_id: {session_id}\n"
            f"started_at: {datetime.now().isoformat(timespec='seconds')}\n"
            f"problem_file: {args.problem}\n"
            f"binary: {bin_abs or '(not set)'}\n"
            f"\n{'=' * 72}\nFULL INFO SENT TO GRAPH\n{'=' * 72}\n\n"
            f"{info}\n"
        )

    def append_log(text: str) -> None:
        with open(interaction_log, "a", encoding="utf-8") as f:
            f.write(text)

    print(f"Session directory: {session_root}")
    print(f"Full interaction log: {interaction_log}")
    if jsonl_path:
        print(f"JSONL mirror: {jsonl_path}")
    print(
        "Round 1: automatic (default question). Round 2+: non-empty hint from terminal.\n"
        "Hints read from /dev/tty when available. Ctrl+C to exit.\n"
    )

    last_state = None
    round_num = 0
    try:
        while True:
            round_num += 1
            hint = ""
            if round_num == 1:
                append_log(
                    f"\n{'=' * 72}\nOUTER ROUND 1 — automatic (default question)\n{'=' * 72}\n"
                )
                if jsonl_path:
                    _append_jsonl(
                        jsonl_path,
                        {"kind": "user_input", "round": 1, "text": "", "auto": True},
                    )
            else:
                print("\n" + "=" * 72, flush=True)
                print(f"Round {round_num} — enter a non-empty hint", flush=True)
                print("=" * 72 + "\n", flush=True)
                try:
                    hint = _read_hint_from_tty("Your hint: ")
                except EOFError:
                    append_log("\nEOF on input — session end\n")
                    if jsonl_path:
                        _append_jsonl(jsonl_path, {"kind": "session_end", "reason": "eof"})
                    break
                while not (hint or "").strip():
                    try:
                        hint = _read_hint_from_tty("Hint required (non-empty): ")
                    except EOFError:
                        append_log("\nEOF on input — session end\n")
                        if jsonl_path:
                            _append_jsonl(jsonl_path, {"kind": "session_end", "reason": "eof"})
                        hint = None
                        break
                if hint is None:
                    break
                append_log(
                    f"\n{'=' * 72}\nOUTER ROUND {round_num} — user hint\n{'=' * 72}\n{hint}\n"
                )
                if jsonl_path:
                    _append_jsonl(
                        jsonl_path,
                        {"kind": "user_input", "round": round_num, "text": hint},
                    )

            if jsonl_path:
                _append_jsonl(jsonl_path, {"kind": "round_start", "round": round_num})

            print(f"\n[Round {round_num}] Running graph ...", flush=True)

            if round_num == 1:
                last_state = llmgraph.run_graph_round(
                    info,
                    prior_messages=None,
                    user_message=None,
                    append_default_question=True,
                )
            else:
                last_state = llmgraph.run_graph_round(
                    info,
                    prior_messages=last_state["messages"],
                    user_message=hint.strip(),
                    append_default_question=False,
                )

            err = last_state.get("error")
            gen = last_state.get("generation")
            append_log(
                f"\n{'=' * 72}\nOUTER ROUND {round_num} — summary\n{'=' * 72}\n"
                f"error: {err!r}\niterations: {last_state.get('iterations')!r}\n\n"
                f"--- generation ---\n{_format_generation(gen)}\n\n"
                f"--- messages ---\n{_format_messages(last_state.get('messages'))}\n"
            )
            if jsonl_path:
                _append_jsonl(
                    jsonl_path,
                    {
                        "kind": "round_end",
                        "round": round_num,
                        "error": err,
                        "iterations": last_state.get("iterations"),
                    },
                )

            print(f"\n--- Round {round_num} ---\nerror: {err}\niterations: {last_state.get('iterations')}")
            print(_format_generation(gen))
            if err == "no":
                print(
                    "\n[Signal] error=no (check passed). Add another hint or Ctrl+C.\n",
                    flush=True,
                )

            append_log(
                f"\nended_at: {datetime.now().isoformat(timespec='seconds')}\n{'=' * 72}\n"
            )

    except KeyboardInterrupt:
        append_log("\nKeyboardInterrupt — session end\n")
        if jsonl_path:
            _append_jsonl(
                jsonl_path, {"kind": "session_end", "reason": "keyboard_interrupt"}
            )
        print("\n[Ctrl+C] Session ended.")


if __name__ == "__main__":
    main()
