from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from automation import local_config


class LLMClientError(RuntimeError):
    pass


@dataclass
class LLMResult:
    model: str
    raw_content: str
    extracted_content: str


ROLE_PLANNER = "planner"
ROLE_EXECUTOR = "executor"
ROLE_DECIDER = "decider"
ROLE_DEFAULT = "default"


def _extract_code(text: str) -> str:
    stripped = text.strip()
    if "```" not in stripped:
        return stripped
    parts = stripped.split("```")
    # Prefer first fenced body.
    for chunk in parts:
        c = chunk.strip()
        if not c:
            continue
        if c.startswith("python"):
            return c[len("python") :].strip()
        if c.startswith("json"):
            return c[len("json") :].strip()
        if "\n" in c:
            return c
    return stripped


def _resolve_model_for_role(role: str) -> str:
    role = (role or ROLE_DEFAULT).strip().lower()
    if role == ROLE_PLANNER:
        return (
            getattr(local_config, "AUTOMATION_MODEL_PLANNER", "")
            or os.environ.get("AUTOMATION_MODEL_PLANNER", "")
            or getattr(local_config, "AUTOMATION_MODEL", "")
            or os.environ.get("AUTOMATION_MODEL", "openai/gpt-4o-2024-11-20")
        ).strip()
    if role == ROLE_EXECUTOR:
        return (
            getattr(local_config, "AUTOMATION_MODEL_EXECUTOR", "")
            or os.environ.get("AUTOMATION_MODEL_EXECUTOR", "")
            or getattr(local_config, "AUTOMATION_MODEL", "")
            or os.environ.get("AUTOMATION_MODEL", "openai/gpt-4o-2024-11-20")
        ).strip()
    if role == ROLE_DECIDER:
        return (
            getattr(local_config, "AUTOMATION_MODEL_DECIDER", "")
            or os.environ.get("AUTOMATION_MODEL_DECIDER", "")
            or getattr(local_config, "AUTOMATION_MODEL", "")
            or os.environ.get("AUTOMATION_MODEL", "openai/gpt-4o-2024-11-20")
        ).strip()
    return (
        getattr(local_config, "AUTOMATION_MODEL", "")
        or os.environ.get("AUTOMATION_MODEL", "openai/gpt-4o-2024-11-20")
    ).strip()


def chat_complete_detailed(
    prompt: str,
    system_prompt: str,
    *,
    temperature: float = 0.1,
    role: str = ROLE_DEFAULT,
) -> LLMResult:
    """
    Thin OpenAI-compatible client wrapper.
    Reads:
    - OPENAI_API_KEY (required)
    - OPENAI_BASE_URL (optional)
    - AUTOMATION_MODEL (optional, default openai/gpt-4o-2024-11-20)
    """
    try:
        from openai import OpenAI
    except Exception as exc:  # pragma: no cover
        raise LLMClientError(f"openai package unavailable: {exc}") from exc

    # Priority: code config -> environment variable.
    api_key = (getattr(local_config, "OPENAI_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")).strip()
    if not api_key:
        raise LLMClientError("OPENAI_API_KEY is required (set in automation/local_config.py or env)")

    model = _resolve_model_for_role(role)
    base_url: Optional[str] = (
        getattr(local_config, "OPENAI_BASE_URL", "")
        or os.environ.get("OPENAI_BASE_URL", "")
        or None
    )

    client = OpenAI(api_key=api_key, base_url=base_url)
    resp = client.chat.completions.create(
        model=model,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    )
    content = (resp.choices[0].message.content or "").strip()
    if not content:
        raise LLMClientError("empty LLM response")
    return LLMResult(model=model, raw_content=content, extracted_content=_extract_code(content))


def chat_complete(prompt: str, system_prompt: str, *, temperature: float = 0.1) -> str:
    return chat_complete_detailed(prompt, system_prompt, temperature=temperature).extracted_content
