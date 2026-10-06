"""Turn a Jev HTTP outcome into the verdict dictionary.

Pure functions: no HTTP, no clock, so every branch is testable directly.
"""

from __future__ import annotations

import math
from typing import Any

# Documented price: $42 per billion input tokens; output is free.
USD_PER_INPUT_TOKEN = 0.042 / 1_000_000

_UNAVAILABLE_CODES = {408, 429, 529}
_NULLED_WHEN_NOT_OK = ("attack", "answers", "model", "input_tokens", "cost_usd")


def verdict(
    status: str,
    *,
    latency_ms: float,
    truncated: bool = False,
    error: str | None = None,
    attack: float | None = None,
    answers: dict[str, float] | None = None,
    model: str | None = None,
    input_tokens: int | None = None,
    cost_usd: float | None = None,
) -> dict:
    """Build a verdict with all nine keys. Non-ok verdicts carry no Jev data."""
    out: dict[str, Any] = {
        "status": status,
        "attack": attack,
        "answers": answers,
        "model": model,
        "input_tokens": input_tokens,
        "cost_usd": cost_usd,
        "latency_ms": round(float(latency_ms), 1),
        "truncated": truncated,
        "error": error,
    }
    if status != "ok":
        for key in _NULLED_WHEN_NOT_OK:
            out[key] = None
    return out


def cost_usd(input_tokens: int) -> float:
    """Cost of one call in dollars, from the documented input-token price."""
    return round(input_tokens * USD_PER_INPUT_TOKEN, 12)


def is_unavailable_code(status_code: int) -> bool:
    """Codes that mean Jev is down or busy, not that our request was wrong."""
    return status_code in _UNAVAILABLE_CODES or status_code >= 500


def _noul(value: Any) -> float | None:
    # bool is an int subclass; a true/false answer is not a probability.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    if math.isnan(value) or not 0.0 <= value <= 1.0:
        return None
    return value


def normalise(
    status_code: int,
    body: Any,
    latency_ms: float,
    asked: tuple[str, ...],
    *,
    truncated: bool = False,
) -> dict:
    """Map an HTTP status and parsed JSON body to a verdict.

    ``body`` is the parsed JSON, or ``None`` when the reply was not JSON.
    """
    common = {"latency_ms": latency_ms, "truncated": truncated}
    if is_unavailable_code(status_code):
        return verdict("unavailable", error=f"http_{status_code}", **common)
    if status_code != 200:
        return verdict("error", error=f"http_{status_code}", **common)
    if not isinstance(body, dict):
        return verdict("error", error="bad_json", **common)

    raw_answers = body.get("answers")
    if not isinstance(raw_answers, dict):
        return verdict("error", error="missing_answer", **common)
    answers: dict[str, float] = {}
    for qid in asked:
        entry = raw_answers.get(qid)
        value = _noul(entry.get("noul")) if isinstance(entry, dict) else None
        if value is None:
            return verdict("error", error="missing_answer", **common)
        answers[qid] = value
    if not answers:
        return verdict("error", error="missing_answer", **common)

    usage = body.get("usage")
    tokens = usage.get("input_tokens") if isinstance(usage, dict) else None
    if isinstance(tokens, bool) or not isinstance(tokens, int):
        tokens = None
    model = body.get("model") if isinstance(body.get("model"), str) else None

    return verdict(
        "ok",
        attack=max(answers.values()),
        answers=answers,
        model=model,
        input_tokens=tokens,
        cost_usd=cost_usd(tokens) if tokens is not None else None,
        **common,
    )
