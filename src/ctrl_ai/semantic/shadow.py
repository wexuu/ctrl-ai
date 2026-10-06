"""The shadow check: the shadow model looks again at a sample of what the classifier accepted.

The classifier's rejections already go to the judge, but a request the classifier wrongly
accepts would never be looked at. A random share of accepted requests (``judge.shadow.rate``)
is sent to the shadow model (``CTRL_AI_SHADOW_MODEL``, the judge's model by default) after the
decision, in the background: the user's request never waits for it, and the text is held in
memory only for the call. One ``shadow`` row records both verdicts (no text). Agreement over
time is the drift signal on the Jev trust page; a yes from the shadow model on a request the
classifier accepted is a possible miss for human review.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import Callable
from typing import Any

from ctrl_ai.core.audit import utc_now_iso
from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.scores import Score
from ctrl_ai.semantic.models import DecisionModel
from ctrl_ai.semantic.semantic import judge_input

MAX_IN_FLIGHT = 2  # free-tier rate limits: drop a sample rather than queue behind others
_TASKS: set[asyncio.Task] = set()


def eligible(ctx: RequestContext, policy: Any) -> bool:
    """Jev answered and the request went through on Jev's word alone."""
    shadow = getattr(policy, "shadow", None) or {}
    sem = ctx.semantic or {}
    return (
        float(shadow.get("rate") or 0) > 0
        and getattr(policy, "judge_enabled", False)
        and sem.get("source") == "jev"
        and sem.get("action") == "observe"
        and ctx.decision != "block"
        and bool(ctx.semantic_texts)
    )


def maybe_start(
    ctx: RequestContext,
    policy: Any,
    audit: Any,
    sampler: DecisionModel | None,
    rng: Callable[[], float] = random.random,
) -> bool:
    """Start a shadow check for this request if it is drawn. Returns whether one started."""
    if sampler is None or not eligible(ctx, policy):
        return False
    if rng() >= float(policy.shadow["rate"]) or len(_TASKS) >= MAX_IN_FLIGHT:
        return False
    text, source = judge_input(ctx.semantic_texts)
    task = asyncio.get_running_loop().create_task(
        _run(ctx, text, source, int(policy.shadow.get("samples") or 5), audit, sampler)
    )
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return True


async def _run(
    ctx: RequestContext, text: str, source: str, n: int, audit: Any, sampler: DecisionModel
) -> None:
    try:
        result = await sampler.sample(text, source, n)
    except Exception as exc:  # never surfaces: the request has long been answered
        result = Score("error", error=type(exc).__name__)
    ident = ctx.identity
    jev_score = (ctx.semantic or {}).get("score")
    p = result.score
    row = {
        "type": "shadow",
        "v": 2,
        "ts": utc_now_iso(),
        "request_id": ctx.request_id,
        "team": ident.team,
        "department": ident.department,
        "user": ident.user,
        "key_id": ident.key_id,
        "model": ctx.model_requested,
        "source": source,
        "jev_score": jev_score,
        "second": result.shadow_row(),
        # Jev accepted this request; the second model agreeing means it says no attack too.
        "agree": None if p is None else p < 0.5,
        "possible_miss": None if p is None else p >= 0.5,
    }
    with contextlib.suppress(Exception):
        audit.write(row)
