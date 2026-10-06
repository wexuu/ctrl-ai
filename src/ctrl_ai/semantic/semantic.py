"""The semantic decision: the classifier (Jev by default), the judge when the classifier is
unavailable or uncertain, then the profile decides. Pure apart from the two injected async
checks, which return ``models.Score``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.scores import Score

ClassifierCheck = Callable[[dict[str, str]], Awaitable[Score]]
JudgeCheck = Callable[[str, str], Awaitable[Score]]
UNAVAILABLE_ACTION = {"allow": "observe", "flag": "flag", "block": "block"}


def semantic_block_message(source: str | None, score: float | None) -> str:
    return (
        f"Blocked by ctrl-ai: semantic check ({source}) scored {score:.2f}. "
        "If this is legitimate work, ask your security on-call for a break-glass override."
    )


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return ""


def judge_block_message(policy: Any, judge: Score | None, score: float) -> str | None:
    """The admin's ``judge.block_message`` filled in, or None to use the standard message.
    The reason is the judge model's own words (one line, capped), not the user's text."""
    template = getattr(policy, "judge_block_message", None)
    if not template:
        return None
    values = _Blank(
        score=f"{score:.2f}",
        category=(judge.category if judge else None) or "unspecified",
        reason=((judge.reason if judge else None) or "no reason given").rstrip(" .!"),
        model=(judge.model if judge else None) or "",
    )
    try:
        return template.format_map(values)
    except (ValueError, IndexError, AttributeError, KeyError):
        return None  # a malformed template must not break the refusal


def block_message_for(policy: Any, ctx: RequestContext, source: str | None, score: float | None) -> str:
    if score is None:
        return (
            "Blocked by ctrl-ai: the semantic check is unavailable and this team's "
            "profile does not allow unchecked requests. Try again shortly."
        )
    if source == "judge":
        custom = judge_block_message(policy, ctx.judge, score)
        if custom:
            return custom
    return semantic_block_message(source, score)


def judge_input(texts: dict[str, str]) -> tuple[str, str]:
    """One text for the judge: the single source, or every source labelled."""
    if len(texts) == 1:
        ((source, text),) = texts.items()
        return text, source
    return "\n\n".join(f"[{src}]\n{text}" for src, text in texts.items()), "mixed"


async def decide(
    ctx: RequestContext,
    policy: Any,
    ask_classifier: ClassifierCheck,
    judge_check: JudgeCheck | None,
    relaxed: bool = False,
) -> None:
    """Fill ``ctx.jev``, ``ctx.judge``, ``ctx.semantic``; block or flag per the profile."""
    texts = ctx.semantic_texts
    if not texts:
        ctx.jev = Score.skipped()
        ctx.semantic = {"source": None, "score": None, "action": "observe", "reason": "no_text"}
        return
    ctx.jev = await ask_classifier(texts) if policy.jev_enabled else Score.skipped()
    jev_ok = ctx.jev.ok
    score = float(ctx.jev.score) if jev_ok and ctx.jev.score is not None else None
    source = "jev" if jev_ok else None
    reason = None

    accept = getattr(policy, "accept_below", None)
    if accept is not None:
        await _decide_escalate(
            ctx, policy, texts, jev_ok, score, accept, judge_check=judge_check, relaxed=relaxed
        )
        return

    review, block = policy.review_threshold, policy.block_threshold
    want_judge = False
    if policy.judge_enabled and judge_check is not None:
        if not jev_ok and "jev_unavailable" in policy.judge_when:
            want_judge, reason = True, "jev_unavailable"
        elif jev_ok and review <= score < block and "jev_uncertain" in policy.judge_when:
            want_judge, reason = True, "uncertain_band"
    if want_judge and judge_check is not None:
        text, src = judge_input(texts)
        ctx.judge = await judge_check(text, src)
        if ctx.judge.ok and ctx.judge.score is not None:
            score, source = float(ctx.judge.score), "judge"

    if score is None:
        action = UNAVAILABLE_ACTION.get(ctx.profile.on_semantic_unavailable, "observe")
        reason = "unavailable"
    elif score >= block:
        action = ctx.profile.semantic_action
        reason = reason if source == "judge" else "above_block_threshold"
    else:
        action = "observe"
        if source == "jev" and review <= score:
            reason = "uncertain_band"
        elif source == "jev":
            reason = None

    if action == "block" and relaxed:
        action, reason = "flag", "break_glass"
    ctx.semantic = {
        "source": source,
        "score": None if score is None else round(score, 4),
        "action": action,
        "reason": reason,
    }
    if action == "flag":
        ctx.flagged = True
    elif action == "block":
        ctx.flagged = True
        ctx.would_block = True
        if ctx.mode == "enforce":
            ctx.decision = "block"
            ctx.status_code = 400
            ctx.message = block_message_for(policy, ctx, source, score)


async def _decide_escalate(
    ctx: RequestContext,
    policy: Any,
    texts: dict,
    jev_ok: bool,
    score: float | None,
    accept: float,
    *,
    judge_check: JudgeCheck | None,
    relaxed: bool,
) -> None:
    """Single-threshold flow: Jev accepts below ``accept``; anything else goes to the AI judge,
    whose score at or above ``judge_reject_from`` rejects the request (the profile then flags or
    blocks). Without a judge answer, Jev's own rejection stands; with neither, the profile's
    ``on_semantic_unavailable`` applies."""
    if jev_ok and score is not None and score < accept:
        _finish(ctx, policy, "jev", score, "observe", None, relaxed)
        return
    first_reason = "jev_rejected" if jev_ok else "jev_unavailable"
    if policy.judge_enabled and judge_check is not None:
        text, src = judge_input(texts)
        ctx.judge = await judge_check(text, src)
        if ctx.judge.ok and ctx.judge.score is not None:
            jscore = float(ctx.judge.score)
            if jscore >= policy.judge_reject_from:
                _finish(ctx, policy, "judge", jscore, ctx.profile.semantic_action, "judge_rejected", relaxed)
            else:
                _finish(ctx, policy, "judge", jscore, "observe", "judge_accepted", relaxed)
            return
    if jev_ok:
        _finish(ctx, policy, "jev", score, ctx.profile.semantic_action, first_reason, relaxed)
    else:
        _finish(
            ctx,
            policy,
            None,
            None,
            UNAVAILABLE_ACTION.get(ctx.profile.on_semantic_unavailable, "observe"),
            "unavailable",
            relaxed,
        )


def _finish(
    ctx: RequestContext,
    policy: Any,
    source: str | None,
    score: float | None,
    action: str,
    reason: str | None,
    relaxed: bool,
) -> None:
    if action == "block" and relaxed:
        action, reason = "flag", "break_glass"
    ctx.semantic = {
        "source": source,
        "score": None if score is None else round(score, 4),
        "action": action,
        "reason": reason,
    }
    if action == "flag":
        ctx.flagged = True
    elif action == "block":
        ctx.flagged = True
        ctx.would_block = True
        if ctx.mode == "enforce":
            ctx.decision = "block"
            ctx.status_code = 400
            ctx.message = block_message_for(policy, ctx, source, score)
