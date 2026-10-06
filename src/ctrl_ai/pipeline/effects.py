"""Effects: what the gateway changes on the way through.

Masking rewrites the forwarded request and keeps the surrogate map for the restore hook; the
agent timeout caps a single model call. Refusals are not effects: the adapters build the HTTP
response from the decision fields the evaluator set.
"""

from __future__ import annotations

from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.policy import Policy
from ctrl_ai.core.state import RedisState
from ctrl_ai.detect import masking

MASKING_FAILED_MESSAGE = "ctrl-ai could not protect this request's data; it was not sent."


def cap_timeout(data: dict, policy: Policy) -> None:
    """Agent timeout: the gateway cuts a single model call that runs longer than the policy allows."""
    timeout = (policy.loops or {}).get("request_timeout_s")
    if not timeout:
        return
    current = data.get("timeout")
    if not isinstance(current, (int, float)) or current > timeout:
        data["timeout"] = float(timeout)


def mask_semantic_copy(ctx: RequestContext, masker: masking.Masker) -> None:
    """The copy sent to Jev and the judge never carries personal data (both routes)."""
    if ctx.mask_plan is None or not ctx.semantic_texts:
        return
    try:
        ctx.semantic_texts = {src: masker.mask_text(text) for src, text in ctx.semantic_texts.items()}
        if ctx.mask_plan == "semantic_only":
            ctx.masked = dict(masker.counts)
    except Exception as exc:
        # Nothing may leave unmasked: without a masked copy the semantic check is skipped.
        ctx.semantic_texts = {}
        ctx.masking = f"error: {type(exc).__name__}"


async def rewrite_request(
    ctx: RequestContext, data: dict, policy: Policy, masker: masking.Masker, state: RedisState, secret: str
) -> None:
    """External route: replace personal data in the forwarded request (fail closed by default)."""
    try:
        masker.mask_body(data)
        ctx.masked = dict(masker.counts)
        ctx.mask_map = dict(masker.mapping)
    except Exception as exc:
        ctx.masking = f"error: {type(exc).__name__}"
        if policy.masking.get("on_error", "fail_closed") == "fail_closed":
            ctx.decision = "block"
            ctx.would_block = True
            ctx.rule = "masking-failed"
            ctx.status_code = 503
            ctx.message = MASKING_FAILED_MESSAGE
        return
    if ctx.mask_map:
        await store_mask_map(ctx, state, secret)


async def store_mask_map(ctx: RequestContext, state: RedisState, secret: str) -> None:
    """Keep the surrogate map (encrypted) in Redis for the session; in memory otherwise."""
    try:
        stored = masking.encrypt_map(ctx.mask_map, secret)
        await state.hset_many(f"ctrl-ai:mask:{ctx.session}", stored, 86400)
        ctx.mask_store = "redis"
    except Exception:
        ctx.mask_store = "memory"
