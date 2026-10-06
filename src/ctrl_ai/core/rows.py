"""Audit rows, version 2.

Every new row carries ``"v": 2`` and every v2 field, with a neutral value when the
step that fills it has nothing to say. No prompt text, response text, key, token or
header value ever goes into a row: counts, ids, labels and scores only.
"""

from __future__ import annotations

from ctrl_ai.core.audit import utc_now_iso
from ctrl_ai.core.context import RequestContext

JEV_KEYS = (
    "status",
    "attack",
    "answers",
    "model",
    "input_tokens",
    "cost_usd",
    "latency_ms",
    "truncated",
    "error",
)


def jev_verdict(status: str, error: str | None = None, latency_ms: float = 0.0) -> dict:
    """A verdict for a call that produced no Jev answer, with all nine contract keys."""
    return {
        "status": status,
        "attack": None,
        "answers": None,
        "model": None,
        "input_tokens": None,
        "cost_usd": None,
        "latency_ms": latency_ms,
        "truncated": False,
        "error": error,
    }


def neutral_semantic(reason: str | None = "skipped") -> dict:
    return {"source": None, "score": None, "action": "observe", "reason": reason}


def decision_row(ctx: RequestContext) -> dict:
    """The decision row for a request: all v1 fields, then the v2 fields."""
    identity = ctx.identity
    row = {
        "type": "decision",
        "v": 2,
        "ts": utc_now_iso(),
        "request_id": ctx.request_id,
        "endpoint": ctx.endpoint,
        "model": ctx.model_requested,
        "stream": bool(ctx.stream),
        "mode": ctx.mode,
        "decision": ctx.decision,
        "would_block": bool(ctx.would_block),
        "rule": ctx.rule,
        "policy_version": ctx.policy_version,
        "text_chars": ctx.text_chars,
        "jev": ctx.jev.jev_row() if ctx.jev is not None else jev_verdict("skipped"),
        "guard_ms": ctx.guard_ms,
        "team": identity.team,
        "department": identity.department,
        "user": identity.user,
        "key_id": identity.key_id,
        "profile": ctx.profile.name,
        "model_requested": ctx.model_requested,
        "model_routed": ctx.model_routed if ctx.model_routed is not None else ctx.model_requested,
        "route_reason": ctx.route_reason,
        "findings": [f.as_dict() for f in ctx.findings],
        "data_class_detected": ctx.data_class_detected,
        "normalisation": dict(ctx.normalisation),
        "masked": dict(ctx.masked),
        "semantic": ctx.semantic if ctx.semantic is not None else neutral_semantic(),
        "judge": ctx.judge.judge_row() if ctx.judge is not None else None,
        "flagged": bool(ctx.flagged),
        "loop": ctx.loop,
        "budget": ctx.budget,
        "break_glass": ctx.break_glass,
    }
    # Optional fields, present only when they say something.
    for key in ("masking", "restore", "mask_store"):
        value = getattr(ctx, key)
        if value is not None:
            row[key] = value
    if ctx.identity.error:
        row["identity_error"] = ctx.identity.error
    if ctx.error:
        row["error"] = ctx.error
    return row


def usage_fields(ctx: RequestContext | None) -> dict:
    """The v2 identity and routing fields of a usage row, from the request's context."""
    if ctx is None:
        return {
            "team": None,
            "department": None,
            "user": None,
            "key_id": None,
            "model_requested": None,
            "model_routed": None,
            "masked_total": 0,
        }
    identity = ctx.identity
    return {
        "team": identity.team,
        "department": identity.department,
        "user": identity.user,
        "key_id": identity.key_id,
        "model_requested": ctx.model_requested,
        "model_routed": ctx.model_routed if ctx.model_routed is not None else ctx.model_requested,
        "masked_total": sum(int(n) for n in ctx.masked.values()),
    }


def break_glass_row(event: str, record: dict) -> dict:
    """A ``break_glass`` row (issue, use, revoke, expire). Never the token."""
    return {
        "type": "break_glass",
        "v": 2,
        "ts": utc_now_iso(),
        "event": event,
        "id": record.get("id"),
        "subject": record.get("subject"),
        "relax": list(record.get("relax") or []),
        "ticket": record.get("ticket"),
        "issued_by": record.get("issued_by"),
        "expires_at": record.get("expires_at"),
    }
