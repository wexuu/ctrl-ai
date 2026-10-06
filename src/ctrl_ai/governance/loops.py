"""Runaway-loop caps: warn at 80%, throttle above 100%, stop above 150%.

Counters live in Redis (``state.py``) so several gateway replicas agree. Any Redis error
fails open: the request goes through and the row says ``loop: {state: "unavailable"}``
(at most once a minute, not on every request).
"""

from __future__ import annotations

import contextlib
import hashlib
import time
from typing import Any

from ctrl_ai.core.state import StateUnavailable

WARN, THROTTLE, STOP = 0.8, 1.0, 1.5
STOP_TTL_S = 600
_ORDER = {None: 0, "warn": 1, "throttle": 2, "stop": 3}
_last_unavailable = [0.0]


def session_id(header_session: str | None, litellm_session: Any, key_id: str | None, now: float) -> str:
    """Claude Code's session header, else LiteLLM's session id, else the key plus a 10-minute bucket."""
    if header_session:
        return "cc:" + header_session
    if isinstance(litellm_session, str) and litellm_session:
        return "ls:" + litellm_session[:200]
    return f"key:{key_id or 'admin'}:{int(now // 600)}"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


def _level(count: float, limit: float) -> str | None:
    if limit <= 0:
        return None
    ratio = count / limit
    if ratio > STOP:
        return "stop"
    if ratio > THROTTLE:
        return "throttle"
    if ratio >= WARN:
        return "warn"
    return None


async def check(
    state: Any,
    session: str | None,
    prompt_text: str,
    tool_signature: str | None,
    limits: dict,
    now: float | None = None,
) -> dict | None:
    """Count this request; return the loop record for the row, or None when all is quiet."""
    now = now or time.time()
    try:
        if await state.get(f"ctrl-ai:loop:stop:{session}"):
            return {"state": "stop", "counter": None, "limit": None, "kind": "stopped_session"}
        max_minutes = limits.get("max_session_minutes")
        if max_minutes:
            started = await state.get(f"ctrl-ai:loop:start:{session}")
            if started is None:
                await state.set(f"ctrl-ai:loop:start:{session}", str(now), 86400)
            elif now - float(started) > float(max_minutes) * 60:
                minutes = int((now - float(started)) // 60)
                await state.set(f"ctrl-ai:loop:stop:{session}", "session_time", STOP_TTL_S)
                return {
                    "state": "stop",
                    "counter": minutes,
                    "limit": int(max_minutes),
                    "kind": "session_time",
                }
        bucket = int(now // 600)
        results = []
        req = await state.incr(f"ctrl-ai:loop:req:{session}:{bucket}", 900)
        results.append(("requests_per_10_min", req, limits["max_requests_per_10_min"]))
        turn = await state.incr(f"ctrl-ai:loop:turn:{session}:{_sha(prompt_text)}", 3600)
        results.append(("calls_per_user_turn", turn, limits["max_calls_per_user_turn"]))
        tokens = int(await state.get(f"ctrl-ai:loop:tok:{session}") or 0)
        results.append(("tokens_per_session", tokens, limits["max_tokens_per_session"]))
        worst = None
        for kind, count, limit in results:
            level = _level(count, limit)
            if _ORDER[level] > _ORDER[worst["state"] if worst else None]:
                worst = {"state": level, "counter": count, "limit": limit, "kind": kind}
        if tool_signature:
            limit = limits["max_identical_tool_calls"]
            recent = await state.push_recent(
                f"ctrl-ai:loop:tools:{session}", _sha(tool_signature), limit, 3600
            )
            run = 0
            for item in recent:
                if item != recent[0]:
                    break
                run += 1
            if run >= limit:
                worst = {"state": "stop", "counter": run, "limit": limit, "kind": "identical_tool_calls"}
            elif _level(run, limit) == "warn" and worst is None:
                worst = {"state": "warn", "counter": run, "limit": limit, "kind": "identical_tool_calls"}
        if worst and worst["state"] == "stop":
            await state.set(f"ctrl-ai:loop:stop:{session}", worst["kind"], STOP_TTL_S)
        return worst
    except StateUnavailable:
        if now - _last_unavailable[0] >= 60:
            _last_unavailable[0] = now
            return {"state": "unavailable", "counter": None, "limit": None}
        return None


async def add_tokens(state: Any, session: str, tokens: int) -> None:
    if tokens <= 0:
        return
    with contextlib.suppress(StateUnavailable):
        await state.incrby(f"ctrl-ai:loop:tok:{session}", int(tokens), 86400)


def message(loop: dict) -> str:
    kind = loop.get("kind") or ""
    if loop["state"] == "throttle":
        return (
            f"ctrl-ai: this session is sending requests unusually fast ({loop['counter']} "
            f"{_KIND_TEXT.get(kind, kind)}, limit {loop['limit']}). Slow down or start a new session."
        )
    detected = {
        "identical_tool_calls": f"the same tool call repeated {loop['counter']} times in a row",
        "stopped_session": "a runaway loop earlier in this session",
        "session_time": f"it ran for {loop['counter']} minutes (agent timeout {loop['limit']} minutes)",
    }.get(kind, f"{loop['counter']} {_KIND_TEXT.get(kind, kind)} (limit {loop['limit']})")
    return (
        f"ctrl-ai: this session was stopped because it looks like a runaway agent loop: {detected}. "
        "Start a new session, or ask your security on-call for a break-glass override."
    )


_KIND_TEXT = {
    "requests_per_10_min": "requests in 10 minutes",
    "calls_per_user_turn": "model calls for one prompt",
    "tokens_per_session": "tokens in this session",
}
