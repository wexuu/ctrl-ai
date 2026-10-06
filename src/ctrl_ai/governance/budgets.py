"""Team budgets with reservation: monthly dollars and daily tokens.

At admission the estimated cost of the request is reserved atomically (INCRBYFLOAT), so
two concurrent requests cannot both spend the last dollar. After the call the logger adds
the actual cost and tokens and releases the reservation. Redis errors fail open.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import Any

from ctrl_ai.core.state import StateUnavailable

NEAR = 0.8
MONTH_TTL = 40 * 86400
DAY_TTL = 2 * 86400
DEFAULT_MAX_TOKENS = 1024


def month_of(now: datetime) -> str:
    return now.strftime("%Y-%m")


def day_of(now: datetime) -> str:
    return now.strftime("%Y-%m-%d")


def estimate_usd(prompt_chars: int, max_tokens: int | None, price: Any) -> float:
    """(prompt characters / 4) × input price + max_tokens (or 1024) × output price."""
    if price is None:
        return 0.0
    out_tokens = max_tokens if isinstance(max_tokens, int) and max_tokens > 0 else DEFAULT_MAX_TOKENS
    return (prompt_chars / 4) * price.input_per_mtok / 1e6 + out_tokens * price.output_per_mtok / 1e6


async def admit(state: Any, team: str, budget: dict, estimate: float, now: datetime | None = None) -> dict:
    """Reserve ``estimate`` and classify the team's spend: ok, near or exceeded.

    Returns the row's budget record plus ``reserved`` (the amount to release later; zero
    when the request is not admitted on this budget).
    """
    now = now or datetime.now(UTC)
    month = month_of(now)
    limit = budget.get("monthly_usd")
    daily_tokens = budget.get("daily_tokens")
    try:
        used = float(await state.get(f"ctrl-ai:budget:usd:{team}:{month}") or 0.0)
        reserved_total = (
            float(await state.incrbyfloat(f"ctrl-ai:budget:resv:{team}:{month}", estimate, MONTH_TTL))
            if estimate > 0
            else float(await state.get(f"ctrl-ai:budget:resv:{team}:{month}") or 0.0)
        )
        tokens_today = int(await state.get(f"ctrl-ai:budget:tok:{team}:{day_of(now)}") or 0)
    except StateUnavailable:
        return {"state": "unavailable", "action": None, "used_usd": None, "limit_usd": limit, "reserved": 0.0}
    record = {
        "state": "ok",
        "action": None,
        "used_usd": round(used, 6),
        "limit_usd": limit,
        "reserved": estimate,
        "month": month,
    }
    exceeded = False
    if isinstance(limit, (int, float)):
        total = used + reserved_total
        if total >= limit:
            exceeded = True
        elif total >= NEAR * limit:
            record["state"] = "near"
    if isinstance(daily_tokens, int) and daily_tokens > 0 and tokens_today >= daily_tokens:
        exceeded = True
    if exceeded:
        record["state"] = "exceeded"
        record["action"] = budget.get("on_exceeded", "alert_only")
    return record


async def release(state: Any, team: str, month: str, amount: float) -> None:
    if amount > 0:
        with contextlib.suppress(StateUnavailable):
            await state.incrbyfloat(f"ctrl-ai:budget:resv:{team}:{month}", -amount, MONTH_TTL)


async def reconcile(
    state: Any,
    team: str,
    month: str,
    reserved: float,
    cost_usd: Any,
    tokens: int,
    now: datetime | None = None,
) -> None:
    """After the call: add the actual cost and tokens; release the reservation."""
    now = now or datetime.now(UTC)
    try:
        if isinstance(cost_usd, (int, float)) and cost_usd > 0:
            await state.incrbyfloat(f"ctrl-ai:budget:usd:{team}:{month}", float(cost_usd), MONTH_TTL)
        if tokens > 0:
            await state.incrby(f"ctrl-ai:budget:tok:{team}:{day_of(now)}", tokens, DAY_TTL)
    except StateUnavailable:
        pass
    await release(state, team, month, reserved)


def block_message(team: str, used: Any, limit: Any) -> str:
    used_text = f"${used:.2f}" if isinstance(used, (int, float)) else "its spend"
    limit_text = f"${limit:.2f}" if isinstance(limit, (int, float)) else "its limit"
    return (
        f"ctrl-ai: team {team} has used its monthly AI budget ({used_text} of {limit_text}). "
        "Contact your AI platform team."
    )
