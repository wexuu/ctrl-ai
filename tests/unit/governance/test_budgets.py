"""Reservation arithmetic, thresholds, on_exceeded, reconcile, unknown price, concurrency."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from ctrl_ai.governance import budgets
from ctrl_ai.governance.catalogue import Price
from tests.unit.fake_state import FakeState

NOW = datetime(2026, 10, 4, 8, 0, tzinfo=UTC)
BUDGET = {"monthly_usd": 1.0, "daily_tokens": 1000, "on_exceeded": "downgrade", "downgrade_to": "chat-groq"}


def admit(state, estimate, budget=BUDGET):
    return asyncio.run(budgets.admit(state, "t", budget, estimate, NOW))


def test_estimate():
    price = Price(2.0, 10.0)
    assert budgets.estimate_usd(4000, 100, price) == pytest.approx(1000 * 2 / 1e6 + 100 * 10 / 1e6)
    assert budgets.estimate_usd(0, None, price) == pytest.approx(1024 * 10 / 1e6)
    assert budgets.estimate_usd(4000, 100, None) == 0.0


def test_thresholds_and_action():
    state = FakeState()
    assert admit(state, 0.5)["state"] == "ok"
    near = admit(state, 0.35)
    assert near["state"] == "near"
    over = admit(state, 0.2)
    assert (over["state"], over["action"]) == ("exceeded", "downgrade")


@pytest.mark.parametrize("action", ["downgrade", "block", "alert_only"])
def test_on_exceeded_is_reported(action):
    state = FakeState()
    state.data["ctrl-ai:budget:usd:t:2026-10"] = 2.0
    assert admit(state, 0.01, {**BUDGET, "on_exceeded": action})["action"] == action


def test_daily_tokens_exceeded():
    state = FakeState()
    state.data["ctrl-ai:budget:tok:t:2026-10-04"] = 1000
    assert admit(state, 0.0)["state"] == "exceeded"


def test_reconcile_adds_cost_and_tokens_and_releases():
    state = FakeState()
    record = admit(state, 0.3)
    asyncio.run(budgets.reconcile(state, "t", record["month"], 0.3, 0.12, 50, NOW))
    assert state.data["ctrl-ai:budget:usd:t:2026-10"] == pytest.approx(0.12)
    assert state.data["ctrl-ai:budget:resv:t:2026-10"] == pytest.approx(0.0)
    assert state.data["ctrl-ai:budget:tok:t:2026-10-04"] == 50


def test_unknown_price_counts_tokens_only():
    state = FakeState()
    record = admit(state, 0.0)
    assert record["state"] == "ok" and record["reserved"] == 0.0
    asyncio.run(budgets.reconcile(state, "t", record["month"], 0.0, None, 70, NOW))
    assert (
        "ctrl-ai:budget:usd:t:2026-10" not in state.data
        and state.data["ctrl-ai:budget:tok:t:2026-10-04"] == 70
    )


def test_redis_down_fails_open():
    state = FakeState()
    state.down = True
    assert admit(state, 0.1)["state"] == "unavailable"


def test_two_requests_racing_for_the_last_dollar():
    state = FakeState()
    state.data["ctrl-ai:budget:usd:t:2026-10"] = 0.5

    async def race():
        return await asyncio.gather(
            budgets.admit(state, "t", BUDGET, 0.4, NOW), budgets.admit(state, "t", BUDGET, 0.4, NOW)
        )

    first, second = asyncio.run(race())
    assert sorted(r["state"] for r in (first, second)).count("exceeded") >= 1


def test_block_message():
    assert budgets.block_message("risk-analytics", 300.5, 300) == (
        "ctrl-ai: team risk-analytics has used its monthly AI budget ($300.50 of $300.00). "
        "Contact your AI platform team."
    )
