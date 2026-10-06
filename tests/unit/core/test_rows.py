"""Decision and usage rows carry exactly the v2 fields of B's fixture, with matching types."""

from __future__ import annotations

import json
from pathlib import Path

from ctrl_ai.core.context import Finding, Identity, RequestContext
from ctrl_ai.core.rows import decision_row
from ctrl_ai.governance.usage import build_usage_row
from ctrl_ai.pipeline.ctxcache import ContextCache
from ctrl_ai.semantic.models import Score

FIXTURE = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "audit-v2-sample.jsonl"


def fixture_row(row_type: str) -> dict:
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("type") == row_type and row.get("v") == 2:
            return row
    raise AssertionError(f"no v2 {row_type} row in the fixture")


def assert_same_shape(ours: dict, theirs: dict) -> None:
    assert set(ours) == set(theirs), set(ours) ^ set(theirs)
    for key, value in theirs.items():
        if value is None or ours[key] is None:
            continue
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            assert isinstance(ours[key], (int, float)) and not isinstance(ours[key], bool), key
        else:
            assert type(ours[key]) is type(value), (key, type(ours[key]), type(value))


def test_decision_row_matches_fixture():
    ctx = RequestContext(
        request_id="r1",
        endpoint="chat_completions",
        model_requested="chat-groq",
        identity=Identity("retail-dev", "retail", "anna", "k_0a1b2c3d", "balanced"),
    )
    ctx.mode, ctx.policy_version, ctx.text_chars, ctx.guard_ms = "enforce", "abcd1234", 10, 1.5
    ctx.findings.append(Finding("pii-iban", "pii", "prompt", "mask", "high"))
    ctx.semantic = {"source": "jev", "score": 0.1, "action": "observe", "reason": None}
    ctx.budget = {"state": "ok", "action": None, "used_usd": 1.0, "limit_usd": 2}
    ctx.jev = Score(
        "ok",
        score=0.1,
        answers={"a": 0.1},
        model="m",
        input_tokens=3,
        cost_usd=0.1,
        latency_ms=1.0,
    )
    row = decision_row(ctx)
    assert row["v"] == 2
    assert_same_shape(row, fixture_row("decision"))
    finding_keys = {"rule", "pack", "source", "action", "severity"}
    assert set(row["findings"][0]) == finding_keys


def test_neutral_decision_row_has_every_field():
    row = decision_row(RequestContext())
    assert set(row) == set(fixture_row("decision"))
    assert row["findings"] == [] and row["masked"] == {} and row["flagged"] is False
    assert row["semantic"]["action"] == "observe"


def test_usage_row_matches_fixture():
    slo = {
        "litellm_call_id": "r1",
        "status": "success",
        "model_group": "chat-groq",
        "prompt_tokens": 5,
        "completion_tokens": 7,
        "response_cost": 0.001,
        "response_time": 0.5,
        "metadata": {"user_api_key_request_route": "/v1/chat/completions"},
    }
    ctx = RequestContext(
        request_id="r1",
        model_requested="chat-groq",
        model_routed="chat-groq",
        identity=Identity("retail-dev", "retail", "anna", "k_0a1b2c3d"),
    )
    row = build_usage_row(slo, ctx)
    assert row["v"] == 2
    assert_same_shape(row, fixture_row("usage"))
    # Without a context (e.g. an auth failure) the row still has every field.
    assert set(build_usage_row(slo)) == set(fixture_row("usage"))


def test_context_cache_bounded_and_expiring():
    now = [0.0]
    cache = ContextCache(max_entries=2, ttl_s=10, clock=lambda: now[0])
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    assert cache.get("a") is None and cache.get("c") == 3
    now[0] = 11
    assert cache.get("b") is None
    cache.put(None, 4)
    assert len(cache) <= 2
