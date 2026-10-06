"""The semantic decision, the judge, and the one-row-per-request hook glue."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path

import pytest

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.policy import PolicyStore, parse_policy
from ctrl_ai.pipeline import hooks
from ctrl_ai.pipeline.ctxcache import ContextCache
from ctrl_ai.pipeline.engine import Engine
from ctrl_ai.semantic import semantic
from ctrl_ai.semantic.models import Score, StaticModel

REPO = Path(__file__).resolve().parents[3]
POLICY = parse_policy((REPO / "tests" / "fixtures" / "config" / "policy.yaml").read_bytes())


def jev_ok(score):
    return Score(
        "ok", score=score, answers={"q": score}, model="jev", input_tokens=1, cost_usd=0.0, latency_ms=1.0
    )


def jev_down():
    return Score.unavailable("timeout", 1.0)


def judge_result(score=None, status="ok", **fields):
    return Score(status, score=score, model="j", latency_ms=1.0, cost_usd=0.0, **fields)


def run(profile, jev, judged=None, relaxed=False, mode="enforce"):
    ctx = RequestContext(profile=POLICY.profile(profile), mode=mode)
    ctx.semantic_texts = {"prompt": "text"}
    calls = []

    async def ask(texts):
        return jev

    async def judge_check(text, source):
        calls.append(source)
        return judged

    asyncio.run(semantic.decide(ctx, POLICY, ask, judge_check if judged is not None else None, relaxed))
    return ctx, calls


def test_low_score_is_observed():
    ctx, calls = run("balanced", jev_ok(0.05))
    assert ctx.semantic == {"source": "jev", "score": 0.05, "action": "observe", "reason": None}
    assert calls == [] and ctx.decision == "allow" and not ctx.flagged


@pytest.mark.parametrize(
    "profile, action, decision",
    [("observe", "observe", "allow"), ("balanced", "flag", "allow"), ("strict", "block", "block")],
)
def test_high_score_follows_the_profile(profile, action, decision):
    mode = "monitor" if profile == "observe" else "enforce"
    ctx, _ = run(profile, jev_ok(0.93), mode=mode)
    assert ctx.semantic["action"] == action and ctx.decision == decision
    if decision == "block":
        assert ctx.message.startswith("Blocked by ctrl-ai: semantic check (jev) scored 0.93")


def test_uncertain_band_asks_the_judge_whose_score_wins():
    ctx, calls = run("strict", jev_ok(0.55), judge_result(0.91))
    assert calls == ["prompt"]
    # Single-threshold flow: Jev rejected, the judge decided and rejected.
    assert ctx.semantic == {"source": "judge", "score": 0.91, "action": "block", "reason": "judge_rejected"}
    ctx, _ = run("strict", jev_ok(0.55), judge_result(0.1))
    assert ctx.semantic["action"] == "observe" and ctx.decision == "allow"


def test_jev_unavailable_asks_the_judge():
    ctx, calls = run("balanced", jev_down(), judge_result(0.2))
    assert calls == ["prompt"] and ctx.semantic["source"] == "judge"


# Merge: strict fails closed since the per-team scenario decision (on_semantic_unavailable: block).
@pytest.mark.parametrize(
    "profile, action, decision", [("balanced", "observe", "allow"), ("strict", "block", "block")]
)
def test_nothing_available_applies_on_semantic_unavailable(profile, action, decision):
    ctx, _ = run(profile, jev_down(), judge_result(status="unavailable"))
    assert ctx.semantic == {"source": None, "score": None, "action": action, "reason": "unavailable"}
    assert ctx.decision == decision


def test_break_glass_turns_a_block_into_a_flag():
    ctx, _ = run("strict", jev_ok(0.93), relaxed=True)
    assert ctx.semantic["action"] == "flag" and ctx.semantic["reason"] == "break_glass"
    assert ctx.decision == "allow" and ctx.flagged


def test_monitor_mode_never_blocks():
    ctx, _ = run("strict", jev_ok(0.93), mode="monitor")
    assert ctx.decision == "allow" and ctx.would_block


def hook_engine(tmp_path) -> Engine:
    return Engine(
        policy_store=PolicyStore(str(REPO / "tests" / "fixtures" / "config" / "policy.yaml")),
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
        cache=ContextCache(),
    )


def test_hooks_write_one_row_per_request(tmp_path):
    engine = hook_engine(tmp_path)
    data = {
        "litellm_call_id": "c1",
        "model": "claude-opus-5-5",
        "messages": [{"role": "user", "content": "hello"}],
    }

    jev = StaticModel(0.01, name="jev")

    async def flow():
        ctx = await hooks.before_call(engine, data, "anthropic_messages", None)
        assert ctx.semantic_pending and not ctx.row_written
        await hooks.during_call(engine, data, classifier=jev)
        await hooks.during_call(engine, data, classifier=jev)  # second call: no-op
        slo = {
            "litellm_call_id": "c1",
            "status": "success",
            "model_group": "claude-opus-5-5",
            "metadata": {"user_api_key_request_route": "/v1/messages"},
        }
        await hooks.after_call(engine, slo)

    asyncio.run(flow())
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [r["type"] for r in rows] == ["decision", "usage"]
    assert rows[0]["semantic"]["source"] == "jev"


def test_logger_writes_the_row_when_the_semantic_hook_never_ran(tmp_path):
    engine = hook_engine(tmp_path)
    data = {
        "litellm_call_id": "c2",
        "model": "claude-opus-5-5",
        "messages": [{"role": "user", "content": "x"}],
    }

    async def flow():
        await hooks.before_call(engine, data, "acompletion", None)
        await hooks.after_call(
            engine,
            {
                "litellm_call_id": "c2",
                "status": "success",
                "metadata": {"user_api_key_request_route": "/v1/chat/completions"},
            },
        )

    asyncio.run(flow())
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [r["type"] for r in rows] == ["decision", "usage"]
    assert rows[0]["semantic"]["reason"] == "not_run"


# ---- single-threshold flow: Jev accepts below accept_below, the judge decides the rest


def test_escalate_flow_jev_accepts():
    ctx, calls = run("strict", jev_ok(0.10), judged=judge_result(0.99))
    assert calls == [] and ctx.semantic["action"] == "observe" and ctx.semantic["source"] == "jev"


def test_escalate_flow_judge_accepts_what_jev_rejected():
    ctx, calls = run("strict", jev_ok(0.80), judged=judge_result(0.10))
    assert calls == ["prompt"]
    assert ctx.semantic == {"source": "judge", "score": 0.1, "action": "observe", "reason": "judge_accepted"}
    assert ctx.decision != "block"


def test_escalate_flow_judge_down_keeps_jev_rejection():
    ctx, _ = run("strict", jev_ok(0.80), judged=judge_result(status="unavailable"))
    assert ctx.semantic["source"] == "jev" and ctx.semantic["reason"] == "jev_rejected"
    assert ctx.decision == "block"


def test_judge_block_uses_the_custom_message():
    policy = dataclasses.replace(POLICY, judge_block_message="No: {category}, {reason} ({score}){nope}")
    ctx = RequestContext(profile=policy.profile("strict"), mode="enforce")
    ctx.semantic_texts = {"prompt": "text"}

    async def ask(texts):
        return jev_ok(0.96)

    async def judge_check(text, source):
        return judge_result(0.92, category="exfiltration", reason="sends keys out")

    asyncio.run(semantic.decide(ctx, policy, ask, judge_check))
    assert ctx.decision == "block" and ctx.message == "No: exfiltration, sends keys out (0.92)"


def test_malformed_judge_message_falls_back_to_the_standard_one():
    class P:
        judge_block_message = "broken {"

    assert semantic.judge_block_message(P(), judge_result(0.9, reason="r"), 0.9) is None


def test_shadow_checks_a_sample_of_what_jev_accepted():
    from ctrl_ai.semantic import shadow

    policy = dataclasses.replace(POLICY, shadow={**POLICY.shadow, "rate": 1.0, "samples": 3})
    rows = []

    class Audit:
        def write(self, row):
            rows.append(row)

    class Sampler:
        name = "sampler"

        async def score(self, text, source):
            raise AssertionError("the shadow check samples")

        async def sample(self, text, source, n):
            assert n == 3 and text == "text"
            return Score("ok", score=0.67, model="sampler")

    sampler = Sampler()

    def go(jev_score, with_sampler=True):
        ctx, _ = run("strict", jev_ok(jev_score))

        async def start():
            started = shadow.maybe_start(ctx, policy, Audit(), sampler if with_sampler else None)
            await asyncio.gather(*list(shadow._TASKS))
            return started

        return asyncio.run(start())

    assert (go(0.05)) is True
    assert rows[0]["type"] == "shadow" and rows[0]["jev_score"] == 0.05 and rows[0]["possible_miss"] is True
    assert rows[0]["second"]["p"] == 0.67
    assert (go(0.99)) is False  # rejected requests already go to the second model
    assert (go(0.05)) is True and len(rows) == 2
    assert (go(0.05, with_sampler=False)) is False  # no sampler: shadow checks are off
