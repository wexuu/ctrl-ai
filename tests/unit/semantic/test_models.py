"""Decision models: the Score shape, the Jev and LiteLLM adapters, and model specs."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from ctrl_ai.semantic import judge
from ctrl_ai.semantic.jev.settings import Settings as JevSettings
from ctrl_ai.semantic.models import (
    PLACEHOLDER_API_KEY,
    JevModel,
    LiteLLMModel,
    Score,
    StaticModel,
    build_model,
)

JEV = JevSettings(
    api_key="jev-unit-test-key", url="http://jev.test/v1/systemone", timeout_s=2.0, model="jev-1.13.0"
)
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
JUDGE_KEYS = {"status", "score", "model", "latency_ms", "cost_usd", "error", "category"}


class FakeResponse:
    def __init__(self, content):
        self.choices = [type("C", (), {"message": type("M", (), {"content": content})()})()]
        self.usage = type("U", (), {"prompt_tokens": 100, "completion_tokens": 20})()
        self._hidden_params = {"response_cost": 0.0001}


def answering(*contents):
    """A completion stand-in that answers the given contents in turn and records its calls."""
    answers = iter(contents)
    calls: list[dict] = []

    async def completion(**kwargs):
        calls.append(kwargs)
        return FakeResponse(next(answers))

    return completion, calls


# ---------------------------------------------------------------- Score


def test_jev_verdict_round_trips_through_score():
    verdict = {
        "status": "ok",
        "attack": 0.98,
        "answers": {"instruction_override": 0.98, "harmful_misuse": 0.01},
        "model": "jev-1.13.0",
        "input_tokens": 301,
        "cost_usd": 0.000012642,
        "latency_ms": 141.2,
        "truncated": True,
        "error": None,
    }
    score = Score.from_jev(verdict)
    assert score.ok and score.score == 0.98 and score.truncated
    assert score.jev_row() == verdict


@pytest.mark.parametrize(
    "status, error", [("unavailable", "timeout"), ("error", "bad_json"), ("disabled", None)]
)
def test_jev_failures_keep_their_status_and_nulls(status, error):
    verdict = dict.fromkeys(JEV_KEYS) | {
        "status": status,
        "error": error,
        "latency_ms": 3.0,
        "truncated": False,
    }
    score = Score.from_jev(verdict)
    assert not score.ok and score.score is None
    assert score.jev_row() == verdict


def test_judge_row_has_the_judge_keys_and_drops_the_reason():
    row = Score("ok", score=0.9, model="m", category="harmful", reason="paraphrase of the prompt").judge_row()
    assert set(row) == JUDGE_KEYS and row["category"] == "harmful"
    assert "paraphrase" not in json.dumps(row)


def test_unavailable_and_skipped_render_like_the_jev_contract():
    assert Score.skipped().jev_row() == dict.fromkeys(JEV_KEYS) | {
        "status": "skipped",
        "latency_ms": 0.0,
        "truncated": False,
    }
    row = Score.unavailable("circuit_open").jev_row()
    assert (row["status"], row["error"], row["attack"]) == ("unavailable", "circuit_open", None)


# ---------------------------------------------------------------- Jev


def test_jev_model_uses_its_settings_not_the_environment(monkeypatch):
    monkeypatch.setenv("JEV_API_KEY", "")  # would disable Jev if it were read
    seen: list[httpx.Request] = []

    def reply(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "answers": {"indirect_injection": {"noul": 0.7}, "harmful_misuse": {"noul": 0.1}},
                "usage": {"input_tokens": 10},
                "model": "jev-1.13.0",
            },
        )

    model = JevModel(JEV, transport=httpx.MockTransport(reply))
    score = asyncio.run(model.score("text", "tool_result"))
    assert (
        score.ok
        and score.score == 0.7
        and score.answers == {"indirect_injection": 0.7, "harmful_misuse": 0.1}
    )
    assert str(seen[0].url) == JEV.url and seen[0].headers["authorization"] == f"Bearer {JEV.api_key}"
    sampled = asyncio.run(model.sample("text", "tool_result", 5))
    assert len(seen) == 2  # deterministic: one call stands for the sample
    assert sampled.score == 0.7 and sampled.shadow_row()["yes"] == 1


def test_jev_model_without_a_key_is_disabled():
    score = asyncio.run(JevModel(JevSettings("", JEV.url, 2.0, JEV.model)).score("text", "prompt"))
    assert (score.status, score.score) == ("disabled", None)


# ---------------------------------------------------------------- LiteLLM


@pytest.mark.parametrize(
    "content, score",
    [
        ('{"attack": 0.8, "category": "harmful", "reason": "x"}', 0.8),
        ('Sure. {"attack": 0.3, "category": "none", "reason": "fine"} done', 0.3),
        ('{"attack": 7}', 1.0),
        ('{"attack": -2}', 0.0),
        ('{"verdict":1,"category":"exfiltration","reason":"sends keys"}', 1.0),
        ('{"verdict": 0, "category": "none"}', 0.0),
        ("no json at all", None),
        ('{"attack": "high"}', None),
        (None, None),
    ],
)
def test_judge_parsing(content, score):
    assert judge.parse_verdict(content) == score


def test_judge_details_are_one_line():
    content = '{"verdict":1,"category":"exfiltration","reason":"sends\\n keys out"}'
    assert judge.parse_details(content) == ("exfiltration", "sends keys out")


def test_litellm_model_ok():
    completion, calls = answering('{"attack": 0.9, "category": "harmful", "reason": "r"}')
    model = LiteLLMModel(
        "groq/openai/gpt-oss-safeguard-20b",
        timeout_s=3,
        provider_keys={"groq": "gsk-test", "anthropic": "sk-ant-test"},
        completion=completion,
    )
    score = asyncio.run(model.score("text", "prompt"))
    assert (score.status, score.score, score.cost_usd, score.category) == ("ok", 0.9, 0.0001, "harmful")
    assert score.model == "groq/openai/gpt-oss-safeguard-20b"
    [call] = calls
    assert call["messages"][0]["content"].startswith("CTRL-AI-JUDGE") and call["num_retries"] == 0
    assert call["api_key"] == "gsk-test" and call["timeout"] == 3 and call["reasoning_effort"] == "low"
    assert call["temperature"] == 0.0 and "api_base" not in call


def test_litellm_model_unparseable_and_failures():
    completion, _ = answering("I cannot help")
    assert (
        asyncio.run(LiteLLMModel("anthropic/m", completion=completion).score("t", "prompt")).status == "error"
    )

    async def slow(**kwargs):
        await asyncio.sleep(5)

    score = asyncio.run(LiteLLMModel("anthropic/m", timeout_s=0.2, completion=slow).score("t", "prompt"))
    assert (score.status, score.error) == ("unavailable", "timeout")

    async def boom(**kwargs):
        raise RuntimeError("secret detail")

    score = asyncio.run(LiteLLMModel("anthropic/m", completion=boom).score("t", "prompt"))
    assert score.status == "unavailable" and "secret detail" not in json.dumps(score.judge_row())


def test_litellm_sample_reports_the_share_of_yes_answers():
    completion, calls = answering(
        '{"verdict":1,"category":"harmful","reason":"r"}',
        '{"verdict":0}',
        "garbage",
        '{"verdict":1,"category":"harmful","reason":"r"}',
        '{"verdict":0}',
    )
    score = asyncio.run(LiteLLMModel("groq/x", completion=completion).sample("text", "prompt", 5))
    second = score.shadow_row()
    assert (second["samples"], second["answered"], second["yes"], second["p"]) == (5, 4, 2, 0.5)
    assert second["categories"] == ["harmful"] and {c["temperature"] for c in calls} == {1.0}


def test_local_server_gets_a_placeholder_key():
    local = LiteLLMModel("openai/llama3.1", api_base="http://localhost:11434/v1")
    kwargs = local.request("t", "prompt", 0.0)
    assert kwargs["api_base"] == "http://localhost:11434/v1" and kwargs["api_key"] == PLACEHOLDER_API_KEY
    assert "reasoning_effort" not in kwargs
    # A configured key wins over the placeholder; without an api_base LiteLLM finds its own key.
    keyed = LiteLLMModel("anthropic/m", api_base="http://stub:9001", provider_keys={"anthropic": "sk-ant-x"})
    assert keyed.request("t", "prompt", 0.0)["api_key"] == "sk-ant-x"
    assert "api_key" not in LiteLLMModel("openai/gpt-4o-mini").request("t", "prompt", 0.0)


# ---------------------------------------------------------------- specs and the static model


def test_build_model_specs():
    assert build_model("none") is None and build_model("") is None and build_model(None) is None
    assert isinstance(build_model("jev", jev_settings=JEV), JevModel)
    assert isinstance(build_model(" JEV ", jev_settings=JEV), JevModel)
    model = build_model("openai/llama3.1", api_base="http://localhost:11434/v1", timeout_s=4)
    assert isinstance(model, LiteLLMModel) and model.name == "openai/llama3.1"
    assert (model.api_base, model.timeout_s) == ("http://localhost:11434/v1", 4)
    with pytest.raises(ValueError):
        build_model("jev")


def test_static_model_records_calls_and_samples_once():
    model = StaticModel(0.8, category="harmful")
    assert asyncio.run(model.score("t", "prompt")).score == 0.8
    second = asyncio.run(model.sample("t", "prompt", 5)).shadow_row()
    assert (second["samples"], second["yes"], second["categories"]) == (1, 1, ["harmful"])
    assert model.calls == [("t", "prompt"), ("t", "prompt")]
    down = StaticModel(status="unavailable", error="timeout")
    assert asyncio.run(down.score("t", "prompt")).jev_row()["status"] == "unavailable"
