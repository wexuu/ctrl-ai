from __future__ import annotations

import asyncio
import copy
import json
import os
import time
from pathlib import Path

import pytest

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.filestore import FileStore
from ctrl_ai.core.policy import PolicyStore
from ctrl_ai.core.settings import Settings
from ctrl_ai.pipeline import runtime
from ctrl_ai.pipeline.engine import Engine
from ctrl_ai.semantic.models import JevModel, LiteLLMModel, Score

PROMPT = "PROMPT-TEXT-zx81 please summarise this"
BLOCKED_PROMPT = "PROMPT-TEXT-zx81 with CTRL-AI-BLOCK-TEST inside"

ROW_KEYS = {
    "type",
    "ts",
    "request_id",
    "endpoint",
    "model",
    "stream",
    "mode",
    "decision",
    "would_block",
    "rule",
    "policy_version",
    "text_chars",
    "jev",
    "guard_ms",
    # every new row carries these as well.
    "v",
    "team",
    "department",
    "user",
    "key_id",
    "profile",
    "model_requested",
    "model_routed",
    "route_reason",
    "findings",
    "data_class_detected",
    "normalisation",
    "masked",
    "semantic",
    "judge",
    "flagged",
    "loop",
    "budget",
    "break_glass",
}
JEV_KEYS = {
    "status",
    "attack",
    "answers",
    "model",
    "input_tokens",
    "cost_usd",
    "latency_ms",
    "truncated",
    "error",
}
SKIPPED = {
    "status": "skipped",
    "attack": None,
    "answers": None,
    "model": None,
    "input_tokens": None,
    "cost_usd": None,
    "latency_ms": 0.0,
    "truncated": False,
    "error": None,
}
OK_VERDICT = {
    "status": "ok",
    "attack": 0.98,
    "answers": {"instruction_override": 0.98},
    "model": "jev-1.13.0",
    "input_tokens": 301,
    "cost_usd": 0.000012642,
    "latency_ms": 141.2,
    "truncated": False,
    "error": None,
}


class FakeJev:
    """A classifier that answers with a fixed Jev verdict and records the texts it saw."""

    name = "jev"

    def __init__(self, verdict=None, answer=None):
        self.verdict = OK_VERDICT if verdict is None else verdict
        self.answer = answer  # an async function of the text, replacing the fixed verdict
        self.calls: list[str] = []

    async def score(self, text: str, source: str) -> Score:
        self.calls.append(text)
        if self.answer is not None:
            return Score.from_jev(await self.answer(text))
        return Score.from_jev(self.verdict)

    async def sample(self, text: str, source: str, n: int) -> Score:
        return await self.score(text, source)


class Env:
    """A policy file, an audit file and a fake Jev, wired into an Engine."""

    def __init__(self, tmp_path):
        self.policy_path = tmp_path / "policy.yaml"
        self.audit_path = tmp_path / "audit.jsonl"
        self.store = PolicyStore(str(self.policy_path))
        self.audit = AuditLog(str(self.audit_path))
        self.jev = FakeJev()
        self.set_policy()

    def set_policy(self, mode: str = "enforce", jev_enabled: bool = True) -> None:
        before_ns = self.policy_path.stat().st_mtime_ns if self.policy_path.exists() else 0
        self.policy_path.write_text(
            f"mode: {mode}\n"
            "rules:\n"
            "  - id: test-marker\n"
            "    type: contains\n"
            '    value: "CTRL-AI-BLOCK-TEST"\n'
            f"jev:\n  enabled: {str(jev_enabled).lower()}\n",
            encoding="utf-8",
        )
        # Coarse filesystem timestamps (ext4) can give two quick writes the same mtime; a same-size
        # rewrite would then go unnoticed, so move the mtime forward explicitly.
        mtime_ns = max(time.time_ns(), before_ns + 1_000_000_000)
        os.utime(self.policy_path, ns=(mtime_ns, mtime_ns))

    def engine(self, policy_store=None, audit=None, **kwargs) -> Engine:
        return Engine(
            policy_store=self.store if policy_store is None else policy_store,
            audit=self.audit if audit is None else audit,
            **kwargs,
        )

    async def run(self, data, *, policy_store=None, classifier_timeout_s=2.0, **kwargs):
        kwargs.setdefault("classifier", self.jev)
        engine = self.engine(policy_store, classifier_timeout_s=classifier_timeout_s)
        return await engine.evaluate(data, request_id="req-1", **kwargs)

    def rows(self) -> list[dict]:
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def messages(text: str, **extra) -> dict:
    return {"model": "claude-opus-5-5", "messages": [{"role": "user", "content": text}], **extra}


@pytest.mark.asyncio
async def test_block_in_enforce_mode_skips_jev(env):
    decision = await env.run(messages(BLOCKED_PROMPT, stream=True), call_type="anthropic_messages")

    assert decision.decision == "block"
    assert decision.rule == "test-marker"
    assert decision.would_block is True
    assert decision.message == (
        "Blocked by ctrl-ai: rule test-marker. Remove the flagged content and try again."
    )
    assert env.jev.calls == []

    [row] = env.rows()
    assert row == decision.row
    assert set(row) == ROW_KEYS
    assert row["type"] == "decision"
    assert row["request_id"] == "req-1"
    assert row["endpoint"] == "messages"
    assert row["model"] == "claude-opus-5-5"
    assert row["stream"] is True
    assert row["mode"] == "enforce"
    assert row["decision"] == "block"
    assert row["would_block"] is True
    assert row["rule"] == "test-marker"
    assert row["policy_version"] == env.store.current().version
    assert row["text_chars"] == len(BLOCKED_PROMPT)
    assert row["jev"] == SKIPPED
    assert isinstance(row["guard_ms"], float)


@pytest.mark.asyncio
async def test_allow_stores_the_jev_verdict_unchanged(env):
    decision = await env.run(messages(PROMPT), call_type="acompletion")

    assert (decision.decision, decision.rule, decision.would_block, decision.message) == (
        "allow",
        None,
        False,
        None,
    )
    assert env.jev.calls == [PROMPT]
    [row] = env.rows()
    assert set(row) == ROW_KEYS
    assert row["jev"] == OK_VERDICT
    assert row["endpoint"] == "chat_completions"
    assert row["stream"] is False
    assert row["rule"] is None


@pytest.mark.asyncio
async def test_monitor_mode_allows_and_records_would_block(env):
    env.set_policy(mode="monitor")
    decision = await env.run(messages(BLOCKED_PROMPT))

    assert decision.decision == "allow"
    assert decision.would_block is True
    assert decision.rule == "test-marker"
    assert decision.message is None
    assert env.jev.calls == [BLOCKED_PROMPT]
    [row] = env.rows()
    assert (row["mode"], row["decision"], row["would_block"], row["rule"]) == (
        "monitor",
        "allow",
        True,
        "test-marker",
    )
    assert row["jev"] == OK_VERDICT


@pytest.mark.asyncio
async def test_policy_change_applies_without_a_restart(env):
    assert (await env.run(messages(BLOCKED_PROMPT))).decision == "block"
    env.set_policy(mode="monitor")
    assert (await env.run(messages(BLOCKED_PROMPT))).decision == "allow"
    first, second = env.rows()
    assert first["policy_version"] != second["policy_version"]


@pytest.mark.asyncio
async def test_jev_is_skipped_when_switched_off_or_text_is_empty(env):
    await env.run(messages(""))
    env.set_policy(jev_enabled=False)
    await env.run(messages(PROMPT))

    assert env.jev.calls == []
    empty, switched_off = env.rows()
    assert empty["jev"] == SKIPPED and empty["text_chars"] == 0
    assert switched_off["jev"] == SKIPPED and switched_off["decision"] == "allow"


@pytest.mark.asyncio
async def test_jev_that_raises_gives_unavailable(env):
    async def broken(text: str) -> dict:
        raise RuntimeError(f"failed on {text}")

    decision = await env.run(messages(PROMPT), classifier=FakeJev(answer=broken))

    assert decision.decision == "allow"
    [row] = env.rows()
    assert set(row) == ROW_KEYS
    assert set(row["jev"]) == JEV_KEYS
    assert row["jev"]["status"] == "unavailable"
    assert row["jev"]["attack"] is None
    assert PROMPT not in json.dumps(row)


@pytest.mark.asyncio
async def test_slow_jev_gives_unavailable_within_the_limit(env):
    async def slow(text: str) -> dict:
        await asyncio.sleep(5)
        return OK_VERDICT

    started = time.perf_counter()
    decision = await env.run(messages(PROMPT), classifier=FakeJev(answer=slow), classifier_timeout_s=0.1)
    elapsed = time.perf_counter() - started

    assert decision.decision == "allow"
    assert 0.5 < elapsed < 1.5  # the Jev timeout plus half a second
    [row] = env.rows()
    assert set(row["jev"]) == JEV_KEYS
    assert (row["jev"]["status"], row["jev"]["error"]) == ("unavailable", "timeout")


@pytest.mark.asyncio
async def test_engine_without_a_jev_client_records_not_configured(env):
    decision = await env.engine().evaluate(messages(PROMPT))

    assert decision.decision == "allow"
    [row] = env.rows()
    assert set(row["jev"]) == JEV_KEYS
    assert (row["jev"]["status"], row["jev"]["error"]) == ("unavailable", "not_configured")


@pytest.mark.asyncio
async def test_policy_store_that_raises_fails_open(env):
    class BrokenStore:
        def current(self):
            raise RuntimeError(f"cannot load policy for {BLOCKED_PROMPT}")

    decision = await env.run(messages(BLOCKED_PROMPT), policy_store=BrokenStore())

    assert (decision.decision, decision.message) == ("allow", None)
    [row] = env.rows()
    assert set(row) == ROW_KEYS | {"error"}
    assert row["error"] == "internal: RuntimeError"
    assert row["decision"] == "allow"
    assert BLOCKED_PROMPT not in json.dumps(row)


@pytest.mark.asyncio
@pytest.mark.parametrize("garbage", [None, "a string", 42, []])
async def test_garbage_request_fails_open(env, garbage):
    decision = await env.run(garbage)
    assert decision.decision == "allow"
    [row] = env.rows()
    assert row["error"].startswith("internal: ")


@pytest.mark.asyncio
async def test_audit_that_raises_does_not_escape(env):
    class BrokenAudit:
        def write(self, row):
            raise OSError("disk full")

    decision = await env.engine(audit=BrokenAudit()).evaluate(messages(BLOCKED_PROMPT), classifier=env.jev)
    assert decision.decision == "block"


@pytest.mark.asyncio
async def test_audit_file_never_contains_the_request_text(env):
    await env.run(messages(BLOCKED_PROMPT), call_type="anthropic_messages")
    env.set_policy(mode="monitor")
    await env.run(messages(BLOCKED_PROMPT))
    await env.run({"model": "claude-opus-5-5", "input": PROMPT}, call_type="aresponses")
    await env.run(messages(PROMPT), policy_store=object())  # internal failure

    content = env.audit_path.read_text(encoding="utf-8")
    assert len(content.splitlines()) == 4
    assert "PROMPT-TEXT-zx81" not in content
    assert "CTRL-AI-BLOCK-TEST" not in content


@pytest.mark.asyncio
async def test_only_the_listed_request_keys_are_read(env):
    class Recorder(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.read: set[str] = set()

        def get(self, key, default=None):
            self.read.add(key)
            return super().get(key, default)

        def __getitem__(self, key):
            self.read.add(key)
            return super().__getitem__(key)

        def __contains__(self, key):
            self.read.add(key)
            return super().__contains__(key)

    data = Recorder(
        messages(PROMPT),
        secret_fields={"raw_headers": {"authorization": "Bearer TOKEN"}},
        proxy_server_request={"headers": {}},
        litellm_call_id="abc",
    )
    await env.run(data)  # no call_type, so the body-shape fallback runs too

    # proxy_server_request is read for the user-agent and x-app header values only;
    # secret_fields only for the prefix of the Authorization header (route decision).
    # litellm_session_id identifies the session for loop caps.
    assert data.read <= {
        "messages",
        "input",
        "model",
        "stream",
        "system",
        "proxy_server_request",
        "secret_fields",
        "litellm_session_id",
        # budget estimate
        "max_tokens",
        "max_output_tokens",
        "max_completion_tokens",
    }
    assert "TOKEN" not in env.audit_path.read_text(encoding="utf-8")


def test_build_engine_wires_the_configured_paths(tmp_path):
    env = {
        "CTRL_AI_POLICY_FILE": str(tmp_path / "policy.yaml"),
        "CTRL_AI_MODELS_FILE": str(tmp_path / "models.yaml"),
        "CTRL_AI_TEAMS_FILE": str(tmp_path / "teams.yaml"),
        "CTRL_AI_SIGNATURES_FILE": str(tmp_path / "signatures.yaml"),
        "CTRL_AI_BREAKGLASS_FILE": str(tmp_path / "break_glass.json"),
        "CTRL_AI_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
        "CTRL_AI_MASKING_SECRET": "mask-secret",
        "CTRL_AI_BREAKGLASS_SECRET": "glass-secret",
        "JEV_TIMEOUT_S": "1.5",
        "CTRL_AI_SHADOW": "0",
    }
    (tmp_path / "policy.yaml").write_text("mode: enforce\nrules: []\n", encoding="utf-8")
    built = runtime.build_engine(Settings.from_env(env))

    assert isinstance(built.policy_store, PolicyStore)
    assert built.policy_store.current().mode == "enforce"  # read from the given file
    assert isinstance(built.audit, AuditLog)
    built.audit.write({"type": "probe"})
    assert json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8")) == {"type": "probe"}
    for store, name in (
        (built.catalogue, "CTRL_AI_MODELS_FILE"),
        (built.teams, "CTRL_AI_TEAMS_FILE"),
        (built.signatures, "CTRL_AI_SIGNATURES_FILE"),
        (built.break_glass_register, "CTRL_AI_BREAKGLASS_FILE"),
    ):
        assert isinstance(store, FileStore)
        assert store.path == env[name]
    assert (built.masking_secret, built.break_glass_secret) == ("mask-secret", "glass-secret")
    assert built.classifier_timeout_s == 1.5  # JEV_TIMEOUT_S, since the classifier is Jev
    assert isinstance(built.classifier, JevModel) and built.classifier.settings.timeout_s == 1.5
    assert isinstance(built.judge, LiteLLMModel) and built.judge.name == "groq/openai/gpt-oss-safeguard-20b"
    assert built.shadow is None  # CTRL_AI_SHADOW=0


def test_build_engine_models_per_role(tmp_path):
    env = {
        "CTRL_AI_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
        "CTRL_AI_CLASSIFIER_MODEL": "none",
        "CTRL_AI_JUDGE_MODEL": "openai/llama3.1",
        "CTRL_AI_JUDGE_API_BASE": "http://localhost:11434/v1",
        "CTRL_AI_JUDGE_TIMEOUT_S": "20",
    }
    built = runtime.build_engine(Settings.from_env(env))

    assert built.classifier is None
    assert isinstance(built.judge, LiteLLMModel) and built.judge.timeout_s == 20
    assert built.judge.request("t", "prompt", 0.0)["api_base"] == "http://localhost:11434/v1"
    # The shadow check defaults to the judge's model and endpoint.
    assert isinstance(built.shadow, LiteLLMModel) and built.shadow.name == "openai/llama3.1"
    assert built.shadow.api_base == "http://localhost:11434/v1"
    assert built.classifier_timeout_s == 8.0  # CTRL_AI_CLASSIFIER_TIMEOUT_S default


@pytest.mark.asyncio
async def test_the_cached_context_keeps_no_request_text(tmp_path):
    fixtures = Path(__file__).resolve().parents[2] / "fixtures" / "config"
    engine = Engine(
        policy_store=PolicyStore(str(fixtures / "policy.yaml")),
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
        masking_secret="ctrl-ai-test-masking-secret",
        classifier=FakeJev(),
    )
    iban = "PL61 1090 1014 0000 0712 1981 2874"
    body = messages(f"{PROMPT} for {iban}")
    ctx = await engine.pre_call(copy.deepcopy(body), request_id="req-text")
    assert ctx.pieces and ctx.semantic_texts  # the checks still need the text before the decision

    decision = await engine.evaluate(body, request_id="req-text")
    cached = engine.cache.get("req-text")
    assert cached is decision.ctx and decision.row["text_chars"] > 0
    assert cached.pieces == [] and cached.semantic_texts == {}
    # The surrogate map stays: the restore hook needs it until the response is done.
    assert iban in cached.mask_map.values()
