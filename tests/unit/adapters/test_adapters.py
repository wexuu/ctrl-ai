"""The two LiteLLM adapters, run against stand-ins for LiteLLM and FastAPI.

LiteLLM must not be installed on the host, so these tests put minimal fake
modules in ``sys.modules``. They cover our logic in the adapters; that the
real LiteLLM calls them as expected is checked in a container by the end-to-end suite.
"""

from __future__ import annotations

import importlib
import json
import sys
import types
from pathlib import Path

import pytest

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.policy import PolicyStore
from ctrl_ai.core.rows import jev_verdict
from ctrl_ai.pipeline.ctxcache import ContextCache
from ctrl_ai.pipeline.engine import Engine

ADAPTERS = ("ctrl_ai.adapters.litellm.guardrail", "ctrl_ai.adapters.litellm.logger")
POLICY_FILE = Path(__file__).resolve().parents[2] / "fixtures" / "config" / "policy.yaml"


def make_engine(audit_path: Path) -> Engine:
    return Engine(
        policy_store=PolicyStore(str(POLICY_FILE)), audit=AuditLog(str(audit_path)), cache=ContextCache()
    )


class FakeHTTPException(Exception):
    def __init__(self, status_code, detail, headers=None):
        super().__init__(status_code)
        self.status_code = status_code
        self.detail = detail
        self.headers = headers


class FakeCustomGuardrail:
    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
        self.guardrail_name = kwargs.get("guardrail_name")
        self.recorded: list[dict] = []

    def add_standard_logging_guardrail_information_to_request_data(self, **kwargs):
        self.recorded.append(kwargs)


class FakeCustomLogger:
    pass


@pytest.fixture
def fakes(monkeypatch):
    """Install the stand-in modules; returns the list of applied-guardrail header calls."""
    header_calls: list[dict] = []

    def module(name: str, **attrs) -> None:
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, mod)

    module("fastapi", HTTPException=FakeHTTPException)
    for name in ("litellm", "litellm.integrations", "litellm.proxy", "litellm.proxy.common_utils"):
        module(name)
    module("litellm.integrations.custom_guardrail", CustomGuardrail=FakeCustomGuardrail)
    module("litellm.integrations.custom_logger", CustomLogger=FakeCustomLogger)
    module(
        "litellm.proxy.common_utils.callback_utils",
        add_guardrail_to_applied_guardrails_header=lambda **kwargs: header_calls.append(kwargs),
    )
    for name in ADAPTERS:
        sys.modules.pop(name, None)
    yield header_calls
    for name in ADAPTERS:
        sys.modules.pop(name, None)


def decision(kind: str, rule: str | None = None, jev: dict | None = None):
    """the adapter now gets a RequestContext from hooks.before_call."""
    from ctrl_ai.core.context import RequestContext

    message = f"Blocked by ctrl-ai: rule {rule}. Remove the flagged content and try again."
    ctx = RequestContext(request_id="call-1")
    ctx.decision, ctx.rule, ctx.would_block = kind, rule, rule is not None
    ctx.message = message if kind == "block" else None
    ctx.jev = jev or jev_verdict("skipped")
    return ctx


# --- guardrail ---------------------------------------------------------------


@pytest.fixture
def guardrail_module(fakes, tmp_path, monkeypatch):
    module = importlib.import_module("ctrl_ai.adapters.litellm.guardrail")
    module.engine = make_engine(tmp_path / "audit.jsonl")
    monkeypatch.setattr(module, "get_engine", lambda: module.engine)
    return module


def make_guardrail(module, monkeypatch, result):
    calls: list[dict] = []

    async def fake_before_call(engine, data, call_type, user_api_key_dict):
        calls.append(
            {
                "engine": engine,
                "data": data,
                "call_type": call_type,
                "request_id": data.get("litellm_call_id"),
            }
        )
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(module.hooks, "before_call", fake_before_call)
    guardrail = module.CtrlAiGuardrail(
        guardrail_name="ctrl-ai", event_hook="pre_call", default_on=True, extra="x"
    )
    return guardrail, calls


def test_guardrail_does_not_define_apply_guardrail(guardrail_module):
    assert not hasattr(guardrail_module.CtrlAiGuardrail, "apply_guardrail")


@pytest.mark.asyncio
async def test_guardrail_passes_constructor_kwargs_to_the_parent(guardrail_module, monkeypatch):
    guardrail, _ = make_guardrail(guardrail_module, monkeypatch, decision("allow"))
    assert guardrail.init_kwargs == {
        "guardrail_name": "ctrl-ai",
        "event_hook": "pre_call",
        "default_on": True,
        "extra": "x",
    }


@pytest.mark.asyncio
async def test_guardrail_allow_returns_the_same_data_and_records_the_outcome(
    guardrail_module, monkeypatch, fakes
):
    jev = {**jev_verdict("ok"), "attack": 0.4}
    guardrail, calls = make_guardrail(guardrail_module, monkeypatch, decision("allow", jev=jev))
    data = {"litellm_call_id": "call-1", "messages": [{"role": "user", "content": "PROMPT-TEXT"}]}

    assert await guardrail.async_pre_call_hook(None, None, data, "anthropic_messages") is data

    # the adapter also passes the caller's identity (and more context) to the engine.
    assert [{k: c[k] for k in ("data", "call_type", "request_id")} for c in calls] == [
        {"data": data, "call_type": "anthropic_messages", "request_id": "call-1"}
    ]
    assert calls[0]["engine"] is guardrail_module.engine
    assert fakes == [{"request_data": data, "guardrail_name": "ctrl-ai"}]
    [recorded] = guardrail.recorded
    # Jev runs in the during-call hook now; the pre-call record carries decision and findings.
    assert recorded["guardrail_json_response"] == {"decision": "allow", "rule": None, "findings": 0}
    assert recorded["guardrail_status"] == "success"
    assert recorded["guardrail_provider"] == "ctrl-ai"
    assert recorded["request_data"] is data
    assert "PROMPT-TEXT" not in json.dumps(recorded["guardrail_json_response"])


@pytest.mark.asyncio
async def test_guardrail_block_raises_http_400(guardrail_module, monkeypatch, fakes):
    guardrail, _ = make_guardrail(guardrail_module, monkeypatch, decision("block", "test-marker"))

    with pytest.raises(FakeHTTPException) as raised:
        await guardrail.async_pre_call_hook(None, None, {"litellm_call_id": "call-1"}, "acompletion")

    assert raised.value.status_code == 400
    assert raised.value.detail == {
        "error": "Blocked by ctrl-ai: rule test-marker. Remove the flagged content and try again.",
        "rule": "test-marker",
    }
    assert fakes == []  # LiteLLM adds the header itself on a block
    assert guardrail.recorded[0]["guardrail_status"] == "guardrail_intervened"


@pytest.mark.asyncio
async def test_guardrail_lets_the_request_through_when_evaluate_raises(guardrail_module, monkeypatch):
    guardrail, _ = make_guardrail(guardrail_module, monkeypatch, RuntimeError("bug"))
    data = {"litellm_call_id": "call-1"}
    assert await guardrail.async_pre_call_hook(None, None, data, "acompletion") is data


@pytest.mark.asyncio
async def test_guardrail_survives_a_failure_in_the_bookkeeping(guardrail_module, monkeypatch):
    def broken(**kwargs):
        raise RuntimeError("bookkeeping bug")

    monkeypatch.setattr(guardrail_module, "add_guardrail_to_applied_guardrails_header", broken)
    guardrail, _ = make_guardrail(guardrail_module, monkeypatch, decision("allow"))
    data = {"litellm_call_id": "call-1"}
    assert await guardrail.async_pre_call_hook(None, None, data, "acompletion") is data

    guardrail, _ = make_guardrail(guardrail_module, monkeypatch, decision("block", "test-marker"))
    monkeypatch.setattr(guardrail, "add_standard_logging_guardrail_information_to_request_data", broken)
    with pytest.raises(FakeHTTPException):
        await guardrail.async_pre_call_hook(None, None, data, "acompletion")


# --- logger ------------------------------------------------------------------


@pytest.fixture
def logger_module(fakes, tmp_path, monkeypatch):
    module = importlib.import_module("ctrl_ai.adapters.litellm.logger")
    module.audit_path = tmp_path / "audit.jsonl"
    engine = make_engine(module.audit_path)
    monkeypatch.setattr(module, "get_engine", lambda: engine)
    return module


def slo(route: str = "/v1/messages", **overrides) -> dict:
    base = {
        "litellm_call_id": "call-1",
        "call_type": "anthropic_messages",
        "status": "success",
        "stream": None,
        "model": "anthropic/claude-opus-5-5",
        "model_group": "claude-opus-5-5",
        "prompt_tokens": 25,
        "completion_tokens": 12,
        "response_cost": 0.00034,
        "response_time": 0.8124,
        "messages": [{"role": "user", "content": "PROMPT-TEXT"}],
        "metadata": {"user_api_key_request_route": route},
        "error_information": {"error_class": "", "error_code": ""},
    }
    return {**base, **overrides}


def rows(module) -> list[dict]:
    if not module.audit_path.exists():
        return []
    return [json.loads(line) for line in module.audit_path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.asyncio
async def test_logger_writes_a_success_row(logger_module):
    kwargs = {"standard_logging_object": slo(), "api_key": "sk-ant-SECRET"}
    await logger_module.ctrl_ai_logger.async_log_success_event(kwargs, None, None, None)

    [row] = rows(logger_module)
    ts = row.pop("ts")
    assert ts.endswith("Z")
    # the v1 fields keep their values; the v2 fields are checked in test_rows.py.
    assert {
        k: row[k]
        for k in (
            "type",
            "request_id",
            "endpoint",
            "model",
            "stream",
            "status",
            "input_tokens",
            "output_tokens",
            "cost_usd",
            "total_ms",
            "error",
        )
    } == {
        "type": "usage",
        "request_id": "call-1",
        "endpoint": "messages",
        "model": "claude-opus-5-5",
        "stream": False,
        "status": "success",
        "input_tokens": 25,
        "output_tokens": 12,
        "cost_usd": 0.00034,
        "total_ms": 812.4,
        "error": None,
    }
    assert row["v"] == 2
    content = logger_module.audit_path.read_text(encoding="utf-8")
    assert "PROMPT-TEXT" not in content and "SECRET" not in content


@pytest.mark.asyncio
async def test_logger_writes_a_failure_row_for_a_blocked_request(logger_module):
    blocked = slo(
        call_type="acompletion",  # what LiteLLM reports for failed /v1/messages calls
        status="failure",
        stream=True,
        prompt_tokens=0,
        completion_tokens=0,
        response_cost=0.0,
        error_information={
            "error_class": "HTTPException",
            "error_code": "400",
            "error_message": "400: {'error': 'Blocked'}",
        },
    )
    await logger_module.ctrl_ai_logger.async_log_failure_event(
        {"standard_logging_object": blocked}, None, None, None
    )

    [row] = rows(logger_module)
    assert (row["endpoint"], row["status"], row["stream"], row["error"]) == (
        "messages",
        "failure",
        True,
        "HTTPException:400",
    )
    assert (row["input_tokens"], row["output_tokens"]) == (0, 0)


async def logged(module, standard_logging_object: dict) -> dict:
    await module.ctrl_ai_logger.async_log_success_event(
        {"standard_logging_object": standard_logging_object}, None, None, None
    )
    [row] = rows(module)
    return row


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route, endpoint",
    [
        ("/v1/messages", "messages"),
        ("/v1/chat/completions", "chat_completions"),
        ("/chat/completions", "chat_completions"),
        ("/v1/responses", "responses"),
    ],
)
async def test_logger_endpoint_comes_from_the_route(logger_module, route, endpoint):
    assert (await logged(logger_module, slo(route)))["endpoint"] == endpoint


@pytest.mark.asyncio
async def test_logger_model_falls_back_to_model(logger_module):
    assert (await logged(logger_module, slo(model_group=None)))["model"] == "anthropic/claude-opus-5-5"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"standard_logging_object": slo("/v1/models")},
        {"standard_logging_object": slo(metadata=None)},
        {"standard_logging_object": None},
        {},
        {"standard_logging_object": "garbage"},
        None,
    ],
)
async def test_logger_skips_other_routes_and_never_raises(logger_module, kwargs):
    await logger_module.ctrl_ai_logger.async_log_success_event(kwargs, None, None, None)
    await logger_module.ctrl_ai_logger.async_log_failure_event(kwargs, None, None, None)
    assert rows(logger_module) == []
