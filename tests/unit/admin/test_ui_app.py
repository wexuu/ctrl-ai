"""Unit tests for src/ctrl_ai/admin/app.py with FastAPI's test client and the gateway mocked."""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from ctrl_ai.admin import app as ui_app
from ctrl_ai.admin.routes import chat as routes_chat

MASTER = "sk-ctrl-ai-unit-master-0123456789"
CALL_ID = "0c3f0000-1111-2222-3333-444455556666"
BLOCK_MESSAGE = "Blocked by ctrl-ai: rule test-marker. Remove the flagged content and try again."
# The chat endpoint, /v1/chat/completions.
BLOCK_BODY = {
    "error": {
        "message": BLOCK_MESSAGE,
        "type": "invalid_request_error",
        "param": None,
        "code": "400",
        "provider_specific_fields": {
            "error": BLOCK_MESSAGE,
            "rule": "test-marker",
            "guardrail_name": "ctrl-ai",
            "guardrail_mode": "pre_call",
        },
    }
}
POLICY = b"""mode: enforce
scan: last_user_message
rules:
  - id: test-marker
    type: contains
    value: "CTRL-AI-BLOCK-TEST"
  - id: aws-access-key
    type: regex
    value: "AKIA[0-9A-Z]{16}"
jev:
  enabled: true
"""


class Gateway:
    """Stands in for the gateway: records requests and answers with a handler."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.handler = lambda req: httpx.Response(200, json={})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


@pytest.fixture
def gateway(monkeypatch, tmp_path):
    gw = Gateway()
    real_client = httpx.AsyncClient

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(gw)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", fake_client)
    monkeypatch.setenv("LITELLM_MASTER_KEY", MASTER)
    monkeypatch.setenv("CTRL_AI_GATEWAY_URL", "http://gateway:4000")
    monkeypatch.setenv("CTRL_AI_UI_MODELS", "chat-mistral,chat-groq,claude-haiku-4-5")
    monkeypatch.setenv("CTRL_AI_UI_KEYED_MODELS", ",chat-groq")
    policy = tmp_path / "policy.yaml"
    policy.write_bytes(POLICY)
    monkeypatch.setenv("CTRL_AI_POLICY_FILE", str(policy))
    monkeypatch.setenv("CTRL_AI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return gw


@pytest.fixture
def client(gateway):
    return TestClient(ui_app.create_app())


def _chat(client, text="hello", model="chat-groq"):
    return client.post("/api/chat", json={"model": model, "messages": [{"role": "user", "content": text}]})


def _assert_no_master(resp):
    assert MASTER not in resp.text
    assert all(MASTER not in v for v in resp.headers.values())


def test_health_and_page(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    # The dashboard is the home page; the chat page was replaced by the Jev audit log.
    page = client.get("/audit")
    assert page.status_code == 200 and "Jev audit log" in page.text
    assert client.get("/").status_code == 200
    assert client.get("/static/audit.js").status_code == 200
    assert "default-src 'self'" in page.headers["content-security-policy"]


def test_chat_allowed(client, gateway):
    gateway.handler = lambda req: httpx.Response(
        200,
        headers={"x-litellm-call-id": CALL_ID},
        json={"choices": [{"message": {"role": "assistant", "content": "hi there"}}]},
    )
    resp = _chat(client)
    assert resp.json() == {
        "status": "ok",
        "reply": "hi there",
        "message": None,
        "rule": None,
        "request_id": CALL_ID,
        "http_status": 200,
    }
    [req] = gateway.requests
    assert req.url == "http://gateway:4000/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {MASTER}"
    sent = json.loads(req.content)
    # MAX_TOKENS raised to 4096: Groq's reasoning model spent all 1024 on reasoning.
    assert sent == {
        "model": "chat-groq",
        "max_tokens": routes_chat.MAX_TOKENS,
        "stream": False,
        "messages": [{"role": "user", "content": "hello"}],
    }
    _assert_no_master(resp)


def test_chat_blocked(client, gateway):
    gateway.handler = lambda req: httpx.Response(400, headers={"x-litellm-call-id": CALL_ID}, json=BLOCK_BODY)
    body = _chat(client, "CTRL-AI-BLOCK-TEST please say hi").json()
    assert body["status"] == "blocked"
    assert body["rule"] == "test-marker"
    assert body["message"] == BLOCK_MESSAGE
    assert body["request_id"] == CALL_ID
    assert body["http_status"] == 400


def test_chat_gateway_error(client, gateway):
    gateway.handler = lambda req: httpx.Response(
        429, json={"error": {"message": "litellm.RateLimitError: slow down", "code": "429"}}
    )
    body = _chat(client).json()
    assert body["status"] == "error"
    assert body["http_status"] == 429
    assert "slow down" in body["message"]


def test_chat_other_400_is_error(client, gateway):
    gateway.handler = lambda req: httpx.Response(400, json={"error": {"message": "bad request"}})
    assert _chat(client).json()["status"] == "error"


def test_error_message_never_echoes_master_key(client, gateway):
    gateway.handler = lambda req: httpx.Response(401, json={"error": {"message": f"bad key {MASTER}"}})
    resp = _chat(client)
    assert resp.json()["status"] == "error"
    _assert_no_master(resp)


def test_chat_gateway_unreachable(client, gateway):
    def boom(req):
        raise httpx.ConnectError("refused", request=req)

    gateway.handler = boom
    body = _chat(client).json()
    assert body["status"] == "error"
    assert "unreachable" in body["message"]
    assert body["http_status"] is None


def test_chat_rejects_bad_role(client, gateway):
    resp = client.post("/api/chat", json={"model": "x", "messages": [{"role": "system", "content": "x"}]})
    assert resp.status_code == 422
    assert gateway.requests == []


def test_models_filtering(client, gateway):
    gateway.handler = lambda req: httpx.Response(
        200,
        json={
            "data": [
                {"id": "claude-opus-5-5"},
                {"id": "claude-haiku-4-5"},
                {"id": "chat-mistral"},
                {"id": "chat-groq"},
            ]
        },
    )
    body = client.get("/api/models").json()
    assert body["models"] == ["chat-groq", "claude-haiku-4-5"]
    assert {h["model"] for h in body["hidden"]} == {"chat-mistral"}
    assert body["message"] is None
    assert gateway.requests[0].headers["authorization"] == f"Bearer {MASTER}"


def test_models_not_listed_by_gateway(client, gateway, monkeypatch):
    monkeypatch.setenv("CTRL_AI_UI_MODELS", "chat-groq,nonexistent")
    client = TestClient(ui_app.create_app())  # settings are read when the app is created
    gateway.handler = lambda req: httpx.Response(200, json={"data": [{"id": "chat-groq"}]})
    assert client.get("/api/models").json()["models"] == ["chat-groq"]


def test_models_empty_gives_clear_message(client, gateway, monkeypatch):
    monkeypatch.setenv("CTRL_AI_UI_KEYED_MODELS", ",")
    monkeypatch.setenv("CTRL_AI_UI_MODELS", "chat-mistral,chat-groq")
    client = TestClient(ui_app.create_app())
    gateway.handler = lambda req: httpx.Response(
        200, json={"data": [{"id": "chat-mistral"}, {"id": "chat-groq"}]}
    )
    body = client.get("/api/models").json()
    assert body["models"] == []
    assert "MISTRAL_API_KEY" in body["message"]


def test_models_gateway_unreachable(client, gateway):
    def boom(req):
        raise httpx.ConnectError("refused", request=req)

    gateway.handler = boom
    body = client.get("/api/models").json()
    assert body["models"] == [] and "unreachable" in body["message"]


def test_policy(client):
    body = client.get("/api/policy").json()
    assert body["mode"] == "enforce"
    assert body["version"] == hashlib.sha256(POLICY).hexdigest()[:8]
    assert body["rules"] == [
        {"id": "test-marker", "type": "contains"},
        {"id": "aws-access-key", "type": "regex"},
    ]
    assert body["jev_enabled"] is True
    assert "CTRL-AI-BLOCK-TEST" not in json.dumps(body)


def test_policy_invalid_and_missing(client, monkeypatch, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just a list\n")
    monkeypatch.setenv("CTRL_AI_POLICY_FILE", str(bad))
    assert TestClient(ui_app.create_app()).get("/api/policy").json()["error"]
    monkeypatch.setenv("CTRL_AI_POLICY_FILE", str(tmp_path / "missing.yaml"))
    assert TestClient(ui_app.create_app()).get("/api/policy").json()["error"]


def test_audit_endpoint(client, tmp_path):
    (tmp_path / "audit.jsonl").write_text(
        json.dumps({"type": "decision", "request_id": "r1", "decision": "allow"})
        + "\n"
        + json.dumps({"type": "usage", "request_id": "r1", "status": "success"})
        + "\n"
    )
    recs = client.get("/api/audit?limit=5").json()["records"]
    assert [r["request_id"] for r in recs] == ["r1"] and recs[0]["has_usage"]
    assert client.get("/api/audit?request_id=zzz").json()["records"] == []


def test_audit_missing_file(client):
    assert client.get("/api/audit").json() == {"records": []}


def test_master_key_in_no_response(client, gateway):
    gateway.handler = lambda req: httpx.Response(
        200,
        headers={"x-litellm-call-id": CALL_ID},
        json={"data": [{"id": "chat-groq"}], "choices": [{"message": {"content": "ok"}}]},
    )
    for resp in (
        client.get("/"),
        client.get("/static/audit.js"),
        client.get("/static/audit.html"),
        client.get("/static/style.css"),
        client.get("/api/health"),
        client.get("/api/models"),
        client.get("/api/policy"),
        client.get("/api/audit"),
        _chat(client),
    ):
        _assert_no_master(resp)
