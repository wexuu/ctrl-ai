"""Unit tests for the admin app's home page, health check, audit data and policy summary."""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from ctrl_ai.admin import app as ui_app

MASTER = "sk-ctrl-ai-unit-master-0123456789"
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


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("LITELLM_MASTER_KEY", MASTER)
    policy = tmp_path / "policy.yaml"
    policy.write_bytes(POLICY)
    monkeypatch.setenv("CTRL_AI_POLICY_FILE", str(policy))
    monkeypatch.setenv("CTRL_AI_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return TestClient(ui_app.create_app())


def _assert_no_master(resp):
    assert MASTER not in resp.text
    assert all(MASTER not in v for v in resp.headers.values())


def test_health_and_page(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    # The dashboard is the home page.
    page = client.get("/audit")
    assert page.status_code == 200 and "Jev audit log" in page.text
    assert client.get("/").status_code == 200
    assert client.get("/static/audit.js").status_code == 200
    assert "default-src 'self'" in page.headers["content-security-policy"]


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


def test_master_key_in_no_response(client):
    for resp in (
        client.get("/"),
        client.get("/static/audit.js"),
        client.get("/static/audit.html"),
        client.get("/static/style.css"),
        client.get("/api/health"),
        client.get("/api/policy"),
        client.get("/api/audit"),
    ):
        _assert_no_master(resp)
