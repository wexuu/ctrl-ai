"""The admin app's pages and audit data against the test stack.

Requests go straight to the gateway; the admin app's audit endpoint must show them joined, with
the decision the gateway made and the policy version it used.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

from tests.e2e import harness as h
from tests.e2e.constants import BLOCK_MARKER, STUB_REPLY_PREFIX

UI_URL = os.environ.get("CTRL_AI_TEST_UI_URL", "http://localhost:4100").rstrip("/")
UI_RESPONSES: list[httpx.Response] = []


@pytest.fixture(scope="module")
def ui(stack):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if httpx.get(UI_URL + "/api/health", timeout=2).status_code == 200:
                return UI_URL
        except httpx.HTTPError:
            pass
        time.sleep(1)
    pytest.fail(f"The UI at {UI_URL} is not answering. Run `make test-up`.")


def _get(path: str) -> httpx.Response:
    resp = httpx.get(UI_URL + path, timeout=30)
    UI_RESPONSES.append(resp)
    return resp


def _gateway_chat(text: str) -> httpx.Response:
    """A chat request straight to the gateway, with the test key."""
    h.remember(text)
    return h.post_chat(h.chat_body(text))


def _record(request_id: str, *, need_usage: bool = True, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        recs = _get(f"/api/audit?limit=200&request_id={request_id}").json()["records"]
        if recs and recs[0]["decision"] and (recs[0]["has_usage"] or not need_usage):
            return recs[0]
        if time.monotonic() >= deadline:
            raise AssertionError(f"no complete audit record for {request_id} within {timeout}s: {recs}")
        time.sleep(0.2)


def test_page_served(ui):
    # The dashboard is the home page.
    home = _get("/")
    assert home.status_code == 303 and home.headers["location"] == "/dashboard"
    audit = _get("/audit")
    assert audit.status_code == 200 and "Jev audit log" in audit.text
    assert _get("/static/audit.js").status_code == 200
    assert _get("/static/style.css").status_code == 200


def test_audit_joins_an_allowed_request(ui):
    resp = _gateway_chat(f"hello from the audit test {h.tag()}")
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"].startswith(STUB_REPLY_PREFIX)
    rid = h.call_id(resp)
    assert rid, "x-litellm-call-id missing on an allowed response"
    rec = _record(rid)
    assert rec["decision"] == "allow"
    assert rec["rows"]["decisions"] and rec["rows"]["usage"]
    assert rec["status"] == "success"
    assert rec["endpoint"] == "chat_completions"


def test_audit_shows_a_blocked_request(ui):
    resp = _gateway_chat(f"{BLOCK_MARKER} please say hi {h.tag()}")
    assert resp.status_code == 400
    rid = h.call_id(resp)
    assert rid, "x-litellm-call-id missing on a blocked response"
    rec = _record(rid)
    assert rec["decision"] == "block" and rec["rule"] == "test-marker"
    assert rec["status"] == "failure"


def test_policy_matches_decisions(ui):
    pol = _get("/api/policy").json()
    assert pol["mode"] == "enforce"
    assert pol["version"] == h.policy_version(h.POLICY_FILE.read_text(encoding="utf-8"))
    resp = _gateway_chat(f"policy version check {h.tag()}")
    rec = _record(h.call_id(resp), need_usage=False)
    assert rec["policy_version"] == pol["version"]


def test_no_master_key_in_ui_responses(ui):
    assert UI_RESPONSES, "no UI responses recorded"
    for resp in UI_RESPONSES:
        assert h.TEST_KEY not in resp.text
        assert all(h.TEST_KEY not in v for v in resp.headers.values())
