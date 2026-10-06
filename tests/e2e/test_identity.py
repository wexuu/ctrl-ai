"""Team keys give identity and profile; revoked and unknown keys get 401."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.constants import FAKE_OAUTH_TOKEN, WRONG_KEY_TEXT
from tests.e2e.gateway_keys import issue_test_key, key_headers, revoke_test_key


def test_team_key_identity_in_rows(audit_start):
    key, key_id = issue_test_key("payments-dev", "piotr")
    resp = h.post_messages(h.messages_body(f"hello from payments {h.tag()}"), key_headers(key))
    assert resp.status_code == 200, resp.text
    row = h.decision_row(resp, audit_start)
    assert (row["team"], row["department"], row["user"], row["key_id"], row["profile"]) == (
        "payments-dev",
        "payments",
        "piotr",
        key_id,
        "strict",
    )
    usage = h.usage_row(resp, audit_start)
    assert (usage["team"], usage["key_id"]) == ("payments-dev", key_id)
    assert key not in h.AUDIT_FILE.read_text(encoding="utf-8")


def test_revoked_key_gets_401_without_restart():
    key, key_id = issue_test_key("retail-dev")
    assert h.post_chat(h.chat_body(f"before revoke {h.tag()}"), key_headers(key)).status_code == 200
    revoke_test_key(key_id)
    resp = h.post_chat(h.chat_body(f"after revoke {h.tag()}"), key_headers(key))
    assert resp.status_code == 401 and WRONG_KEY_TEXT in resp.text


def test_unknown_key_and_master_key(audit_start):
    assert (
        h.post_chat(h.chat_body(f"unknown {h.tag()}"), key_headers("sk-ctrl-ai-not-a-key")).status_code == 401
    )
    resp = h.post_messages(h.messages_body(f"master {h.tag()}"))
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert (row["team"], row["department"], row["key_id"], row["profile"]) == (
        "admin",
        "platform",
        None,
        "balanced",
    )


def test_unknown_team_is_recorded(audit_start):
    key, _ = issue_test_key("no-such-team")
    resp = h.post_messages(h.messages_body(f"ghost team {h.tag()}"), key_headers(key))
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert row["department"] == "unknown" and row["identity_error"] == "unknown_team"


def test_team_key_with_subscription_pass_through():
    key, _ = issue_test_key("payments-dev")
    headers = {
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "x-litellm-api-key": f"Bearer {key}",
        "authorization": f"Bearer {FAKE_OAUTH_TOKEN}",
    }
    resp = h.post_messages(h.messages_body(f"subscription with team key {h.tag()}"), headers)
    assert resp.status_code == 200
    up = h.anthropic_requests()[0]
    assert up["authorization"]["oauth_shaped"] is True and up["x_api_key"]["present"] is False
