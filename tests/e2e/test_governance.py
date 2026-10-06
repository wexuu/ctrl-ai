"""Rerouting through data["model"], refusals, catalogue pricing."""

from __future__ import annotations

import pytest

from tests.e2e import harness as h
from tests.e2e.gateway_keys import issue_test_key, key_headers
from tests.e2e.stack_config import model

IBAN_PL = "PL61 1090 1014 0000 0712 1981 2874"


def responses_body(text: str, model: str) -> dict:
    h.remember(text)
    return {"model": model, "input": text, "max_output_tokens": 64}


@pytest.mark.parametrize("endpoint", ["messages", "chat", "responses"])
def test_unapproved_model_is_rerouted(audit_start, endpoint):
    """The experiment: the pre-call hook sets data["model"]; LiteLLM sends the request to the new model."""
    key, _ = issue_test_key("payments-dev")  # default_model: claude-sonnet-5-5
    text = f"use another model {h.tag()}"
    if endpoint == "messages":
        resp = h.post_messages(h.messages_body(text, model="unapproved-model-x"), key_headers(key))
    elif endpoint == "chat":
        resp = h.post_chat(h.chat_body(text, model="unapproved-model-x"), key_headers(key))
    else:
        resp = h.post("/v1/responses", responses_body(text, "unapproved-model-x"), key_headers(key))
    assert resp.status_code == 200, resp.text
    assert [r["model"] for r in h.anthropic_requests()] == ["claude-sonnet-5-5"]
    row = h.decision_row(resp, audit_start)
    assert (row["decision"], row["route_reason"]) == ("reroute", "not_approved")
    assert (row["model_requested"], row["model_routed"]) == ("unapproved-model-x", "claude-sonnet-5-5")
    usage = h.usage_row(resp, audit_start)
    assert usage["model"] == "claude-sonnet-5-5" and usage["model_routed"] == "claude-sonnet-5-5"
    assert usage["fallback_used"] is False


def test_banned_model_without_equivalent_is_refused(audit_start, set_models):
    def ban(doc):
        m = model(doc, "claude-haiku-4-5")
        m["status"] = "banned"
        m.pop("equivalent", None)

    set_models(ban)
    resp = h.post_messages(h.messages_body(f"banned {h.tag()}", model="claude-haiku-4-5"))
    assert resp.status_code == 403
    message, rule = h.block_info(resp)
    assert "not approved" in message and "Allowed:" in message and "claude-opus-5-5" in message
    assert rule == "model-banned"
    assert h.anthropic_requests() == []
    row = h.decision_row(resp, audit_start)
    assert (row["decision"], row["route_reason"], row["rule"]) == ("block", "banned", "model-banned")


def test_confidential_data_rerouted_to_capable_model(audit_start):
    key, _ = issue_test_key("payments-dev")
    resp = h.post_messages(
        h.messages_body(f"account {IBAN_PL} {h.tag()}", model="claude-haiku-4-5"), key_headers(key)
    )
    assert resp.status_code == 200, resp.text
    row = h.decision_row(resp, audit_start)
    assert row["data_class_detected"] == "confidential"
    if row["route_reason"] is None:
        # Masking removes the IBAN before it leaves, so the data that leaves is no longer confidential.
        assert row["masked"].get("iban") == 1
    else:
        assert (row["decision"], row["route_reason"]) == ("reroute", "data_class")
        assert h.anthropic_requests()[0]["model"] == row["model_routed"] == "claude-opus-5-5"


def test_catalogue_price_and_unknown_price(audit_start):
    resp = h.post_messages(h.messages_body(f"priced {h.tag()}", model="claude-opus-5-5"))
    usage = h.usage_row(resp, audit_start)
    assert (usage["cost_source"], usage["price_known"], usage["provider"]) == ("catalogue", True, "anthropic")
    assert usage["cost_usd"] == pytest.approx((25 * 4.0 + 12 * 20.0) / 1e6)
    assert usage["shadow"] is False

    offset = h.audit_offset()
    resp = h.post_messages(h.messages_body(f"wildcard {h.tag()}", model="claude-e2e-unpriced-1"))
    assert resp.status_code == 200, resp.text
    usage = h.usage_row(resp, offset)
    assert (usage["price_known"], usage["cost_source"], usage["cost_usd"]) == (False, "unknown", None)


def test_subscription_never_rerouted_to_non_claude(audit_start):
    from tests.e2e.constants import FAKE_OAUTH_TOKEN

    key, _ = issue_test_key("retail-dev")  # default_model: chat-groq (not Claude)
    headers = {
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "x-litellm-api-key": f"Bearer {key}",
        "authorization": f"Bearer {FAKE_OAUTH_TOKEN}",
    }
    resp = h.post_messages(
        h.messages_body(f"subscription reroute {h.tag()}", model="unapproved-model-x"), headers
    )
    assert resp.status_code == 403, resp.text
    message, _ = h.block_info(resp)
    assert "chat-groq" not in message.split("Allowed:")[1] and "claude-opus-5-5" in message
    assert h.anthropic_requests() == []
    assert FAKE_OAUTH_TOKEN not in h.AUDIT_FILE.read_text(encoding="utf-8")
