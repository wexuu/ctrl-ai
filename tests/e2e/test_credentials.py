"""Which credential goes upstream in subscription and provider-key mode."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.constants import FAKE_OAUTH_TOKEN, TEST_PROVIDER_KEY


def test_subscription_pass_through():
    """An sk-ant-oat bearer is forwarded unchanged, x-api-key is dropped, the OAuth beta is added."""
    headers = {
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "x-litellm-api-key": f"Bearer {h.TEST_KEY}",
        "authorization": f"Bearer {FAKE_OAUTH_TOKEN}",
        "anthropic-beta": "some-beta-2025-01-01",
    }
    resp = h.post_messages(h.messages_body(f"subscription {h.tag()}"), headers)
    assert resp.status_code == 200
    seen = h.anthropic_requests()
    assert len(seen) == 1
    up = seen[0]
    assert up["authorization"]["present"] is True
    assert up["authorization"]["oauth_shaped"] is True
    assert up["authorization"]["length"] == len(FAKE_OAUTH_TOKEN) + len("Bearer ")
    assert up["x_api_key"]["present"] is False
    betas = {b.strip() for b in (up["anthropic_beta"] or "").split(",")}
    assert {"some-beta-2025-01-01", "oauth-2025-04-20"} <= betas
    assert "x-litellm-api-key" not in up["header_names"]


def test_key_mode_does_not_leak_gateway_key():
    """With only the gateway key, upstream gets the provider key and no Authorization header."""
    resp = h.post_messages(h.messages_body(f"key mode {h.tag()}"), h.bearer_headers())
    assert resp.status_code == 200
    up = h.anthropic_requests()[0]
    assert up["authorization"]["present"] is False
    assert up["x_api_key"]["present"] is True
    assert up["x_api_key"]["length"] == len(TEST_PROVIDER_KEY)
