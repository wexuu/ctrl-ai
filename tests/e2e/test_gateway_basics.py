"""The gateway talks to the stubs, answers health checks, and enforces its key."""

from __future__ import annotations

import httpx
import pytest

from tests.e2e import harness as h
from tests.e2e.constants import MISSING_KEY_STATUS, TEST_PROVIDER_KEY, WRONG_KEY_STATUS, WRONG_KEY_TEXT


def test_gateway_is_talking_to_the_stubs():
    """An allowed request reaches the stub Anthropic server, carrying the dummy provider key."""
    resp = h.post_messages(h.messages_body(f"isolation check {h.tag()}"))
    seen = h.anthropic_requests()
    assert seen, (
        "ISOLATION FAILURE: the stub Anthropic server received nothing. The gateway is "
        "pointed somewhere else, possibly the real API. Stop and check ANTHROPIC_API_BASE."
    )
    assert resp.status_code == 200, f"status {resp.status_code}"
    key = seen[-1]["x_api_key"]
    assert key["present"] and key["length"] == len(TEST_PROVIDER_KEY), (
        "ISOLATION FAILURE: upstream x-api-key is not the dummy test key; a real key may be configured."
    )


def test_liveliness_without_key():
    """/health/liveliness answers 200 without a key."""
    assert httpx.get(h.BASE_URL + "/health/liveliness", timeout=5).status_code == 200


@pytest.mark.parametrize(
    "path, build", [("/v1/messages", h.messages_body), ("/v1/chat/completions", h.chat_body)]
)
def test_missing_and_wrong_key(path, build):
    """No key gives 401, a wrong key gives 401 (ctrl-ai's own message); nothing reaches the stub."""
    body = build(f"auth check {h.tag()}")
    no_key = h.post(path, body, h.bearer_headers(None))
    assert no_key.status_code == MISSING_KEY_STATUS
    wrong = h.post(path, body, h.bearer_headers("sk-ctrl-ai-wrong-key"))
    assert wrong.status_code == WRONG_KEY_STATUS
    assert WRONG_KEY_TEXT in wrong.text
    assert h.anthropic_requests() == []
