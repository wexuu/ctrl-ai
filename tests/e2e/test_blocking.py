"""Policy rules block requests before they leave the gateway."""

from __future__ import annotations

import time

import pytest

from tests.e2e import harness as h
from tests.e2e.constants import BLOCK_MARKER, BLOCK_MARKER_TEXT, BLOCK_STATUS


def _assert_blocked(resp, rule: str) -> None:
    assert resp.status_code == BLOCK_STATUS
    message, rule_id = h.block_info(resp)
    assert BLOCK_MARKER_TEXT in message
    assert rule in message
    assert rule_id == rule


def _assert_block_row(row: dict, rule: str) -> None:
    assert row["decision"] == "block"
    assert row["would_block"] is True
    assert row["rule"] == rule
    assert row["mode"] == "enforce"
    assert row["jev"]["status"] == "skipped"


def test_block_on_messages(audit_start):
    """The marker is blocked on /v1/messages, nothing goes upstream, and the decision row says why."""
    resp = h.post_messages(h.messages_body(f"{BLOCK_MARKER} please {h.tag()}"))
    _assert_blocked(resp, "test-marker")
    assert h.anthropic_requests() == []
    row = h.decision_row(resp, audit_start)
    _assert_block_row(row, "test-marker")
    assert row["endpoint"] == "messages"


def test_block_on_chat_completions(audit_start):
    """The same block on /v1/chat/completions."""
    resp = h.post_chat(h.chat_body(f"{BLOCK_MARKER} please {h.tag()}"))
    _assert_blocked(resp, "test-marker")
    assert h.anthropic_requests() == []
    row = h.decision_row(resp, audit_start)
    _assert_block_row(row, "test-marker")
    assert row["endpoint"] == "chat_completions"


def test_aws_key_pattern(audit_start):
    """AKIA plus 16 upper-case letters and digits is blocked; AKIA plus 15 is allowed."""
    blocked = h.post_messages(h.messages_body(f"my key is AKIAABCDEFGHIJ123456 ok {h.tag()}"))
    _assert_blocked(blocked, "aws-access-key")
    _assert_block_row(h.decision_row(blocked, audit_start), "aws-access-key")

    allowed = h.post_messages(h.messages_body(f"my key is AKIAABCDEFGHIJ12345 ok {h.tag()}"))
    assert allowed.status_code == 200
    assert len(h.anthropic_requests()) == 1


@pytest.mark.parametrize(
    "path, build", [("/v1/messages", h.messages_body), ("/v1/chat/completions", h.chat_body)]
)
def test_blocked_streaming_request(path, build):
    """A streaming request with the marker gets a plain JSON 400 within 2 seconds."""
    start = time.monotonic()
    resp = h.post(path, build(f"{BLOCK_MARKER} stream {h.tag()}", stream=True))
    elapsed = time.monotonic() - start
    assert resp.status_code == BLOCK_STATUS
    assert resp.headers.get("content-type", "").startswith("application/json")
    assert BLOCK_MARKER_TEXT in resp.json()["error"]["message"]
    assert elapsed < 2.0, f"took {elapsed:.2f}s"
    assert h.anthropic_requests() == []
