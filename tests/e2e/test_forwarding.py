"""Allowed requests are forwarded and answered in each endpoint's own format."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.constants import STUB_REPLY_PREFIX

STUB_EVENT_ORDER = [
    "message_start",
    "content_block_start",
    "ping",
    "content_block_delta",
    "content_block_delta",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
]


def test_messages_allowed():
    """/v1/messages answers 200 with an Anthropic-shaped body from the stub; one upstream request."""
    resp = h.post_messages(h.messages_body(f"hello {h.tag()}"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["type"] == "message" and body["role"] == "assistant"
    assert body["content"][0]["type"] == "text"
    assert body["content"][0]["text"].startswith(STUB_REPLY_PREFIX)
    seen = h.anthropic_requests()
    assert len(seen) == 1 and seen[0]["path"].split("?")[0] == "/v1/messages"


def test_messages_streaming():
    """A streamed /v1/messages call delivers the stub's event sequence unchanged."""
    status, ctype, events, _ = h.stream_events(
        "/v1/messages", h.messages_body(f"stream {h.tag()}", stream=True)
    )
    assert status == 200
    assert ctype.startswith("text/event-stream")
    assert events == STUB_EVENT_ORDER


def test_chat_completions_allowed():
    """/v1/chat/completions answers 200 with an OpenAI-shaped body holding the stub's reply."""
    resp = h.post_chat(h.chat_body(f"hello chat {h.tag()}"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["content"].startswith(STUB_REPLY_PREFIX)
    assert len(h.anthropic_requests()) == 1
