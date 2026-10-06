"""Only the newest user turn is checked, tool results included, injected context excluded."""

from __future__ import annotations

import pytest

from tests.e2e import harness as h
from tests.e2e.constants import BLOCK_MARKER, BLOCK_MARKER_TEXT


def test_older_turn_is_not_rescanned(audit_start):
    """A marker in an older user turn does not block a clean newest turn."""
    old = h.remember(f"{BLOCK_MARKER} earlier {h.tag()}")
    new = h.remember(f"a clean follow-up {h.tag()}")
    body = h.messages_conversation(
        [
            {"role": "user", "content": old},
            {"role": "assistant", "content": "Understood."},
            {"role": "user", "content": new},
        ]
    )
    resp = h.post_messages(body)
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert row["decision"] == "allow" and row["would_block"] is False
    assert len(h.anthropic_requests()) == 1


@pytest.mark.parametrize("result_content", ["string", "blocks"])
def test_tool_result_is_scanned(audit_start, result_content):
    """A tool_result in the newest user turn that contains the marker is blocked."""
    output = h.remember(f"file contents: {BLOCK_MARKER} {h.tag()}")
    content = output if result_content == "string" else [{"type": "text", "text": output}]
    body = h.messages_conversation(
        [
            {"role": "user", "content": h.remember(f"read the file {h.tag()}")},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "toolu_e2e_01", "name": "Read", "input": {"path": "notes.txt"}}
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "toolu_e2e_01", "content": content}],
            },
        ]
    )
    resp = h.post_messages(body)
    assert resp.status_code == 400
    message, rule = h.block_info(resp)
    assert BLOCK_MARKER_TEXT in message and rule == "test-marker"
    assert h.anthropic_requests() == []
    assert h.decision_row(resp, audit_start)["rule"] == "test-marker"


def test_system_reminder_is_ignored(audit_start):
    """A marker inside Claude Code's <system-reminder> context does not block, and is not sent to Jev."""
    filler = "Environment details and skill listings. " * 50
    reminder = h.remember(f"<system-reminder>\n{filler}{BLOCK_MARKER} {h.tag()}\n</system-reminder>")
    prompt = h.remember(f"say hi {h.tag()}")
    body = h.messages_conversation(
        [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": reminder},
                    {"type": "text", "text": prompt},
                ],
            }
        ]
    )
    # reminders are split off only for Claude Code requests (user-agent claude-cli/…),
    # so this test now identifies itself as Claude Code. From any other client the tags are plain
    # text and the marker blocks (tests/e2e/test_normalisation.py).
    headers = {**h.bearer_headers(), "user-agent": "claude-cli/2.1.0 (external, cli)"}
    resp = h.post_messages(body, headers)
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert row["decision"] == "allow" and row["would_block"] is False
    seen = h.jev_requests()
    assert len(seen) == 1
    state_length = seen[0]["state_length"]
    # Joining blocks may add a separator; anything near the reminder's size means it was sent.
    assert len(prompt) <= state_length <= len(prompt) + 2, (
        f"Jev got {state_length} chars; the plain prompt is {len(prompt)}, the whole turn {len(reminder) + len(prompt)}"
    )
    assert row["text_chars"] == state_length
