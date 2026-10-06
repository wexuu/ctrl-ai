"""The logger writes a usage row for every request, successful or not."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.constants import STUB_INPUT_TOKENS, STUB_OUTPUT_TOKENS, UPSTREAM_400_MARKER


def test_usage_row(audit_start):
    """An allowed request gets a usage row with the stub's token counts and the decision row's id."""
    resp = h.post_messages(h.messages_body(f"count my tokens {h.tag()}"))
    assert resp.status_code == 200
    decision = h.decision_row(resp, audit_start)
    usage = h.usage_row(resp, audit_start)
    assert usage["status"] == "success"
    assert usage["input_tokens"] == STUB_INPUT_TOKENS
    assert usage["output_tokens"] == STUB_OUTPUT_TOKENS
    assert usage["request_id"] == decision["request_id"]
    assert usage["error"] is None


def test_upstream_failure(audit_start):
    """An upstream 400 reaches the client as 400 and is logged as a failed usage row."""
    # claude-opus-5-5 now has a fallback chain, and LiteLLM falls back on a 400 too
    # (opus → sonnet → haiku, three upstream calls). A model without a chain keeps this test's meaning.
    resp = h.post_messages(
        h.messages_body(f"{UPSTREAM_400_MARKER} please {h.tag()}", model="claude-haiku-4-5")
    )
    assert resp.status_code == 400
    usage = h.usage_row(resp, audit_start)
    assert usage["status"] == "failure"
    assert len(h.anthropic_requests()) == 1
