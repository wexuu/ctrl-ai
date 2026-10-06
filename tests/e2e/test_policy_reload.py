"""The policy file is re-read without a restart, and a broken file is ignored."""

from __future__ import annotations

import re

from tests.e2e import harness as h
from tests.e2e.constants import BLOCK_MARKER


def _with_mode(policy: str, mode: str) -> str:
    new, n = re.subn(r"(?m)^mode:\s*\S+", f"mode: {mode}", policy, count=1)
    assert n == 1, "the policy file has no top-level `mode:` line"
    return new


def test_monitor_mode_live_reload(set_policy, original_policy):
    """Switching to monitor lets the marker through with no restart, and the row records it."""
    before_offset = h.audit_offset()
    before = h.post_messages(h.messages_body(f"{BLOCK_MARKER} before {h.tag()}"))
    assert before.status_code == 400
    version_before = h.decision_row(before, before_offset)["policy_version"]
    assert version_before == h.policy_version(original_policy)

    monitor = _with_mode(original_policy, "monitor")
    set_policy(monitor)
    offset = h.audit_offset()
    resp = h.post_messages(h.messages_body(f"{BLOCK_MARKER} monitored {h.tag()}"))
    assert resp.status_code == 200
    row = h.decision_row(resp, offset)
    assert row["decision"] == "allow"
    assert row["would_block"] is True
    assert row["mode"] == "monitor"
    assert row["rule"] == "test-marker"
    assert row["policy_version"] != version_before
    assert row["policy_version"] == h.policy_version(monitor)
    assert len(h.anthropic_requests()) == 1


def test_invalid_policy_keeps_last_good(set_policy, original_policy):
    """An unparseable policy is ignored; the marker stays blocked under the previous version."""
    offset = h.audit_offset()
    first = h.post_messages(h.messages_body(f"{BLOCK_MARKER} first {h.tag()}"))
    assert first.status_code == 400
    version_before = h.decision_row(first, offset)["policy_version"]

    set_policy("mode: [this is not\n  valid: yaml: {{{\n")
    offset = h.audit_offset()
    resp = h.post_messages(h.messages_body(f"{BLOCK_MARKER} after broken {h.tag()}"))
    assert resp.status_code == 400
    row = h.decision_row(resp, offset)
    assert row["decision"] == "block"
    assert row["policy_version"] == version_before
    assert h.anthropic_requests() == []
