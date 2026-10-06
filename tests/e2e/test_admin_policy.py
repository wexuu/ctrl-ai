"""Policy changes made through the admin API are enforced by the gateway on the next request."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.constants import BLOCK_MARKER, BLOCK_STATUS

RULE_VALUE = "POLICY-E2E-FORBIDDEN"


def test_custom_rule_blocks_then_delete_allows(admin, audit_start):
    original = h.POLICY_FILE.read_text(encoding="utf-8")
    try:
        cfg = admin.config("policy")
        doc = cfg["doc"]
        doc["rules"] = [
            *list(doc.get("rules") or []),
            {"id": "b2-e2e-rule", "type": "contains", "value": RULE_VALUE, "action": "block"},
        ]
        assert admin.save("policy", doc, reason="e2e: add block rule").status_code == 200
        r = h.post_chat(h.chat_body(h.remember(f"please {RULE_VALUE} now " + h.tag())))
        assert r.status_code == BLOCK_STATUS
        assert h.decision_row(r, audit_start)["rule"] == "b2-e2e-rule"
        doc["rules"] = [x for x in doc["rules"] if x["id"] != "b2-e2e-rule"]
        assert admin.save("policy", doc, reason="e2e: delete block rule").status_code == 200
        offset = h.audit_offset()
        r = h.post_chat(h.chat_body(h.remember(f"please {RULE_VALUE} again " + h.tag())))
        assert r.status_code == 200
        assert h.decision_row(r, offset)["decision"] == "allow"
    finally:
        h.write_policy(original)


def test_monitor_mode_lets_marker_pass_with_would_block(admin, audit_start):
    original = h.POLICY_FILE.read_text(encoding="utf-8")
    try:
        cfg = admin.config("policy")
        doc = dict(cfg["doc"], mode="monitor")
        resp = admin.save("policy", doc, reason="e2e: monitor mode")
        assert resp.status_code == 200, resp.text
        r = h.post_chat(h.chat_body(h.remember(f"{BLOCK_MARKER} in monitor " + h.tag())))
        assert r.status_code == 200
        row = h.decision_row(r, audit_start)
        assert row["would_block"] is True and row["decision"] == "allow" and row["mode"] == "monitor"
    finally:
        h.write_policy(original)
