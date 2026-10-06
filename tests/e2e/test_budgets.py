"""A team over its monthly budget is downgraded, blocked, or only flagged."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.gateway_keys import issue_test_key, key_headers


def tiny_budget(team_id: str, on_exceeded: str, downgrade_to: str | None = None):
    def change(doc):
        team = next(t for t in doc["teams"] if t["id"] == team_id)
        team["budget"] = {"monthly_usd": 0.0001, "on_exceeded": on_exceeded}
        if downgrade_to:
            team["budget"]["downgrade_to"] = downgrade_to

    return change


def test_downgrade(audit_start, set_teams):
    set_teams(tiny_budget("payments-dev", "downgrade", "claude-haiku-4-5"))
    key, _ = issue_test_key("payments-dev")
    resp = h.post_messages(h.messages_body(f"expensive {h.tag()}", model="claude-opus-5-5"), key_headers(key))
    assert resp.status_code == 200, resp.text
    assert h.anthropic_requests()[0]["model"] == "claude-haiku-4-5"
    row = h.decision_row(resp, audit_start)
    assert (row["decision"], row["route_reason"], row["model_routed"]) == (
        "reroute",
        "budget",
        "claude-haiku-4-5",
    )
    assert row["budget"]["state"] == "exceeded" and row["budget"]["action"] == "downgrade"


def test_block(audit_start, set_teams):
    set_teams(tiny_budget("risk-analytics", "block"))
    key, _ = issue_test_key("risk-analytics")
    resp = h.post_messages(h.messages_body(f"over budget {h.tag()}"), key_headers(key))
    assert resp.status_code == 429
    message, _ = h.block_info(resp)
    assert "team risk-analytics has used its monthly AI budget" in message
    assert h.anthropic_requests() == []
    assert h.decision_row(resp, audit_start)["budget"]["action"] == "block"


def test_alert_only(audit_start, set_teams):
    set_teams(tiny_budget("markets-quant", "alert_only"))
    key, _ = issue_test_key("markets-quant")
    resp = h.post_messages(h.messages_body(f"alert only {h.tag()}"), key_headers(key))
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert row["flagged"] is True and row["budget"]["state"] == "exceeded" and row["decision"] == "allow"


def test_spend_is_recorded_after_the_call(audit_start):
    key, _ = issue_test_key("retail-dev")
    first = h.post_messages(h.messages_body(f"spend one {h.tag()}"), key_headers(key))
    h.usage_row(first, audit_start)
    offset = h.audit_offset()
    second = h.post_messages(h.messages_body(f"spend two {h.tag()}"), key_headers(key))
    row = h.decision_row(second, offset)
    assert row["budget"]["used_usd"] > 0 and row["budget"]["limit_usd"] == 200
