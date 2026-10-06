"""The dashboard aggregates rows the gateway just wrote; the auditor export has no prompt text."""

from __future__ import annotations

import contextlib
import time

from tests.e2e import harness as h
from tests.e2e.constants import BLOCK_MARKER, BLOCK_STATUS


def _wait_usage(resp, offset):
    with contextlib.suppress(AssertionError):
        h.usage_row(resp, offset, timeout=5)


def test_dashboard_and_export_after_real_requests(admin, audit_start):
    before = admin.get("/api/dash/security").json()["kpis"]["blocked_requests"]
    allowed_text = h.remember("dashboard e2e allowed " + h.tag())
    blocked_text = h.remember(f"{BLOCK_MARKER} dashboard e2e blocked " + h.tag())
    ok = h.post_chat(h.chat_body(allowed_text))
    assert ok.status_code == 200
    blocked = h.post_chat(h.chat_body(blocked_text))
    assert blocked.status_code == BLOCK_STATUS
    _wait_usage(ok, audit_start)
    _wait_usage(blocked, audit_start)
    blocked_id = h.decision_row(blocked, audit_start)["request_id"]
    time.sleep(0.3)
    m = admin.get("/api/dash/management").json()
    assert m["kpis"]["requests"] >= 2
    s = admin.get("/api/dash/security").json()
    assert s["kpis"]["blocked_requests"] >= before + 1
    assert any(r["rule"] == "test-marker" for r in s["findings_by_rule"])
    o = admin.get("/api/dash/operations").json()
    assert o["kpis"]["requests"] >= 2 and o["kpis"]["p50_guard_ms"] is not None
    csv_resp = admin.get("/api/dash/export?format=csv")
    assert csv_resp.status_code == 200
    text = csv_resp.text
    assert blocked_id in text and "test-marker" in text
    for prompt in (allowed_text, blocked_text):
        assert prompt not in text
    js = admin.get("/api/dash/export?format=json").json()
    assert any(r["request_id"] == blocked_id and r["decision"] == "block" for r in js["records"])
    assert all(p not in str(js) for p in (allowed_text, blocked_text))
    actions = [r["action"] for r in admin.get("/api/admin/audit?action=export").json()["rows"]]
    assert len(actions) >= 2
