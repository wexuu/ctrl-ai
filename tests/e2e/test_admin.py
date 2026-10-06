"""Admin API: the open-access admin with CSRF, config store, live pick-up by the gateway, conflict, rollback, history."""

from __future__ import annotations

import httpx

from tests.e2e import harness as h
from tests.e2e.admin_client import UI_URL


def test_open_access_admin_and_csrf(admin):
    s = admin.get("/api/auth/session").json()
    assert s["user"] == "local-admin" and s["open_access"] is True
    assert httpx.get(UI_URL + "/api/admin/config/policy").status_code == 200  # open: no sign-in
    cfg = admin.config("policy")
    no_csrf = admin.post(
        "/api/admin/config/policy",
        {"doc": cfg["doc"], "expected_version": cfg["version"], "reason": "no csrf"},
        csrf=False,
    )
    assert no_csrf.status_code == 403


def test_save_is_applied_live_then_rollback(admin, audit_start):
    original = h.POLICY_FILE.read_text(encoding="utf-8")
    try:
        cfg = admin.config("policy")
        v0 = cfg["version"]
        doc = cfg["doc"]
        doc["rules"] = [
            *list(doc.get("rules") or []),
            {"id": "e2e-admin-rule", "type": "contains", "value": "ADMIN-E2E-MARKER"},
        ]
        resp = admin.save("policy", doc, reason="e2e: add a rule")
        assert resp.status_code == 200, resp.text
        v1 = resp.json()["version"]
        assert v1 != v0
        assert httpx.get(UI_URL + "/api/policy").json()["version"] == v1
        # The gateway decides the next request under the new version, without a restart.
        r = h.post_chat(h.chat_body(h.remember("hello from the admin test " + h.tag())))
        assert r.status_code == 200
        assert h.decision_row(r, audit_start)["policy_version"] == v1
        # Stale expected_version: 409 with the current version.
        stale = admin.save("policy", doc, reason="stale", expected=v0)
        assert stale.status_code == 409 and stale.json()["current_version"] == v1
        # Rollback to v0 is a new, audited version.
        rb = admin.post("/api/admin/config/policy/rollback", {"version": v0, "reason": "e2e: undo"})
        assert rb.status_code == 200, rb.text
        assert "e2e-admin-rule" not in h.POLICY_FILE.read_text(encoding="utf-8")
        hist = admin.get("/api/admin/config/policy/history").json()
        assert v0 in [v["version"] for v in hist["versions"]] and v1 in [
            v["version"] for v in hist["versions"]
        ]
        actions = [r["action"] for r in admin.get("/api/admin/audit").json()["rows"]]
        assert "policy.save" in actions and "policy.rollback" in actions
    finally:
        h.write_policy(original)
