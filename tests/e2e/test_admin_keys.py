"""Keys issued and revoked through the admin API; break-glass overrides listed and revoked."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from tests.e2e import harness as h

KEYS_FILE = h.RUNTIME / "state" / "keys.json"
BG_FILE = h.RUNTIME / "state" / "break_glass.json"


def test_issue_and_revoke_key(admin):
    resp = admin.post("/api/admin/keys", {"team": "payments-dev", "user": "e2e-piotr", "label": "e2e"})
    assert resp.status_code == 200, resp.text
    key = resp.json()["key"]
    kid = resp.json()["record"]["id"]
    assert key.startswith("sk-ctrl-ai-") and resp.text.count(key) == 1
    stored = KEYS_FILE.read_text(encoding="utf-8")
    assert key not in stored and hashlib.sha256(key.encode()).hexdigest() in stored
    listed = admin.get("/api/admin/keys").json()["keys"]
    assert any(k["id"] == kid and k["status"] == "active" for k in listed)
    assert admin.post(f"/api/admin/keys/{kid}/revoke", {"reason": "e2e revoke"}).status_code == 200
    rec = next(k for k in json.loads(KEYS_FILE.read_text())["keys"] if k["id"] == kid)
    assert rec["revoked"] is True
    assert key not in (h.RUNTIME / "admin.jsonl").read_text(encoding="utf-8")


def test_break_glass_shown_and_revoked(admin):
    original = BG_FILE.read_text(encoding="utf-8")
    now = datetime.now(UTC)
    record = {
        "id": "bg_e2e00001",
        "subject": "team:payments-dev",
        "relax": ["semantic"],
        "reason": "e2e urgent fix",
        "ticket": "INC-E2E",
        "issued_by": "e2e",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revoked": False,
    }
    try:
        BG_FILE.write_text(json.dumps({"overrides": [record]}), encoding="utf-8")
        listed = admin.get("/api/admin/break-glass").json()["overrides"]
        assert listed[0]["status"] == "active"
        assert admin.get("/api/nav").json()["break_glass_active"] == 1
        assert (
            admin.post("/api/admin/break-glass/bg_e2e00001/revoke", {"reason": "e2e resolved"}).status_code
            == 200
        )
        assert json.loads(BG_FILE.read_text())["overrides"][0]["revoked"] is True
        assert admin.get("/api/nav").json()["break_glass_active"] == 0
    finally:
        BG_FILE.write_text(original, encoding="utf-8")
