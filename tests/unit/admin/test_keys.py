"""Gateway keys and break-glass register."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta

import jsonschema
import pytest
from fastapi.testclient import TestClient

from ctrl_ai.admin import keys
from ctrl_ai.admin.config_store import StoreError
from tests.unit.admin.test_admin import REPO


def _schema(name):
    return json.loads((REPO / "config" / "schema" / name).read_text())


def test_generate_key_format_and_hash():
    k = keys.generate_key()
    assert re.fullmatch(r"sk-ctrl-ai-[0-9a-f]{48}", k)
    assert keys.hash_key(k) == hashlib.sha256(k.encode()).hexdigest()
    assert keys.generate_key() != k


def test_issue_stores_only_hash(env, settings):
    key, _record = keys.issue(settings, "payments-dev", "piotr", "laptop", None, actor="local-admin")
    stored = (env / "state" / "keys.json").read_text()
    assert key not in stored and keys.hash_key(key) in stored
    doc = json.loads(stored)
    jsonschema.validate(doc, _schema("keys.schema.json"))
    rec = doc["keys"][0]
    assert rec["prefix"] == key[:12] and re.fullmatch(r"k_[0-9a-f]{8}", rec["id"]) and rec["revoked"] is False
    assert key not in (env / "admin.jsonl").read_text()
    row = json.loads((env / "admin.jsonl").read_text().splitlines()[-1])
    assert row["action"] == "key.issue" and row["target"] == rec["id"]


def test_issue_validation(env, settings):
    with pytest.raises(StoreError):
        keys.issue(settings, "no-team", "x", actor="a")
    with pytest.raises(StoreError):
        keys.issue(settings, "payments-dev", "  ", actor="a")
    _, _rec = keys.issue(settings, "payments-dev", "u", expires="2020-01-01", actor="a")
    assert keys.list_keys(settings)[0]["status"] == "expired"


def test_revoke(env, settings):
    _, rec = keys.issue(settings, "retail-dev", "anna", actor="local-admin")
    with pytest.raises(StoreError):
        keys.revoke(settings, rec["id"], actor="local-admin", reason="")
    keys.revoke(settings, rec["id"], actor="local-admin", reason="left the organisation")
    listed = keys.list_keys(settings, {rec["id"]: "2026-10-04T08:00:00Z"})
    assert listed[0]["status"] == "revoked" and listed[0]["last_used"] == "2026-10-04T08:00:00Z"
    assert "hash" not in listed[0]
    with pytest.raises(StoreError):
        keys.revoke(settings, "k_00000000", actor="a", reason="nope")


def _override(minutes=30, **kw):
    now = datetime.now(UTC)
    rec = {
        "id": "bg_1a2b3c4d",
        "subject": "team:payments-dev",
        "relax": ["semantic"],
        "reason": "urgent fix",
        "ticket": "INC-1",
        "issued_by": "alice",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revoked": False,
    }
    rec.update(kw)
    return rec


def test_break_glass_list_and_revoke(env, settings):
    (env / "state" / "break_glass.json").write_text(
        json.dumps(
            {
                "overrides": [
                    _override(),
                    _override(-5, id="bg_00000001"),
                    _override(id="bg_00000002", revoked=True),
                ]
            }
        )
    )
    assert [o["status"] for o in keys.list_overrides(settings)] == ["active", "expired", "revoked"]
    assert len(keys.active_overrides(settings)) == 1
    keys.revoke_override(settings, "bg_1a2b3c4d", actor="local-admin", reason="incident resolved")
    assert keys.active_overrides(settings) == []
    doc = json.loads((env / "state" / "break_glass.json").read_text())
    jsonschema.validate(doc, _schema("break_glass.schema.json"))
    row = json.loads((env / "admin.jsonl").read_text().splitlines()[-1])
    assert row["action"] == "break_glass.revoke" and row["target"] == "bg_1a2b3c4d"


def test_keys_api_returns_key_once(env):
    from ctrl_ai.admin import app as ui_app

    c = TestClient(ui_app.create_app())
    csrf = c.get("/api/auth/session").json()["csrf"]
    resp = c.post(
        "/api/admin/keys", json={"team": "payments-dev", "user": "piotr"}, headers={"x-ctrl-ai-csrf": csrf}
    )
    assert resp.status_code == 200
    key = resp.json()["key"]
    assert resp.text.count(key) == 1
    listed = c.get("/api/admin/keys").text
    assert key not in listed and keys.hash_key(key) not in listed
    assert c.post("/api/admin/keys", json={"team": "payments-dev", "user": "x"}).status_code == 403
    assert c.get("/api/nav").json()["break_glass_active"] == 0
