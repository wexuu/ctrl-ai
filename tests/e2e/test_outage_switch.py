"""The semantic-outage switch set from the admin API, shown on every page, honoured by the gateway."""

from __future__ import annotations

import json

import jsonschema
import pytest

from tests.e2e import harness as h

BG_FILE = h.RUNTIME / "state" / "break_glass.json"
SCHEMA = json.loads((h.REPO / "config" / "schema" / "break_glass.schema.json").read_text())


@pytest.fixture
def restore_bg():
    original = BG_FILE.read_text(encoding="utf-8")
    yield
    BG_FILE.write_text(original, encoding="utf-8")


def test_set_show_and_end_switch(admin, restore_bg):
    body = {"mode": "degrade", "minutes": 10, "reason": "e2e: Jev and judge down", "ticket": "INC-E2E"}
    assert admin.post("/api/admin/semantic-outage", body, csrf=False).status_code == 403
    resp = admin.post("/api/admin/semantic-outage", body)
    assert resp.status_code == 200, resp.text
    doc = json.loads(BG_FILE.read_text())
    jsonschema.validate(doc, SCHEMA)
    assert doc["semantic_outage"]["active"] is True and doc["semantic_outage"]["mode"] == "degrade"
    nav = admin.get("/api/nav").json()["outage"]
    assert nav["active"] and nav["manual"]["ticket"] == "INC-E2E"
    assert admin.get("/api/admin/semantic-outage").json()["switch"]["status"] == "active"
    assert admin.post("/api/admin/semantic-outage/end", {"reason": "e2e: recovered"}).status_code == 200
    assert json.loads(BG_FILE.read_text())["semantic_outage"]["active"] is False
    assert admin.get("/api/nav").json()["outage"]["active"] is False
    actions = [r["action"] for r in admin.get("/api/admin/audit").json()["rows"]]
    assert "break_glass.outage_set" in actions and "break_glass.outage_end" in actions


def test_gateway_degrades_under_the_switch(admin, restore_bg, audit_start):
    admin.post(
        "/api/admin/semantic-outage",
        {"mode": "degrade", "minutes": 10, "reason": "e2e: outage", "ticket": "INC-E2E"},
    )
    r = h.post_chat(h.chat_body(h.remember("outage e2e " + h.tag())))
    assert r.status_code == 200
    row = h.decision_row(r, audit_start)
    assert row["semantic"]["reason"] == "outage" and row["flagged"] is True
