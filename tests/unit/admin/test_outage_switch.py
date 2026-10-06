"""Semantic-outage state, periods and the manual switch, against the extended fixture."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import jsonschema
import pytest
from fastapi.testclient import TestClient

from ctrl_ai.admin import keys
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.dashboard.semantic import outages
from ctrl_ai.admin.records import build_dataset
from tests.unit.admin.test_admin import REPO

FIXTURE = REPO / "tests" / "fixtures" / "audit-v2-sample.jsonl"
AT_0830 = datetime(2026, 10, 4, 8, 30, tzinfo=UTC)


@pytest.fixture
def data():
    return build_dataset(json.loads(x) for x in FIXTURE.read_text().splitlines())


def test_circuits_and_periods(data):
    o = outages(data["incidents"], data["records"], None, now=AT_0830)
    assert (
        o["circuits"]["jev"]["state"] == "closed"
        and o["circuits"]["jev"]["since"] == "2026-10-04T08:20:00.000Z"
    )
    assert o["circuits"]["judge"]["state"] == "open"
    auto, manual = o["periods"]
    assert (
        auto["kind"] == "automatic"
        and auto["start"] == "2026-10-04T08:14:05.000Z"
        and auto["end"] == "2026-10-04T08:20:00.000Z"
    )
    assert auto["duration_s"] == 355 and auto["mode"] == "degrade" and not auto["ongoing"]
    assert (
        manual["kind"] == "manual"
        and manual["by"] == "secops-alice"
        and manual["ticket"] == "INC-1240"
        and manual["ongoing"]
    )
    assert (
        o["active"]
        and not o["automatic_active"]
        and o["mode"] == "degrade"
        and o["since"] == "2026-10-04T08:16:00.000Z"
    )
    # req-0013 (08:15) was decided with semantic reason "outage", allowed and flagged; nothing blocked meanwhile.
    assert o["requests_outage_reason"] == 1 and o["requests_during"] == 1
    assert o["flagged_during"] == 1 and o["blocked_during"] == 0


def test_manual_period_expires(data):
    o = outages(data["incidents"], data["records"], None, now=datetime(2026, 10, 4, 9, 0, tzinfo=UTC))
    manual = o["periods"][-1]
    assert manual["end"] == "2026-10-04T08:46:00.000Z" and not manual["ongoing"]
    assert not o["active"]


def test_blocks_during_outage_are_counted():
    rows = [
        {
            "type": "incident",
            "ts": "2026-10-04T10:00:00.000Z",
            "event": "outage_start",
            "component": "semantic",
            "mode": "degrade",
        },
        {
            "type": "decision",
            "v": 2,
            "ts": "2026-10-04T10:01:00.000Z",
            "request_id": "x1",
            "decision": "block",
            "rule": "secret-aws-key",
            "semantic": {"source": None, "score": None, "action": "flag", "reason": "outage"},
        },
        {
            "type": "decision",
            "v": 2,
            "ts": "2026-10-04T10:02:00.000Z",
            "request_id": "x2",
            "decision": "allow",
            "flagged": True,
            "semantic": {"source": None, "score": None, "action": "flag", "reason": "outage"},
        },
    ]
    d = build_dataset(rows)
    o = outages(d["incidents"], d["records"], None, now=datetime(2026, 10, 4, 10, 5, tzinfo=UTC))
    assert (
        o["automatic_active"]
        and o["blocked_during"] == 1
        and o["flagged_during"] == 1
        and o["requests_during"] == 2
    )


def test_switch_file_adds_a_manual_period():
    now = datetime(2026, 10, 4, 10, 0, tzinfo=UTC)
    sw = {
        "active": True,
        "mode": "fail_closed",
        "reason": "vendor down",
        "ticket": "INC-9",
        "issued_by": "local-admin",
        "issued_at": "2026-10-04T09:50:00Z",
        "expires_at": "2026-10-04T10:20:00Z",
    }
    o = outages([], [], sw, now=now)
    assert o["active"] and o["mode"] == "fail_closed" and o["periods"][0]["kind"] == "manual"
    assert not outages([], [], dict(sw, active=False), now=now)["active"]
    assert not outages([], [], dict(sw, mode="normal"), now=now)["active"]
    assert not outages([], [], sw, now=now + timedelta(hours=1))["active"]


def _schema():
    return json.loads((REPO / "config" / "schema" / "break_glass.schema.json").read_text())


def test_set_and_end_switch(env, settings):
    rec = keys.set_outage(settings, "degrade", 30, "Jev vendor incident", "INC-1240", actor="local-admin")
    doc = json.loads((env / "state" / "break_glass.json").read_text())
    jsonschema.validate(doc, _schema())
    assert doc["semantic_outage"]["mode"] == "degrade" and doc["semantic_outage"]["active"] is True
    assert rec["issued_by"] == "local-admin"
    for bad in (dict(mode="off"), dict(minutes=0), dict(minutes=10_000), dict(reason="x"), dict(ticket="")):
        args = dict(mode="degrade", minutes=30, reason="valid reason", ticket="INC-1") | bad
        with pytest.raises(StoreError):
            keys.set_outage(
                settings, args["mode"], args["minutes"], args["reason"], args["ticket"], actor="a"
            )
    keys.end_outage(settings, actor="local-admin", reason="vendor recovered")
    doc = json.loads((env / "state" / "break_glass.json").read_text())
    jsonschema.validate(doc, _schema())
    assert doc["semantic_outage"]["active"] is False
    with pytest.raises(StoreError):
        keys.end_outage(settings, actor="local-admin", reason="again")
    actions = [json.loads(x)["action"] for x in (env / "admin.jsonl").read_text().splitlines()]
    assert actions == ["break_glass.outage_set", "break_glass.outage_end"]


def test_switch_api_and_nav_banner(env):
    from ctrl_ai.admin import app as ui_app

    c = TestClient(ui_app.create_app())
    csrf = c.get("/api/auth/session").json()["csrf"]
    assert c.get("/api/nav").json()["outage"]["active"] is False
    body = {"mode": "degrade", "minutes": 15, "reason": "Jev and judge down", "ticket": "INC-77"}
    assert c.post("/api/admin/semantic-outage", json=body).status_code == 403
    assert (
        c.post("/api/admin/semantic-outage", json=body, headers={"x-ctrl-ai-csrf": csrf}).status_code == 200
    )
    nav = c.get("/api/nav").json()["outage"]
    assert (
        nav["active"]
        and nav["mode"] == "degrade"
        and nav["manual"]["ticket"] == "INC-77"
        and nav["manual"]["by"] == "local-admin"
    )
    state = c.get("/api/admin/semantic-outage").json()
    assert state["switch"]["status"] == "active" and set(state["circuits"]) == {"jev", "judge"}
    assert (
        c.post(
            "/api/admin/semantic-outage", json=dict(body, minutes=99999), headers={"x-ctrl-ai-csrf": csrf}
        ).status_code
        == 422
    )
    assert (
        c.post(
            "/api/admin/semantic-outage/end", json={"reason": "recovered"}, headers={"x-ctrl-ai-csrf": csrf}
        ).status_code
        == 200
    )
    assert c.get("/api/nav").json()["outage"]["active"] is False


def test_gateway_outage_rows_for_a_manual_switch_are_not_automatic():
    """The gateway writes outage_start with reason "manual switch" when it enforces a manual switch (set from
    the panel, which writes no manual_on row). That is not an automatic outage."""
    rows = [
        {
            "type": "incident",
            "v": 2,
            "ts": "2026-10-04T00:40:55.722Z",
            "event": "outage_start",
            "component": "semantic",
            "mode": "degrade",
            "reason": "manual switch",
            "by": "gateway",
        }
    ]
    switch = {
        "active": False,
        "mode": "degrade",
        "issued_at": "2026-10-04T00:38:00Z",
        "expires_at": "2026-10-04T00:48:00Z",
        "issued_by": "local-admin",
        "reason": "r",
        "ticket": "T",
    }
    out = outages(rows, [], switch, now=datetime(2026, 10, 4, 0, 45, tzinfo=UTC))
    assert out["automatic_active"] is False and out["active"] is False
    assert all(p["kind"] != "automatic" for p in out["periods"])
