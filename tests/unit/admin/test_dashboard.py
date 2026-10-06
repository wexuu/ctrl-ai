"""Dashboard aggregates against tests/fixtures/audit-v2-sample.jsonl.

Expected numbers were worked out by hand from the fixture (see the comments), not computed with
the code under test.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ctrl_ai.admin.dashboard.common import apply_filters, percentile
from ctrl_ai.admin.dashboard.management import management
from ctrl_ai.admin.dashboard.operations import operations
from ctrl_ai.admin.dashboard.security import group_blocks, security
from ctrl_ai.admin.dashboard.semantic import second_model
from ctrl_ai.admin.records import EXPORT_FIELDS, LogReader, build_dataset, export_row

REPO = Path(__file__).resolve().parents[3]
FIXTURE = REPO / "tests" / "fixtures" / "audit-v2-sample.jsonl"
TEAMS = yaml.safe_load((REPO / "tests" / "fixtures" / "config" / "teams.yaml").read_text())
MODELS = yaml.safe_load((REPO / "tests" / "fixtures" / "config" / "models.yaml").read_text())
START, END, TODAY = date(2026, 10, 1), date(2026, 10, 31), date(2026, 10, 4)


@pytest.fixture
def data():
    rows = [json.loads(line) for line in FIXTURE.read_text().splitlines()]
    return build_dataset(rows)


@pytest.fixture
def recs(data):
    return apply_filters(data["records"], START, END)


def test_join_and_v1_defaults(data):
    recs = data["records"]
    assert len(recs) == 14  # req-0001..0013 + legacy-1
    assert len(data["tools"]) == 2 and len(data["break_glass"]) == 1 and len(data["incidents"]) == 6
    legacy = next(r for r in recs if r["request_id"] == "legacy-1")
    assert legacy["team"] == "unattributed" and legacy["department"] == "unattributed"
    assert legacy["cost_source"] == "litellm" and legacy["cost_usd"] == 0.061 and legacy["v"] == 1
    assert legacy["semantic_score"] == 0.16 and legacy["semantic_source"] == "jev"
    r9 = next(r for r in recs if r["request_id"] == "req-0009")
    assert (
        r9["model_requested"] == "chat-groq" and r9["model_routed"] == "chat-mistral" and r9["fallback_used"]
    )


def test_management_kpis(recs):
    m = management(recs, START, END, TEAMS, MODELS, today=TODAY)
    k = m["kpis"]
    # spend (not shadow): req-0002 0.00558 + legacy 0.061
    assert k["spend"] == pytest.approx(0.06658)
    # shadow: six rows of 3.76e-05 (1,4,6,8,11,12) + req-0009 4e-05
    assert k["shadow"] == pytest.approx(0.0002656)
    assert k["requests"] == 14  # req-0013 (outage, no usage row) counts as a request
    assert k["active_users"] == 6  # anna piotr kasia ola tomek admin2
    assert k["active_teams"] == 6  # retail payments markets risk admin ai-platform
    assert k["budget_total"] == 2100  # 500+200+1000+300+100
    # forecast: total 0.0668456 over 4 days elapsed x 31 days
    assert k["forecast"] == pytest.approx(0.0668456 / 4 * 31, abs=1e-6)
    deps = {d["id"]: d for d in m["departments"]}
    assert deps["payments"]["total"] == pytest.approx(0.0056552)
    assert deps["retail"]["total"] == pytest.approx(0.0001152)
    assert deps["unattributed"]["total"] == pytest.approx(0.061)
    assert deps["payments"]["budget"] == 500 and deps["payments"]["utilisation"] == pytest.approx(
        0.0056552 / 500, abs=1e-4
    )
    assert m["models_by_requests"][0] == {
        "model": "chat-groq",
        "status": "approved",
        "requests": 10,  # 1,3-8,11,12,13
        "spend": 0.0,
        "shadow": pytest.approx(0.0002256),
        "total": pytest.approx(0.0002256),
    }
    assert m["top_users"][0] == {"user": "anna", "requests": 5}
    days = {d["day"]: d for d in m["daily"]}
    assert days["2026-10-03"]["total"] == pytest.approx(0.061) and days["2026-10-04"]["requests"] == 13
    assert len(m["daily"]) == 4  # 1..4 October, up to today


def test_filters(data):
    recs = apply_filters(data["records"], date(2026, 10, 4), date(2026, 10, 4), team="retail-dev")
    assert [r["request_id"] for r in recs] == [
        "req-0001",
        "req-0003",
        "req-0006",
        "req-0007",
        "req-0009",
        "req-0013",
    ]
    assert len(apply_filters(data["records"], START, END, model="chat-mistral")) == 2  # 0004 req, 0009 routed
    assert len(apply_filters(data["records"], date(2026, 10, 3), date(2026, 10, 3))) == 1


def test_security(recs, data):
    overrides = [{"id": "bg_1", "status": "active"}, {"id": "bg_2", "status": "revoked"}]
    s = security(recs, data["tools"], data["break_glass"], overrides)
    assert s["kpis"] == {
        "blocked": 2,
        "blocked_requests": 2,
        "flagged": 5,
        "masked_items": 2,
        "rerouted_policy": 1,
        "throttled": 1,
        "unapproved_attempts": 1,
        "break_glass_active": 1,
    }
    rules = {r["rule"]: r for r in s["findings_by_rule"]}
    assert rules["secret-aws-key"]["block"] == 2 and rules["pii-iban"]["mask"] == 1
    assert rules["sig-hidden-instruction"]["flag"] == 1
    assert s["masked"]["totals"]["iban"] == 1 and s["masked"]["totals"]["pesel"] == 1
    assert s["reroutes"] == {"budget": 1, "team_not_allowed": 1}
    assert s["shadow_ai"] == [{"team": "markets-quant", "models": {"chat-mistral": 1}, "attempts": 1}]
    hist = s["semantic"]["histogram"]
    assert hist[0] == 8 and hist[1] == 1 and hist[8] == 1 and hist[9] == 1 and sum(hist) == 11
    assert s["semantic"]["sources"] == {"jev": 10, "judge": 1, "none": 3}
    assert s["semantic"]["jev_availability"] == pytest.approx(10 / 12, abs=1e-4)
    assert s["semantic"]["judge_availability"] == pytest.approx(1 / 3, abs=1e-4)
    assert s["tools"]["blocked"] == 1 and s["tools"]["suspended"] == [{"server": "wiki", "tool": "read_page"}]
    heat = {r["department"]: r for r in s["heat"]["rows"]}
    assert heat["payments"]["pii"] == 1 and heat["payments"]["pl"] == 1 and heat["retail"]["secrets"] == 1
    assert s["risky"][0]["who"] in ("anna", "ola")


def test_operations(recs):
    o = operations(recs, now=datetime(2026, 10, 4, 8, 15, tzinfo=UTC))
    k = o["kpis"]
    assert k["p50_guard_ms"] == 214.0 and k["p95_guard_ms"] == 253.0  # 3.1, 214 x12, 253
    assert k["p50_total_ms"] == 612.0 and k["p95_total_ms"] == 2900.0
    assert k["error_rate"] == 0.0  # the three failures are a block, a block and a throttle
    assert k["fallback_rate"] == pytest.approx(1 / 13, abs=1e-4)
    assert k["unknown_price_requests"] == 1 and k["unknown_price_tokens"] == 60963
    assert k["jev_availability"] == pytest.approx(10 / 12, abs=1e-4)
    assert k["rpm_15min"] == pytest.approx(13 / 15, abs=0.01)  # all 13 October-4 requests are after 08:00
    assert o["fallbacks"][0]["routed"] == "chat-mistral"
    assert o["time_split"]["model_ms"] == 612.0 - 214.0
    assert sum(b["value"] for b in o["jev_latency"]) == 10


def test_percentile():
    assert percentile([], 50) is None
    assert percentile([1, 2, 3, 4], 50) == 2 and percentile([1, 2, 3, 4], 95) == 4


def test_incremental_reader(tmp_path):
    p = tmp_path / "audit.jsonl"
    lines = FIXTURE.read_text().splitlines()
    p.write_text("\n".join(lines[:4]) + "\n")
    r = LogReader(str(p), max_rows=10)
    assert r.refresh() and len(r.rows) == 4
    assert not r.refresh()
    with p.open("a") as f:
        f.write(lines[4] + "\n" + lines[5][:20])  # one whole line and a half-written one
    assert r.refresh() and len(r.rows) == 5
    with p.open("a") as f:
        f.write(lines[5][20:] + "\n")
    r.refresh()
    assert len(r.rows) == 6
    with p.open("a") as f:
        f.write("\n".join(lines[6:]) + "\n")
    r.refresh()
    assert len(r.rows) == 10  # capped at max_rows, newest kept
    assert r.rows[-1]["type"] == json.loads(lines[-1])["type"]


def test_export_contains_no_text_fields(recs):
    row = export_row(recs[0])
    assert set(row) == set(EXPORT_FIELDS)
    assert not any(k in row for k in ("text", "prompt", "messages", "content"))


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name in ("policy", "models", "teams", "mcp", "signatures"):
        shutil.copy(REPO / "tests" / "fixtures" / "config" / f"{name}.yaml", tmp_path / f"{name}.yaml")
        monkeypatch.setenv(f"CTRL_AI_{name.upper()}_FILE", str(tmp_path / f"{name}.yaml"))
    audit = tmp_path / "audit.jsonl"
    shutil.copy(FIXTURE, audit)
    monkeypatch.setenv("CTRL_AI_AUDIT_LOG", str(audit))
    monkeypatch.setenv("CTRL_AI_ADMIN_AUDIT_LOG", str(tmp_path / "admin.jsonl"))
    monkeypatch.setenv("CTRL_AI_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.setenv("CTRL_AI_BREAKGLASS_FILE", str(tmp_path / "bg.json"))
    monkeypatch.setenv("CTRL_AI_SCHEMA_DIR", str(REPO / "config" / "schema"))
    from ctrl_ai.admin import app as ui_app

    return TestClient(ui_app.create_app())


def test_dash_api(client, tmp_path):
    q = "?from=2026-10-01&to=2026-10-31"
    m = client.get("/api/dash/management" + q).json()
    assert m["kpis"]["requests"] == 14 and m["period"]["from"] == "2026-10-01"
    assert client.get("/api/dash/management" + q + "&team=retail-dev").json()["kpis"]["requests"] == 6
    s = client.get("/api/dash/security" + q).json()
    assert s["kpis"]["blocked"] == 2
    o = client.get("/api/dash/operations" + q).json()
    assert o["kpis"]["p95_total_ms"] == 2900.0 and o["prometheus"] is None
    f = client.get("/api/dash/filters" + q).json()
    assert "payments" in f["departments"] and "anna" in f["users"]
    req = client.get("/api/dash/requests" + q + "&decision=block").json()
    assert req["total"] == 2 and {r["request_id"] for r in req["records"]} == {"req-0003", "req-0005"}
    csv_text = client.get("/api/dash/export" + q + "&format=csv").text
    assert csv_text.startswith("# {") and '"rows":14' in csv_text and "a1b2c3d4" in csv_text
    assert len(csv_text.strip().splitlines()) == 16  # header comment + column row + 14 records
    js = client.get("/api/dash/export" + q + "&format=json").json()
    assert js["header"]["rows"] == 14 and js["header"]["policy_versions"] == ["9f8e7d6c", "a1b2c3d4"]
    admin_rows = [json.loads(x) for x in (tmp_path / "admin.jsonl").read_text().splitlines()]
    assert [r["action"] for r in admin_rows] == ["export", "export"] and admin_rows[0]["details"][
        "rows"
    ] == 14
    usage = client.get("/api/dash/team-spend").json()
    assert "teams" in usage


def test_fallback_two_usage_rows_count_once_on_the_serving_model():
    """Merge check against A's real rows: a provider fallback writes a failure usage row (0 tokens)
    and then a success row with fallback_used, model = the serving model, model_routed = the target."""
    rid = "req-fallback"
    rows = [
        {
            "type": "decision",
            "v": 2,
            "ts": "2026-10-04T09:00:00.000Z",
            "request_id": rid,
            "decision": "allow",
            "team": "payments-dev",
            "department": "payments",
            "model_requested": "claude-opus-5-5",
            "model_routed": "claude-opus-5-5",
            "findings": [],
        },
        {
            "type": "usage",
            "v": 2,
            "ts": "2026-10-04T09:00:00.500Z",
            "request_id": rid,
            "status": "failure",
            "model": "claude-opus-5-5",
            "model_routed": "claude-opus-5-5",
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "fallback_used": False,
            "error": "InternalServerError:500",
        },
        {
            "type": "usage",
            "v": 2,
            "ts": "2026-10-04T09:00:01.000Z",
            "request_id": rid,
            "status": "success",
            "model": "claude-sonnet-5-5",
            "model_routed": "claude-opus-5-5",
            "input_tokens": 10,
            "output_tokens": 20,
            "cost_usd": 0.001,
            "cost_source": "catalogue",
            "fallback_used": True,
            "error": None,
        },
    ]
    [rec] = build_dataset(rows)["records"]
    assert rec["status"] == "success" and rec["error"] is None and rec["fallback_used"] is True
    assert (rec["model_requested"], rec["model_routed"]) == ("claude-opus-5-5", "claude-sonnet-5-5")
    assert (rec["input_tokens"], rec["output_tokens"], rec["cost_usd"]) == (10, 20, 0.001)


def test_group_blocks_collapses_a_burst_from_one_key():
    def rec(rid, ts, decision="block", team="t1", key="k1"):
        return {"request_id": rid, "ts": ts, "decision": decision, "team": team, "key_id": key, "user": None}

    records = [
        rec("a", "2026-10-04T05:33:27.300Z"),
        rec("b", "2026-10-04T05:33:27.310Z"),
        rec("c", "2026-10-04T05:33:28.300Z"),
        rec("x", "2026-10-04T05:33:28.400Z", team="t2"),
        rec("ok", "2026-10-04T05:33:29.000Z", decision="allow"),
        rec("d", "2026-10-04T05:33:40.000Z"),
    ]
    out = group_blocks(records)
    assert [(r["request_id"], r.get("repeats")) for r in out] == [("a", 3), ("x", 1), ("ok", None), ("d", 1)]
    assert out[0]["request_ids"] == ["a", "b", "c"] and "repeats" not in records[0]


def test_second_model_summary_and_drift_alert():
    def shadow(ts, p):
        return {
            "type": "shadow",
            "ts": ts,
            "team": "t1",
            "source": "prompt",
            "jev_score": 0.02,
            "second": {"p": p, "model": "m", "categories": ["harmful"] if p >= 0.5 else []},
            "agree": p < 0.5,
            "possible_miss": p >= 0.5,
        }

    shadows = [shadow(f"2026-10-04T10:{i:02d}:00.000Z", 0.8 if i < 3 else 0.0) for i in range(10)]

    def rec(ts, reason, js="ok"):
        return {
            "ts": ts,
            "judge_status": "ok",
            "semantic_reason": reason,
            "jev_status": js,
            "semantic_source": "judge",
        }

    records = [
        rec("2026-10-04T11:00:00.000Z", "judge_rejected"),
        rec("2026-10-04T11:01:00.000Z", "judge_accepted"),
        rec("2026-10-04T11:02:00.000Z", "unavailable", js="unavailable"),
    ]
    out = second_model(records, shadows, {"alert_below": 0.9, "min_checks": 10, "rate": 0.1})
    t = out["total"]
    assert (t["answered"], t["agree"], t["possible_misses"], t["confirmed"], t["overruled"]) == (
        10,
        7,
        3,
        1,
        1,
    )
    assert out["alert"] == {"day": "2026-10-04", "agreement": 0.7, "threshold": 0.9, "checks": 10}
    assert out["decided_alone"] == 1 and len(out["possible_misses"]) == 3
    assert second_model(records, shadows[:5], {"min_checks": 10})["alert"] is None  # too few checks
