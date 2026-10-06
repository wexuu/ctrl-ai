"""Authentication, config store (validation, save, history, rollback), admin audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ctrl_ai.admin import admin_audit, config_store, regex_guard
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.settings import AdminSettings

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def client(env):
    from ctrl_ai.admin import app as ui_app

    return TestClient(ui_app.create_app())


def csrf(client) -> str:
    return client.get("/api/auth/session").json()["csrf"]


def admin_rows(env) -> list[dict]:
    path = env / "admin.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# ---------------------------------------------------------------- open-access identity and CSRF


def test_current_admin_is_local_admin_with_all_roles(client):
    s = client.get("/api/auth/session").json()
    assert s["user"] == "local-admin" and s["open_access"] is True
    assert set(s["roles"]) == {"platform-admin", "security-officer", "finance-viewer"}
    assert "single sign-on" in s["banner"]
    assert client.get("/api/nav").json()["user"] == "local-admin"


def test_csrf_required_for_changes(client, env):
    got = client.get("/api/admin/config/policy")
    assert got.status_code == 200  # open, no sign-in
    got = got.json()
    body = {"doc": got["doc"], "expected_version": got["version"], "reason": "unit test"}
    assert client.post("/api/admin/config/policy", json=body).status_code == 403  # no CSRF
    assert (
        client.post("/api/admin/config/policy", json=body, headers={"x-ctrl-ai-csrf": "bad"}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/admin/config/policy", json=body, headers={"x-ctrl-ai-csrf": csrf(client)}
        ).status_code
        == 200
    )
    rows = admin_rows(env)
    assert [r["action"] for r in rows] == ["policy.save"] and rows[0]["actor"] == "local-admin"
    assert "CTRL-AI-BLOCK-TEST" not in (env / "admin.jsonl").read_text()


def test_pages_are_open(client):
    assert client.get("/").status_code == 200
    for path in (
        "/dashboard",
        "/admin/policy",
        "/admin/models",
        "/admin/teams",
        "/admin/history",
        "/admin/tools",
    ):
        assert client.get(path).status_code == 200, path
    assert client.get("/login").status_code == 404


# ---------------------------------------------------------------- validation


def _policy(**extra):
    doc = {
        "version": 2,
        "mode": "enforce",
        "profiles": {
            "observe": {"mode": "monitor"},
            "balanced": {"mode": "enforce"},
            "strict": {"mode": "enforce"},
        },
        "default_profile": "balanced",
        "rules": [{"id": "a", "type": "contains", "value": "x"}],
    }
    doc.update(extra)
    return doc


def errors(name, doc, **others):
    settings = AdminSettings.from_env()
    return [
        e.path + ": " + e.message for e in config_store.validate(settings, name, doc, others=others or None)
    ]


def test_committed_files_are_valid(env, settings):
    for name in ("policy", "models", "teams", "mcp"):
        assert errors(name, config_store.read_doc(settings, name)) == [], name


def test_policy_validation_rules(env):
    assert errors("policy", _policy()) == []
    assert any("default_profile" in e for e in errors("policy", _policy(default_profile="nope")))
    assert any(
        "duplicate rule id" in e
        for e in errors(
            "policy",
            _policy(
                rules=[
                    {"id": "a", "type": "contains", "value": "x"},
                    {"id": "a", "type": "contains", "value": "y"},
                ]
            ),
        )
    )
    assert any(
        "compile" in e for e in errors("policy", _policy(rules=[{"id": "r", "type": "regex", "value": "(["}]))
    )
    assert any(
        "nested quantifier" in e
        for e in errors("policy", _policy(rules=[{"id": "r", "type": "regex", "value": "(a+)+$"}]))
    )
    assert any(
        "review_threshold" in e
        for e in errors("policy", _policy(jev={"review_threshold": 0.8, "block_threshold": 0.7}))
    )
    assert any(
        "never_relax" in e for e in errors("policy", _policy(break_glass={"never_relax": ["no-such-rule"]}))
    )
    assert (
        errors("policy", _policy(break_glass={"never_relax": ["secret-aws-key", "a", "model-banned"]})) == []
    )
    # A profile used by a team cannot be removed.
    doc = _policy(profiles={"balanced": {"mode": "enforce"}})
    assert any("strict" in e for e in errors("policy", doc))
    # Schema errors carry the field path.
    assert any(e.startswith("mode:") for e in errors("policy", _policy(mode="maybe")))


def test_v1_policy_still_valid(env):
    assert (
        errors("policy", {"mode": "monitor", "rules": [{"id": "x", "type": "contains", "value": "y"}]}) == []
    )


def test_models_validation_rules(env, settings):
    doc = config_store.read_doc(settings, "models")
    m = doc["models"]
    bad = json.loads(json.dumps(doc))
    bad["models"][0]["equivalent"] = "nope"
    assert any("not in the catalogue" in e for e in errors("models", bad))
    bad = json.loads(json.dumps(doc))
    bad["models"][1]["status"] = "banned"
    assert any("is banned" in e for e in errors("models", bad))
    bad = json.loads(json.dumps(doc))
    del bad["models"][0]["price"]
    assert any("needs a price" in e for e in errors("models", bad))
    bad = json.loads(json.dumps(doc))
    bad["models"][2]["status"] = "deprecated"
    assert any("sunset" in e for e in errors("models", bad))
    bad = json.loads(json.dumps(doc))
    bad["models"][2]["teams"] = ["ghost-team"]
    assert any("ghost-team" in e for e in errors("models", bad))
    bad = json.loads(json.dumps(doc))
    bad["models"].append(dict(m[0]))
    assert any("duplicate" in e for e in errors("models", bad))


def test_teams_validation_rules(env, settings):
    doc = config_store.read_doc(settings, "teams")
    bad = json.loads(json.dumps(doc))
    bad["teams"][0]["department"] = "nowhere"
    assert any("department" in e for e in errors("teams", bad))
    bad = json.loads(json.dumps(doc))
    bad["teams"][0]["default_model"] = "gpt-9"
    assert any("not in the catalogue" in e for e in errors("teams", bad))
    bad = json.loads(json.dumps(doc))
    bad["teams"][2]["default_model"] = "chat-mistral"  # markets-quant is not on chat-mistral's list
    assert any("not allowed" in e for e in errors("teams", bad))
    bad = json.loads(json.dumps(doc))
    bad["teams"][0]["profile"] = "lenient"
    assert any("profile" in e for e in errors("teams", bad))
    bad = json.loads(json.dumps(doc))
    bad["teams"].append(dict(doc["teams"][0]))
    assert any("duplicate" in e for e in errors("teams", bad))
    # claude-* wildcard resolves for a team default model.
    ok = json.loads(json.dumps(doc))
    ok["teams"][0]["default_model"] = "claude-fable-5-1"
    assert errors("teams", ok) == []


def test_mcp_names_unique(env):
    s = {"name": "jira", "url": "http://x", "teams": ["*"], "status": "approved"}
    assert any("duplicate" in e for e in errors("mcp", {"servers": [s, dict(s)]}))


def test_redos_guard():
    assert regex_guard.check("AKIA[0-9A-Z]{16}") is None
    assert regex_guard.check("-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----") is None
    assert "nested" in regex_guard.check("(a+)+b")
    assert "nested" in regex_guard.check("(.*)*x")
    assert "compile" in regex_guard.check("(")
    # Not caught by the static check, caught by the timed run.
    assert regex_guard.timed_problem("(a|aa)*c") is not None
    assert regex_guard.timed_problem("abc") is None


# ---------------------------------------------------------------- save, history, rollback


def test_save_conflict_history_rollback(env, settings):
    doc, text, v0 = config_store.read(settings, "policy")
    doc["mode"] = "monitor"
    with pytest.raises(StoreError) as exc:
        config_store.save(settings, "policy", doc, expected_version="00000000", actor="admin", reason="test")
    assert exc.value.status == 409 and exc.value.current_version == v0
    with pytest.raises(StoreError) as exc:
        config_store.save(settings, "policy", doc, expected_version=v0, actor="admin", reason="no")
    assert exc.value.status == 422
    v1 = config_store.save(
        settings, "policy", doc, expected_version=v0, actor="admin", reason="switch to monitor"
    )
    assert v1 != v0
    new_doc, new_text, ver = config_store.read(settings, "policy")
    assert ver == v1 and new_doc["mode"] == "monitor" and new_text.startswith("# ctrl-ai policy")
    hist = config_store.history(settings, "policy")
    assert [h["version"] for h in hist] == [v0]
    assert (Path(str(env)) / "state" / "history" / "policy" / hist[0]["file"]).read_text() == text
    assert "+mode: monitor" in config_store.diff(settings, "policy", v0).replace("'", "")
    bad = dict(new_doc, mode="sometimes")
    with pytest.raises(StoreError) as exc:
        config_store.save(settings, "policy", bad, expected_version=v1, actor="admin", reason="bad")
    assert exc.value.status == 422 and exc.value.errors[0]["path"] == "mode"
    v2 = config_store.rollback(settings, "policy", v0, actor="admin", reason="undo")
    assert config_store.read_doc(settings, "policy")["mode"] == "enforce"
    assert len(config_store.history(settings, "policy")) == 2
    rows = admin_rows(env)
    assert [r["action"] for r in rows] == ["policy.save", "policy.rollback"]
    assert rows[0]["version_before"] == v0 and rows[0]["version_after"] == v1
    assert rows[1]["version_after"] == v2 and "undo" in rows[1]["reason"]
    assert "CTRL-AI-BLOCK-TEST" not in (env / "admin.jsonl").read_text()


def test_rollback_revalidates(env, settings):
    doc, _, v0 = config_store.read(settings, "teams")
    doc["teams"].append({"id": "new-team", "name": "New", "department": "retail"})
    config_store.save(settings, "teams", doc, expected_version=v0, actor="admin", reason="add team")
    # Make the old version invalid against today's other files: an old teams file whose team
    # uses a profile that a later policy removed.
    hist_file = env / "state" / "history" / "teams" / config_store.history(settings, "teams")[0]["file"]
    hist_file.write_text(hist_file.read_text().replace("profile: strict", "profile: lenient", 1))
    bad_version = config_store.version_of(hist_file.read_bytes())
    hist_file.rename(hist_file.with_name(hist_file.name[:-13] + bad_version + ".yaml"))
    with pytest.raises(StoreError) as exc:
        config_store.rollback(settings, "teams", bad_version, actor="admin", reason="try")
    assert exc.value.status == 422


def test_atomic_write_keeps_old_on_failure(env, monkeypatch):
    path = env / "policy.yaml"
    before = path.read_bytes()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(config_store.os, "replace", boom)
    with pytest.raises(OSError):
        config_store.atomic_write(path, b"mode: monitor\n")
    assert path.read_bytes() == before
    assert not [p for p in env.iterdir() if p.name.endswith(".tmp")]


def test_rendered_yaml_order_and_dates(env, settings):
    doc = config_store.read_doc(settings, "models")
    text = config_store.render(settings, "models", doc)
    parsed = yaml.safe_load(text)
    assert list(parsed["models"][0])[:5] == ["id", "display_name", "provider", "status", "data_class_max"]
    assert str(parsed["models"][0]["reviewed"]) == "2026-10-04"


def test_admin_row_fields(env, settings):
    row = admin_audit.write(
        settings.admin_audit_log, "key.issue", actor="local-admin", target="k_12345678", reason="r"
    )
    assert set(row) == {
        "type",
        "ts",
        "actor",
        "action",
        "target",
        "version_before",
        "version_after",
        "reason",
    }
    fixture = REPO / "tests" / "fixtures" / "admin-sample.jsonl"
    assert set(json.loads(fixture.read_text().splitlines()[0])) == set(row)


def test_api_validate_and_diff(client, env):
    csrf = globals()["csrf"](client)
    got = client.get("/api/admin/config/policy").json()
    doc = dict(got["doc"], mode="monitor")
    res = client.post(
        "/api/admin/config/policy/validate", json={"doc": doc}, headers={"x-ctrl-ai-csrf": csrf}
    ).json()
    assert res["errors"] == [] and "+mode: monitor" in res["diff"]
    res = client.post(
        "/api/admin/config/policy",
        json={"doc": doc, "expected_version": "deadbeef", "reason": "x y z"},
        headers={"x-ctrl-ai-csrf": csrf},
    )
    assert res.status_code == 409 and res.json()["current_version"] == got["version"]
    res = client.post(
        "/api/admin/config/policy",
        json={"doc": doc, "expected_version": got["version"], "reason": "monitor"},
        headers={"x-ctrl-ai-csrf": csrf},
    )
    assert res.status_code == 200
    hist = client.get("/api/admin/config/policy/history").json()
    assert hist["current"]["actor"] == "local-admin" and hist["current"]["reason"] == "monitor"
    assert hist["versions"][0]["version"] == got["version"]
    d = client.get(f"/api/admin/config/policy/diff?version={got['version']}").json()["diff"]
    assert "-mode: enforce" in d
    res = client.post(
        "/api/admin/config/policy/rollback",
        json={"version": got["version"], "reason": "back"},
        headers={"x-ctrl-ai-csrf": csrf},
    )
    assert res.status_code == 200
    rows = client.get("/api/admin/audit?action=policy.rollback").json()["rows"]
    assert len(rows) == 1


# ---------------------------------------------------------------- rule tester


def test_rule_tester_contains_and_regex(client):
    h = {"x-ctrl-ai-csrf": globals()["csrf"](client)}
    r = client.post(
        "/api/admin/policy/test-rule",
        json={"type": "contains", "value": "abc", "sample": "xxabcxxabc"},
        headers=h,
    ).json()
    assert r == {"matched": True, "spans": [[2, 5], [7, 10]]}
    r = client.post(
        "/api/admin/policy/test-rule",
        json={"type": "regex", "value": "AKIA[0-9A-Z]{16}", "sample": "key AKIAABCDEFGHIJKLMNOP"},
        headers=h,
    ).json()
    assert r["matched"] and r["spans"] == [[4, 24]]
    r = client.post(
        "/api/admin/policy/test-rule", json={"type": "regex", "value": "zzz", "sample": "abc"}, headers=h
    ).json()
    assert r == {"matched": False, "spans": []}


def test_rule_tester_refuses_redos_and_never_logs_sample(client, env):
    h = {"x-ctrl-ai-csrf": globals()["csrf"](client)}
    r = client.post(
        "/api/admin/policy/test-rule",
        json={"type": "regex", "value": "(a+)+$", "sample": "SECRET-SAMPLE-TEXT"},
        headers=h,
    )
    assert r.status_code == 422 and r.json()["refused"] is True
    assert (
        client.post(
            "/api/admin/policy/test-rule", json={"type": "regex", "value": "x", "sample": "y"}
        ).status_code
        == 403
    )
    assert not (env / "admin.jsonl").exists() or "SECRET-SAMPLE-TEXT" not in (env / "admin.jsonl").read_text()
