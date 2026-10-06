"""The model catalogue is edited through the admin API; the gateway enforces it."""

from __future__ import annotations

import pytest

from tests.e2e import harness as h

MODELS_FILE = h.RUNTIME / "models.yaml"


@pytest.fixture
def restore_models():
    original = MODELS_FILE.read_text(encoding="utf-8")
    yield
    MODELS_FILE.write_text(original, encoding="utf-8")


def _restrict(admin, model_id: str, teams: list[str]) -> str:
    cfg = admin.config("models")
    doc = cfg["doc"]
    for m in doc["models"]:
        if m["id"] == model_id:
            m["teams"] = teams
    resp = admin.save("models", doc, reason=f"e2e: restrict {model_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()["version"]


def test_catalogue_save_validates_and_writes(admin, restore_models):
    version = _restrict(admin, "claude-haiku-4-5", ["payments-dev"])
    cfg = admin.config("models")
    assert cfg["version"] == version
    haiku = next(m for m in cfg["doc"]["models"] if m["id"] == "claude-haiku-4-5")
    assert haiku["teams"] == ["payments-dev"]
    # An unknown team is refused with a field path.
    doc = cfg["doc"]
    doc["models"][0]["teams"] = ["no-such-team"]
    bad = admin.save("models", doc, reason="e2e: bad team")
    assert bad.status_code == 422 and bad.json()["errors"][0]["path"].startswith("models/0/teams")


def test_gateway_reroutes_team_not_allowed(admin, restore_models, audit_start):
    # Governance reroutes a team-not-allowed
    # request to the team's default model, which for retail-dev is chat-groq: the test stack then
    # called the real api.groq.com with an empty key (401). payments-dev's default is
    # claude-sonnet-5-5, served by the stub, so the reroute stays inside the test stack.
    _restrict(admin, "claude-haiku-4-5", ["retail-dev"])
    issued = admin.post("/api/admin/keys", {"team": "payments-dev", "user": "e2e-models", "label": "models"})
    assert issued.status_code == 200
    key = issued.json()["key"]
    r = h.post_chat(
        h.chat_body(h.remember("hello " + h.tag()), model="claude-haiku-4-5"), headers=h.bearer_headers(key)
    )
    assert r.status_code == 200, r.text
    row = h.decision_row(r, audit_start)
    assert row["team"] == "payments-dev"
    assert row["decision"] == "reroute" and row["route_reason"] == "team_not_allowed"
    assert row["model_routed"] == "claude-sonnet-5-5"
