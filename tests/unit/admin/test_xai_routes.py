"""Jev trust page API: reads the published report, never calls a model, and returns
case text only for the authored synthetic casebook."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from ctrl_ai.admin import app as ui_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CTRL_AI_XAI_REPORTS", str(tmp_path / "reports"))
    monkeypatch.setenv("CTRL_AI_XAI_DATASET", str(tmp_path / "ds"))
    (tmp_path / "ds").mkdir()
    (tmp_path / "ds" / "cases.jsonl").write_text(
        json.dumps(
            {"case_id": "S01", "source": "prompt", "text": "hello", "input_origin": "authored_synthetic"}
        )
        + "\n"
        + json.dumps({"case_id": "R01", "source": "prompt", "text": "real", "input_origin": "production"})
        + "\n"
    )
    return TestClient(ui_app.create_app()), tmp_path


def test_no_report_is_an_explicit_state(client):
    c, _ = client
    r = c.get("/api/xai/report")
    assert r.status_code == 200 and r.json()["state"] == "no_report"


def test_report_is_served_with_publication_time(client, monkeypatch):
    c, tmp = client
    (tmp / "reports").mkdir()
    (tmp / "reports" / "latest.json").write_text(json.dumps({"mode": "recorded_real", "run": {}}))
    import httpx

    def boom(*a, **k):
        raise AssertionError("the page must not call a model")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    body = c.get("/api/xai/report").json()
    assert body["state"] == "ok" and body["mode"] == "recorded_real" and body["published_at"]


def test_case_text_only_for_synthetic_cases(client):
    c, _ = client
    assert c.get("/api/xai/case/S01").json()["text"] == "hello"
    assert c.get("/api/xai/case/R01").status_code == 404
    assert c.get("/api/xai/case/nope").status_code == 404


def test_page_is_served(client):
    c, _ = client
    r = c.get("/jev-trust")
    assert r.status_code == 200 and "/static/xai.js" in r.text
