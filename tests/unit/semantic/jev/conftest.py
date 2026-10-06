"""Shared fixtures for the ctrl_ai.semantic.jev unit tests. No network is used."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "jev"

TEST_KEY = "jev-unit-test-key-0123456789"
TEST_URL = "http://jev.test/v1/systemone"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def load_fixture():
    """Return a loader for files in tests/fixtures/jev/."""
    return _load


@pytest.fixture
def jev_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """A configured Jev environment pointing at a fake URL."""
    monkeypatch.setenv("JEV_API_KEY", TEST_KEY)
    monkeypatch.setenv("JEV_URL", TEST_URL)
    monkeypatch.setenv("JEV_TIMEOUT_S", "2.0")
    monkeypatch.setenv("JEV_MODEL", "jev-1.13.0")
    return monkeypatch
