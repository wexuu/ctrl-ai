"""Fixtures for the admin panel's unit tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ctrl_ai.admin.settings import AdminSettings

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Copies of the committed config files, a history folder and an admin log in tmp."""
    for name in ("policy", "models", "teams", "mcp", "signatures"):
        shutil.copy(REPO / "tests" / "fixtures" / "config" / f"{name}.yaml", tmp_path / f"{name}.yaml")
    state = tmp_path / "state"
    (state / "history").mkdir(parents=True)
    (state / "keys.json").write_text('{"keys": []}')
    (state / "break_glass.json").write_text('{"overrides": []}')
    vals = {
        "CTRL_AI_POLICY_FILE": tmp_path / "policy.yaml",
        "CTRL_AI_MODELS_FILE": tmp_path / "models.yaml",
        "CTRL_AI_TEAMS_FILE": tmp_path / "teams.yaml",
        "CTRL_AI_MCP_FILE": tmp_path / "mcp.yaml",
        "CTRL_AI_SIGNATURES_FILE": tmp_path / "signatures.yaml",
        "CTRL_AI_HISTORY_DIR": state / "history",
        "CTRL_AI_ADMIN_AUDIT_LOG": tmp_path / "admin.jsonl",
        "CTRL_AI_SCHEMA_DIR": REPO / "config" / "schema",
        "CTRL_AI_KEYS_FILE": state / "keys.json",
        "CTRL_AI_BREAKGLASS_FILE": state / "break_glass.json",
        "CTRL_AI_AUDIT_LOG": tmp_path / "audit.jsonl",
    }
    for k, v in vals.items():
        monkeypatch.setenv(k, str(v))
    yield tmp_path


@pytest.fixture
def settings(env):
    """The admin settings for the env fixture's files."""
    return AdminSettings.from_env()
