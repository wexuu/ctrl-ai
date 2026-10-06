"""Admin app settings, read once from the environment when the app is created.

Everything the admin panel, the dashboard and the staging chat need from the environment is
here; the routers read it from ``request.app.state.settings`` (``admin_settings``). The
defaults are the container paths; ``deploy/docker/compose.yml`` sets each one explicitly.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import Request

REPO_ROOT = Path(__file__).resolve().parents[3]


def _list(raw: str) -> tuple[str, ...]:
    return tuple(p.strip() for p in raw.split(",") if p.strip())


@dataclass(frozen=True)
class AdminSettings:
    # The configuration files the panel edits, and the history of their versions.
    policy_file: str
    models_file: str
    teams_file: str
    mcp_file: str
    signatures_file: str
    history_dir: str
    schema_dir: str
    # Runtime state the panel writes: gateway keys and the break-glass register.
    keys_file: str
    break_glass_file: str
    # Logs: the gateway's audit log (read) and the admin audit log (written).
    audit_log: str
    admin_audit_log: str
    # The gateway, for the staging chat and the model list.
    gateway_url: str
    master_key: str = field(repr=False)
    ui_models: tuple[str, ...]  # the chat models the staging page offers
    ui_keyed_models: tuple[str, ...]  # of those, the provider models whose key is set
    # The Jev trust page and the per-span latency card.
    xai_reports: str
    xai_dataset: str
    prometheus_url: str  # empty: the card is hidden

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AdminSettings:
        env = os.environ if env is None else env

        def get(name: str, default: str) -> str:
            return env.get(name, default)

        return cls(
            policy_file=get("CTRL_AI_POLICY_FILE", "/app/config/policy.yaml"),
            models_file=get("CTRL_AI_MODELS_FILE", "/app/config/models.yaml"),
            teams_file=get("CTRL_AI_TEAMS_FILE", "/app/config/teams.yaml"),
            mcp_file=get("CTRL_AI_MCP_FILE", "/app/config/mcp.yaml"),
            signatures_file=get("CTRL_AI_SIGNATURES_FILE", "/app/config/signatures.yaml"),
            history_dir=get("CTRL_AI_HISTORY_DIR", "/app/state/history"),
            schema_dir=env.get("CTRL_AI_SCHEMA_DIR") or str(REPO_ROOT / "config" / "schema"),
            keys_file=get("CTRL_AI_KEYS_FILE", "/app/state/keys.json"),
            break_glass_file=get("CTRL_AI_BREAKGLASS_FILE", "/app/state/break_glass.json"),
            audit_log=get("CTRL_AI_AUDIT_LOG", "/app/logs/audit.jsonl"),
            admin_audit_log=get("CTRL_AI_ADMIN_AUDIT_LOG", "/app/logs/admin.jsonl"),
            gateway_url=get("CTRL_AI_GATEWAY_URL", "http://gateway:4000").rstrip("/"),
            master_key=get("LITELLM_MASTER_KEY", ""),
            ui_models=_list(get("CTRL_AI_UI_MODELS", "chat-mistral,chat-groq")),
            ui_keyed_models=_list(get("CTRL_AI_UI_KEYED_MODELS", "")),
            xai_reports=env.get("CTRL_AI_XAI_REPORTS") or str(REPO_ROOT / "reports" / "xai"),
            xai_dataset=env.get("CTRL_AI_XAI_DATASET") or str(REPO_ROOT / "datasets" / "xai"),
            prometheus_url=get("CTRL_AI_PROMETHEUS_URL", "").rstrip("/"),
        )


def admin_settings(request: Request) -> AdminSettings:
    """FastAPI dependency: the settings the app was created with."""
    return request.app.state.settings
