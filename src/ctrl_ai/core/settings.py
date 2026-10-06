"""Gateway settings, read once from the environment.

Everything the gateway side needs from the environment is here, so the rest of the code
takes a ``Settings`` (or the objects built from it) instead of reading ``os.environ``.
The containers set every path explicitly; the defaults point at the repository checkout.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ctrl_ai.semantic.jev.settings import Settings as JevSettings
from ctrl_ai.semantic.jev.settings import settings_from_env as jev_settings_from_env

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CLASSIFIER_MODEL = "jev"
DEFAULT_JUDGE_MODEL = "groq/openai/gpt-oss-safeguard-20b"
DEFAULT_MODEL_TIMEOUT_S = 8.0


def _repo(*parts: str) -> str:
    return str(REPO_ROOT.joinpath(*parts))


def _seconds(raw: str | None, default: float) -> float:
    """A positive number of seconds, else the default (a typo must not hang the gateway)."""
    try:
        value = float(raw or default)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Settings:
    policy_file: str
    models_file: str
    teams_file: str
    signatures_file: str
    mcp_file: str
    keys_file: str
    break_glass_file: str
    audit_log: str
    schema_dir: str  # the JSON Schemas the configuration files are validated against
    redis_url: str  # empty: no shared state, every counter fails open
    masking_secret: str  # empty: requests are never rewritten
    break_glass_secret: str  # empty: break-glass tokens are refused
    # Decision models per role (see semantic/models.py): "jev", "none" or a LiteLLM model string.
    classifier_model: str
    classifier_api_base: str  # empty: the provider's default endpoint
    classifier_timeout_s: float  # for a LiteLLM classifier; Jev uses JEV_TIMEOUT_S
    judge_model: str
    judge_api_base: str
    judge_timeout_s: float
    shadow_model: str  # the shadow check uses the judge's endpoint and timeout
    shadow: bool  # shadow-sample requests the classifier accepted
    jev: JevSettings  # the JEV_* variables, read once
    master_key: str = field(repr=False)  # LiteLLM's master key: the admin identity
    groq_api_key: str = field(repr=False)
    anthropic_api_key: str = field(repr=False)
    gateway_config_file: str  # the LiteLLM config, for the start-up consistency check

    @property
    def provider_keys(self) -> dict[str, str]:
        """API keys by LiteLLM provider prefix, for the LiteLLM-backed decision models."""
        return {"groq": self.groq_api_key, "anthropic": self.anthropic_api_key}

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env

        def get(name: str, default: str) -> str:
            return env.get(name) or default

        judge_model = (env.get("CTRL_AI_JUDGE_MODEL") or DEFAULT_JUDGE_MODEL).strip()
        return cls(
            policy_file=get("CTRL_AI_POLICY_FILE", _repo("config", "policy.yaml")),
            models_file=get("CTRL_AI_MODELS_FILE", _repo("config", "models.yaml")),
            teams_file=get("CTRL_AI_TEAMS_FILE", _repo("config", "teams.yaml")),
            signatures_file=get("CTRL_AI_SIGNATURES_FILE", _repo("config", "signatures.yaml")),
            mcp_file=get("CTRL_AI_MCP_FILE", _repo("config", "mcp.yaml")),
            keys_file=get("CTRL_AI_KEYS_FILE", _repo("state", "keys.json")),
            break_glass_file=get("CTRL_AI_BREAKGLASS_FILE", _repo("state", "break_glass.json")),
            audit_log=get("CTRL_AI_AUDIT_LOG", _repo("logs", "audit.jsonl")),
            schema_dir=get("CTRL_AI_SCHEMA_DIR", _repo("config", "schema")),
            redis_url=env.get("CTRL_AI_REDIS_URL") or "",
            masking_secret=env.get("CTRL_AI_MASKING_SECRET") or "",
            break_glass_secret=env.get("CTRL_AI_BREAKGLASS_SECRET") or "",
            classifier_model=(env.get("CTRL_AI_CLASSIFIER_MODEL") or DEFAULT_CLASSIFIER_MODEL).strip(),
            classifier_api_base=env.get("CTRL_AI_CLASSIFIER_API_BASE") or "",
            classifier_timeout_s=_seconds(env.get("CTRL_AI_CLASSIFIER_TIMEOUT_S"), DEFAULT_MODEL_TIMEOUT_S),
            judge_model=judge_model,
            judge_api_base=env.get("CTRL_AI_JUDGE_API_BASE") or "",
            judge_timeout_s=_seconds(env.get("CTRL_AI_JUDGE_TIMEOUT_S"), DEFAULT_MODEL_TIMEOUT_S),
            shadow_model=(env.get("CTRL_AI_SHADOW_MODEL") or judge_model).strip(),
            shadow=env.get("CTRL_AI_SHADOW", "1") != "0",
            jev=jev_settings_from_env(env),
            master_key=env.get("LITELLM_MASTER_KEY") or "",
            groq_api_key=env.get("GROQ_API_KEY") or "",
            anthropic_api_key=env.get("ANTHROPIC_API_KEY") or "",
            gateway_config_file=get("CTRL_AI_GATEWAY_CONFIG_FILE", "/app/gateway/config.yaml"),
        )
