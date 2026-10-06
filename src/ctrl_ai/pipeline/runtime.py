"""The production engine, built once from the environment.

This is the composition root: the only place that turns settings into stores, clients and the
``Engine``. The LiteLLM adapters call ``get_engine()``, ``get_settings()`` and
``get_key_store()``; everything below them takes its collaborators as arguments.
"""

from __future__ import annotations

from functools import lru_cache

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.filestore import FileStore
from ctrl_ai.core.policy import PolicyStore
from ctrl_ai.core.schema import use_schema_dir
from ctrl_ai.core.settings import Settings
from ctrl_ai.core.state import RedisState
from ctrl_ai.detect.signatures import EMPTY_FEED, parse_feed
from ctrl_ai.governance.catalogue import EMPTY_CATALOGUE, parse_models
from ctrl_ai.governance.identity import EMPTY_TEAMS, KeyRecord, parse_keys, parse_teams
from ctrl_ai.pipeline.engine import EMPTY_REGISTER, Engine
from ctrl_ai.semantic.models import build_model
from ctrl_ai.semantic.outage import parse_register


def build_engine(settings: Settings | None = None) -> Engine:
    """An engine wired to the files, Redis and model clients the settings name."""
    s = settings or Settings.from_env()
    use_schema_dir(s.schema_dir)
    catalogue = FileStore(s.models_file, parse_models, EMPTY_CATALOGUE)
    common = {"jev_settings": s.jev, "provider_keys": s.provider_keys, "catalogue": catalogue}
    classifier = build_model(
        s.classifier_model, api_base=s.classifier_api_base, timeout_s=s.classifier_timeout_s, **common
    )
    judge = build_model(s.judge_model, api_base=s.judge_api_base, timeout_s=s.judge_timeout_s, **common)
    shadow = (
        build_model(s.shadow_model, api_base=s.judge_api_base, timeout_s=s.judge_timeout_s, **common)
        if s.shadow
        else None
    )
    return Engine(
        policy_store=PolicyStore(s.policy_file),
        audit=AuditLog(s.audit_log),
        state=RedisState(s.redis_url),
        teams=FileStore(s.teams_file, parse_teams, EMPTY_TEAMS),
        catalogue=catalogue,
        signatures=FileStore(s.signatures_file, parse_feed, EMPTY_FEED),
        break_glass_register=FileStore(s.break_glass_file, parse_register, dict(EMPTY_REGISTER)),
        classifier=classifier,
        judge=judge,
        shadow=shadow,
        masking_secret=s.masking_secret,
        break_glass_secret=s.break_glass_secret,
        classifier_timeout_s=s.jev.timeout_s
        if s.classifier_model.lower() == "jev"
        else s.classifier_timeout_s,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """The one engine the gateway's hooks share."""
    return build_engine(get_settings())


@lru_cache(maxsize=1)
def get_key_store() -> FileStore[dict[str, KeyRecord]]:
    """The gateway keys (hashes only) that the custom auth checks."""
    return FileStore(get_settings().keys_file, parse_keys, {})
