"""Key verification, identity, teams and the live-reloading stores."""

from __future__ import annotations

import hashlib
import json
import os
import types
from datetime import UTC, datetime
from pathlib import Path

from ctrl_ai.core.context import ADMIN_IDENTITY
from ctrl_ai.core.filestore import FileStore
from ctrl_ai.governance import identity as ident

REPO = Path(__file__).resolve().parents[3]
TEAMS = ident.parse_teams((REPO / "tests" / "fixtures" / "config" / "teams.yaml").read_bytes())
NOW = datetime(2026, 10, 4, 8, 0, tzinfo=UTC)


def record(key: str, **over) -> dict:
    base = {
        "id": "k_0a1b2c3d",
        "hash": hashlib.sha256(key.encode()).hexdigest(),
        "team": "payments-dev",
        "user": "piotr",
        "created": "2026-10-04T07:00:00Z",
        "expires": None,
        "revoked": False,
    }
    return {**base, **over}


def keys_of(*records) -> dict:
    return ident.parse_keys(json.dumps({"keys": list(records)}).encode())


def test_known_key_gives_team_identity():
    result = ident.authenticate("sk-ctrl-ai-abc", "master", keys_of(record("sk-ctrl-ai-abc")), TEAMS, NOW)
    assert result.identity == ident.Identity(
        "payments-dev", "payments", "piotr", "k_0a1b2c3d", "strict", mode="enforce"
    )
    assert result.key_hash == hashlib.sha256(b"sk-ctrl-ai-abc").hexdigest()


def test_master_key_is_admin():
    result = ident.authenticate("master", "master", {}, TEAMS, NOW)
    assert result.identity == ADMIN_IDENTITY and result.key_hash is None


def test_unknown_revoked_expired_missing():
    keys = keys_of(
        record("sk-a", id="k_00000001", revoked=True),
        record("sk-b", id="k_00000002", expires="2026-10-04T07:59:59Z"),
        record("sk-c", id="k_00000003", expires="2026-10-05T00:00:00Z"),
    )
    assert ident.authenticate("sk-zzz", "m", keys, TEAMS, NOW).reason == "unknown"
    assert ident.authenticate("sk-a", "m", keys, TEAMS, NOW).reason == "revoked"
    assert ident.authenticate("sk-b", "m", keys, TEAMS, NOW).reason == "expired"
    assert ident.authenticate("sk-c", "m", keys, TEAMS, NOW).identity is not None
    assert ident.authenticate("", "m", keys, TEAMS, NOW).reason == "missing"
    assert ident.authenticate(None, "m", keys, TEAMS, NOW).reason == "missing"


def test_unknown_team_is_kept_with_an_error():
    result = ident.authenticate("sk-x", None, keys_of(record("sk-x", team="ghosts")), TEAMS, NOW)
    assert result.identity.team == "ghosts" and result.identity.department == "unknown"
    assert result.identity.profile is None and result.identity.error == "unknown_team"


def test_constant_time_compare_is_used(monkeypatch):
    calls = []
    real = ident.hmac.compare_digest
    monkeypatch.setattr(ident.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    ident.authenticate("sk-x", "master", keys_of(record("sk-x"), record("sk-y", id="k_00000009")), TEAMS, NOW)
    assert len(calls) == 3  # the master key, then every stored hash


def test_keys_file_reload_and_invalid_file_keeps_last_good(tmp_path):
    path = tmp_path / "keys.json"
    store = FileStore(str(path), ident.parse_keys, {})
    assert store.current() == {}
    path.write_text(json.dumps({"keys": [record("sk-1")]}))
    assert len(store.current()) == 1
    path.write_text(json.dumps({"keys": [record("sk-1"), record("sk-2", id="k_00000002")]}))
    os.utime(path, ns=(10**18, 10**18))
    assert len(store.current()) == 2
    path.write_text('{"keys": [{"id": "bad"}]}')
    os.utime(path, ns=(2 * 10**18, 2 * 10**18))
    assert len(store.current()) == 2 and store.last_error


def test_resolve_from_user_api_key_dict():
    obj = types.SimpleNamespace(
        team_id="retail-dev",
        user_id="anna",
        key_alias="k_11111111",
        metadata={"ctrl_ai_department": "retail", "ctrl_ai_profile": "balanced"},
    )
    assert ident.resolve(obj) == ident.Identity("retail-dev", "retail", "anna", "k_11111111", "balanced")
    assert ident.resolve(types.SimpleNamespace(metadata={})) == ADMIN_IDENTITY
    assert ident.resolve(None) == ADMIN_IDENTITY


def test_teams_file_parses_profiles_and_budgets():
    assert TEAMS.get("payments-dev").profile == "strict"
    assert TEAMS.get("payments-dev").budget["on_exceeded"] == "downgrade"
    assert TEAMS.profile_of("ai-platform") == "observe"
    assert TEAMS.departments["platform"] == "AI Platform"


def test_team_mode_overrides_the_global_mode():
    from pathlib import Path

    from ctrl_ai.core.policy import parse_policy

    policy = parse_policy(
        (Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "config" / "policy.yaml").read_bytes()
    )
    profile = policy.profile("strict")
    assert policy.effective_mode(profile, "monitor") == "monitor"
    assert policy.effective_mode(profile, None) == profile.mode
