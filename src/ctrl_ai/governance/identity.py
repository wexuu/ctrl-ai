"""Who is calling: gateway keys (``state/keys.json``) and teams (``config/teams.yaml``).

Pure and unit-testable on the host; ``adapters/litellm/auth.py`` is the thin LiteLLM adapter.
Keys are stored as SHA-256 hashes only (written by the admin panel). The raw
key is never stored, logged or put into the returned identity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ctrl_ai.core.context import ADMIN_IDENTITY, Identity
from ctrl_ai.core.filestore import load_yaml
from ctrl_ai.core.schema import validate

INVALID_KEY_MESSAGE = "Invalid or revoked ctrl-ai key"


@dataclass(frozen=True)
class Team:
    id: str
    name: str
    department: str
    profile: str | None = None
    mode: str | None = None
    data_class: str = "internal"
    default_model: str | None = None
    budget: dict = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class Teams:
    teams: dict[str, Team]
    departments: dict[str, str]

    def get(self, team_id: str | None) -> Team | None:
        return self.teams.get(team_id) if team_id else None

    def profile_of(self, team_id: str | None) -> str | None:
        team = self.get(team_id)
        return team.profile if team and team.profile else None


EMPTY_TEAMS = Teams(teams={}, departments={})


def parse_teams(raw: bytes) -> Teams:
    doc = load_yaml(raw)
    validate(doc, "teams")
    deps = {d["id"]: d.get("name", d["id"]) for d in doc.get("departments") or []}
    teams = {}
    for t in doc.get("teams") or []:
        teams[t["id"]] = Team(
            id=t["id"],
            name=t.get("name", t["id"]),
            department=t["department"],
            profile=t.get("profile") or None,
            mode=t.get("mode") or None,
            data_class=t.get("data_class", "internal"),
            default_model=t.get("default_model"),
            budget=dict(t.get("budget") or {}),
        )
    return Teams(teams=teams, departments=deps)


@dataclass(frozen=True)
class KeyRecord:
    id: str
    hash: str
    team: str
    user: str | None
    expires: str | None
    revoked: bool


def parse_keys(raw: bytes) -> dict[str, KeyRecord]:
    doc = json.loads(raw.decode("utf-8"))
    validate(doc, "keys")
    out = {}
    for k in doc.get("keys") or []:
        out[k["hash"]] = KeyRecord(
            id=k["id"],
            hash=k["hash"],
            team=k["team"],
            user=k.get("user"),
            expires=k.get("expires"),
            revoked=bool(k.get("revoked")),
        )
    return out


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def key_expired(expires: str | None, now: datetime) -> bool:
    """An unreadable expiry counts as expired: fail closed."""
    if not expires:
        return False
    try:
        when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError:
        return True  # an unreadable expiry is treated as expired: fail closed on auth
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when <= now


@dataclass(frozen=True)
class AuthResult:
    identity: Identity | None
    key_hash: str | None = None
    reason: str | None = None  # why it failed: missing, unknown, revoked, expired


def authenticate(
    api_key: Any,
    master_key: str | None,
    keys: dict[str, KeyRecord],
    teams: Teams,
    now: datetime | None = None,
) -> AuthResult:
    """Check a gateway key. Master key → admin; a known, live key → its team's identity."""
    if not isinstance(api_key, str) or not api_key:
        return AuthResult(None, reason="missing")
    if master_key and hmac.compare_digest(api_key.encode("utf-8"), master_key.encode("utf-8")):
        return AuthResult(ADMIN_IDENTITY, key_hash=None)
    digest = hash_key(api_key)
    record = None
    for stored_hash, rec in keys.items():
        # Constant-time comparison on every stored hash, so timing reveals nothing.
        if hmac.compare_digest(stored_hash, digest):
            record = rec
    if record is None:
        return AuthResult(None, reason="unknown")
    if record.revoked:
        return AuthResult(None, reason="revoked")
    if key_expired(record.expires, now or datetime.now(UTC)):
        return AuthResult(None, reason="expired")
    return AuthResult(identity_for(record.team, record.user, record.id, teams), key_hash=digest)


def identity_for(team_id: str, user: str | None, key_id: str | None, teams: Teams) -> Identity:
    team = teams.get(team_id)
    if team is None:
        return Identity(
            team=team_id, department="unknown", user=user, key_id=key_id, profile=None, error="unknown_team"
        )
    return Identity(
        team=team.id,
        department=team.department,
        user=user,
        key_id=key_id,
        profile=team.profile,
        mode=team.mode,
    )


def route_hint(user_api_key_dict: Any) -> str | None:
    """The route our custom auth recorded (``claude_subscription`` or ``external``), if any."""
    try:
        metadata = getattr(user_api_key_dict, "metadata", None) or {}
        value = metadata.get("ctrl_ai_route") if isinstance(metadata, dict) else None
        return value if value in ("claude_subscription", "external") else None
    except Exception:
        return None


def resolve(user_api_key_dict: Any) -> Identity:
    """Identity from LiteLLM's ``UserAPIKeyAuth`` as our custom auth filled it.

    Our auth puts team, user, key id, department and profile there; anything else (no
    custom auth, or LiteLLM's own master-key object) means the admin identity.
    """
    try:
        metadata = getattr(user_api_key_dict, "metadata", None) or {}
        if not isinstance(metadata, dict) or "ctrl_ai_department" not in metadata:
            return ADMIN_IDENTITY
        return Identity(
            team=getattr(user_api_key_dict, "team_id", None),
            department=metadata.get("ctrl_ai_department"),
            user=getattr(user_api_key_dict, "user_id", None),
            key_id=getattr(user_api_key_dict, "key_alias", None),
            profile=metadata.get("ctrl_ai_profile"),
            error=metadata.get("ctrl_ai_identity_error"),
            mode=metadata.get("ctrl_ai_mode"),
        )
    except Exception:
        return ADMIN_IDENTITY
