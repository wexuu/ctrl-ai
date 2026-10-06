"""Gateway keys (state/keys.json) and the break-glass register (state/break_glass.json).

Only the SHA-256 of a key is stored, with its first 12 characters as a recognisable prefix.
The key itself is returned once, to the admin who issued it, and never written or logged.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from ctrl_ai.admin import admin_audit, config_store
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.settings import AdminSettings
from ctrl_ai.governance.breakglass import override_expired
from ctrl_ai.governance.identity import hash_key, key_expired

KEY_PREFIX = "sk-ctrl-ai-"


def generate_key() -> str:
    """sk-ctrl-ai- followed by 48 hex characters."""
    return KEY_PREFIX + secrets.token_hex(24)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def key_status(record: dict, now: datetime | None = None) -> str:
    if record.get("revoked"):
        return "revoked"
    return "expired" if key_expired(record.get("expires"), now or _now()) else "active"


def issue(
    settings: AdminSettings, team: str, user: str, label: str = "", expires: str | None = None, *, actor: str
) -> tuple[str, dict]:
    """Create a key for a team; returns (key, stored record). The key is not kept anywhere."""
    teams = {t.get("id") for t in config_store.read_doc(settings, "teams").get("teams", [])}
    if team not in teams:
        raise StoreError(422, f"team {team!r} does not exist", [{"path": "team", "message": "unknown team"}])
    user = (user or "").strip()[:80]
    if not user:
        raise StoreError(422, "user is required", [{"path": "user", "message": "required"}])
    exp = None
    if expires:
        parsed = _parse(expires if "T" in expires else expires + "T23:59:59Z")
        if parsed is None:
            raise StoreError(422, "expires is not a date", [{"path": "expires", "message": "not a date"}])
        exp = _iso(parsed)
    doc = config_store.read_state(settings, "keys")
    ids = {k.get("id") for k in doc["keys"]}
    kid = "k_" + secrets.token_hex(4)
    while kid in ids:
        kid = "k_" + secrets.token_hex(4)
    key = generate_key()
    record = {
        "id": kid,
        "hash": hash_key(key),
        "prefix": key[:12],
        "team": team,
        "user": user,
        "label": (label or "").strip()[:80],
        "created": _iso(_now()),
        "expires": exp,
        "revoked": False,
    }
    doc["keys"].append(record)
    config_store.write_state(settings, "keys", doc)
    admin_audit.write(
        settings.admin_audit_log, "key.issue", actor=actor, target=kid, reason=f"team {team}, user {user}"
    )
    return key, record


def revoke(settings: AdminSettings, key_id: str, *, actor: str, reason: str) -> dict:
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise StoreError(422, "A reason of at least 3 characters is required")
    doc = config_store.read_state(settings, "keys")
    for record in doc["keys"]:
        if record.get("id") == key_id:
            record["revoked"] = True
            config_store.write_state(settings, "keys", doc)
            admin_audit.write(
                settings.admin_audit_log, "key.revoke", actor=actor, target=key_id, reason=reason
            )
            return record
    raise StoreError(404, f"key {key_id} not found")


def list_keys(settings: AdminSettings, last_used: dict | None = None) -> list[dict]:
    """Stored records (never a key), with status and last use from the audit log."""
    last_used = last_used or {}
    out = []
    for k in config_store.read_state(settings, "keys")["keys"]:
        rec = {
            f: k.get(f) for f in ("id", "prefix", "team", "user", "label", "created", "expires", "revoked")
        }
        rec["status"] = key_status(k)
        rec["last_used"] = last_used.get(k.get("id"))
        out.append(rec)
    return out


def override_status(record: dict, now: datetime | None = None) -> str:
    if record.get("revoked"):
        return "revoked"
    return "expired" if override_expired(record, (now or _now()).timestamp()) else "active"


def list_overrides(settings: AdminSettings) -> list[dict]:
    out = []
    for o in config_store.read_state(settings, "break_glass")["overrides"]:
        rec = dict(o)
        rec["status"] = override_status(o)
        out.append(rec)
    return out


def active_overrides(settings: AdminSettings) -> list[dict]:
    return [o for o in list_overrides(settings) if o["status"] == "active"]


def revoke_override(settings: AdminSettings, override_id: str, *, actor: str, reason: str) -> dict:
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise StoreError(422, "A reason of at least 3 characters is required")
    doc = config_store.read_state(settings, "break_glass")
    for record in doc["overrides"]:
        if record.get("id") == override_id:
            record["revoked"] = True
            config_store.write_state(settings, "break_glass", doc)
            admin_audit.write(
                settings.admin_audit_log, "break_glass.revoke", actor=actor, target=override_id, reason=reason
            )
            return record
    raise StoreError(404, f"override {override_id} not found")


# ---------------------------------------------------------------- semantic-outage switch

OUTAGE_MODES = ("degrade", "fail_closed", "normal")
DEFAULT_MAX_OUTAGE_MINUTES = 240


def outage_switch(settings: AdminSettings) -> dict | None:
    """The manual switch in state/break_glass.json (`semantic_outage`), or None."""
    sw = config_store.read_state(settings, "break_glass").get("semantic_outage")
    return sw if isinstance(sw, dict) else None


def set_outage(
    settings: AdminSettings,
    mode: str,
    minutes: int,
    reason: str,
    ticket: str,
    *,
    actor: str,
    max_minutes: int | None = None,
) -> dict:
    """Same record as scripts/break-glass.py outage: time-boxed, with reason and ticket."""
    if mode not in OUTAGE_MODES:
        raise StoreError(
            422, "mode must be degrade, fail_closed or normal", [{"path": "mode", "message": "unknown mode"}]
        )
    reason, ticket = (reason or "").strip(), (ticket or "").strip()
    if len(reason) < 3:
        raise StoreError(
            422, "A reason of at least 3 characters is required", [{"path": "reason", "message": "required"}]
        )
    if not ticket:
        raise StoreError(422, "An incident ticket is required", [{"path": "ticket", "message": "required"}])
    limit = max_minutes or DEFAULT_MAX_OUTAGE_MINUTES
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        minutes = 0
    if not 1 <= minutes <= limit:
        raise StoreError(
            422, f"minutes must be between 1 and {limit}", [{"path": "minutes", "message": f"1..{limit}"}]
        )
    now = _now()
    record = {
        "active": True,
        "mode": mode,
        "reason": reason[:300],
        "ticket": ticket[:60],
        "issued_by": actor,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(minutes=minutes)),
    }
    doc = config_store.read_state(settings, "break_glass")
    doc["semantic_outage"] = record
    config_store.write_state(settings, "break_glass", doc)
    admin_audit.write(
        settings.admin_audit_log,
        "break_glass.outage_set",
        actor=actor,
        target=f"semantic:{mode}",
        reason=f"{reason} ({ticket}, {minutes} min)",
    )
    return record


def end_outage(settings: AdminSettings, *, actor: str, reason: str) -> dict:
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise StoreError(422, "A reason of at least 3 characters is required")
    doc = config_store.read_state(settings, "break_glass")
    sw = doc.get("semantic_outage")
    if not isinstance(sw, dict) or not sw.get("active"):
        raise StoreError(409, "No manual semantic-outage switch is active")
    sw["active"] = False
    config_store.write_state(settings, "break_glass", doc)
    admin_audit.write(
        settings.admin_audit_log,
        "break_glass.outage_end",
        actor=actor,
        target=f"semantic:{sw.get('mode')}",
        reason=reason,
    )
    return sw
