"""Break-glass override tokens. Pure: signing, verification, request validation.

Token: base64url(json({"id","sub","relax","exp"})) + "." + hex(HMAC-SHA256(secret, base64 part)).
The token is never stored; the register (state/break_glass.json) holds only its id.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _ts(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())


def make_token(record: dict, secret: str) -> str:
    payload = json.dumps(
        {
            "id": record["id"],
            "sub": record["subject"],
            "relax": record["relax"],
            "exp": _ts(record["expires_at"]),
        },
        separators=(",", ":"),
    )
    body = _b64(payload.encode())
    return body + "." + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()


def read_token(token: Any, secret: str, now: float | None = None) -> tuple[dict | None, str | None]:
    """Verify signature and expiry; return (claims, None) or (None, reason)."""
    if not secret:
        return None, "no_secret"
    if not isinstance(token, str) or token.count(".") != 1 or len(token) > 4096:
        return None, "malformed"
    body, sig = token.split(".")
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None, "bad_signature"
    try:
        claims = json.loads(_unb64(body))
    except Exception:
        return None, "malformed"
    if not isinstance(claims, dict) or not isinstance(claims.get("exp"), int):
        return None, "malformed"
    now = now if now is not None else datetime.now(UTC).timestamp()
    if claims["exp"] <= now:
        return claims, "expired"
    return claims, None


def validate_request(
    settings: dict, subject: str, relax: list[str], minutes: int, ticket: str, reason: str
) -> str | None:
    """Why an issue request is refused, or None."""
    if not settings.get("enabled", True):
        return "break-glass is disabled in the policy"
    if not (subject.startswith("team:") or subject.startswith("user:")) or len(subject) < 6:
        return "subject must be team:<id> or user:<name>"
    if not relax:
        return "name at least one control to relax"
    never = set(settings.get("never_relax") or [])
    blocked = [r for r in relax if r in never]
    if blocked:
        return f"never relaxable: {', '.join(blocked)}"
    if minutes < 1 or minutes > int(settings.get("max_minutes", 240)):
        return f"minutes must be between 1 and {settings.get('max_minutes', 240)}"
    if settings.get("require_ticket", True) and not ticket:
        return "a ticket is required"
    if not reason or len(reason) < 3:
        return "give a reason"
    return None


def effective_relax(relax: list[str], never_relax: list[str]) -> list[str]:
    return [r for r in relax if r not in set(never_relax)]


def subject_matches(subject: str, team: str | None, user: str | None) -> bool:
    if subject.startswith("team:"):
        return team is not None and subject[5:] == team
    if subject.startswith("user:"):
        return user is not None and subject[5:] == user
    return False


# ------------------------------------------------------------------ gateway side


class UseTracker:
    """Writes a ``use`` row on the first use of a token in each 10-minute window, ``expire`` once."""

    def __init__(self):
        self._used: dict[str, int] = {}
        self._expired: set[str] = set()

    def use(self, override_id: str, now: float) -> bool:
        window = int(now // 600)
        if self._used.get(override_id) == window:
            return False
        self._used[override_id] = window
        return True

    def expire(self, override_id: str) -> bool:
        if override_id in self._expired:
            return False
        self._expired.add(override_id)
        return True


def check(
    token: Any,
    secret: str,
    register: dict,
    team: str | None,
    user: str | None,
    never_relax: list[str],
    now: float,
) -> tuple[dict | None, dict | None, str | None]:
    """Return (record, break_glass row field, event) for a header value.

    The row field is ``{id, relaxed}`` when valid, ``{id, error}`` otherwise; event is
    ``use`` / ``expire`` / None. A bad token never blocks; it is only recorded.
    """
    claims, error = read_token(token, secret, now)
    oid = claims.get("id") if isinstance(claims, dict) else None
    record = None
    for r in (register or {}).get("overrides") or []:
        if r.get("id") == oid:
            record = r
    if error == "expired":
        return record, {"id": oid, "error": "expired"}, "expire"
    if error:
        return None, {"id": None, "error": error}, None
    if record is None:
        return None, {"id": None, "error": "not_in_register"}, None
    if record.get("revoked"):
        return record, {"id": oid, "error": "revoked"}, None
    try:
        if _ts(record["expires_at"]) <= now:
            return record, {"id": oid, "error": "expired"}, "expire"
    except Exception:
        return None, {"id": oid, "error": "malformed"}, None
    if not subject_matches(record.get("subject", ""), team, user):
        return None, {"id": oid, "error": "wrong_subject"}, None
    relax = effective_relax(list(record.get("relax") or []), never_relax)
    return record, {"id": oid, "relaxed": relax}, "use"
