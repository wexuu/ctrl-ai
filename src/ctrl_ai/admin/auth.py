"""Who is using the admin panel and the dashboard, and CSRF protection for changes.

Open access: there is no sign-in. Every admin and dashboard
route depends on `current_admin`, which returns the fixed `local-admin` with all roles. This is
the seam where the organisation's single sign-on plugs in: in production `current_admin` reads the
identity from the SSO session (OIDC/SAML via the central identity provider) and maps the
user's groups to roles. See docs/ADMIN.md.

CSRF protection stays, because the UI can be reached over the LAN: every POST, PUT, PATCH or
DELETE must carry the header X-CTRL-AI-CSRF equal to the token from GET /api/auth/session. The
token is random per process.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

CSRF_HEADER = "x-ctrl-ai-csrf"
LOCAL_ADMIN = "local-admin"
ROLES = ("platform-admin", "security-officer", "finance-viewer")
ACCESS_BANNER = (
    "Open access: no sign-in. In production, access is through the organisation's single sign-on "
    "(OIDC/SAML via the central identity provider), with roles: platform admin, security "
    "officer, finance viewer."
)
STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")

_CSRF_TOKEN = secrets.token_urlsafe(32)


@dataclass(frozen=True)
class Admin:
    """The person behind a request: a name for the audit trail and the roles they hold."""

    name: str
    roles: list = field(default_factory=list)

    def has(self, role: str) -> bool:
        return role in self.roles


def csrf_token() -> str:
    return _CSRF_TOKEN


def csrf_ok(sent: str | None) -> bool:
    return bool(sent) and hmac.compare_digest(sent, _CSRF_TOKEN)


def resolve_admin(request: Request) -> Admin:
    """Open access: always local-admin with every role. Production: the SSO identity (docs/ADMIN.md)."""
    return Admin(name=LOCAL_ADMIN, roles=list(ROLES))


def current_admin(request: Request) -> Admin:
    """FastAPI dependency for every admin and dashboard route; 403 on a change without CSRF."""
    if request.method in STATE_CHANGING and not csrf_ok(request.headers.get(CSRF_HEADER)):
        raise HTTPException(status_code=403, detail="Missing or wrong X-CTRL-AI-CSRF header")
    return resolve_admin(request)
