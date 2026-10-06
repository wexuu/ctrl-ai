"""Admin audit trail: one `admin` row per admin action, in the admin audit log
(``AdminSettings.admin_audit_log``, ``CTRL_AI_ADMIN_AUDIT_LOG``).

Never logs passwords, keys, tokens or file contents: only the fields below, each a short string.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime

from ctrl_ai.admin.audit_reader import parse_rows, tail_lines

_LOCK = threading.Lock()


def now_iso() -> str:
    """UTC timestamp with milliseconds and a Z, like the gateway's rows."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _short(value, limit: int = 300):
    if value is None:
        return None
    text = str(value)
    return text[:limit]


def write(
    path: str,
    action: str,
    *,
    actor: str | None,
    target: str | None = None,
    version_before: str | None = None,
    version_after: str | None = None,
    reason: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Append one admin row and return it. Failures to write are swallowed (never break the panel)."""
    row = {
        "type": "admin",
        "ts": now_iso(),
        "actor": _short(actor, 80),
        "action": action,
        "target": _short(target, 120),
        "version_before": version_before,
        "version_after": version_after,
        "reason": _short(reason),
    }
    if extra:
        # Only scalar, short values (filters, row counts); never content.
        row["details"] = {
            str(k)[:40]: _short(v, 200) if not isinstance(v, (int, float, bool)) else v
            for k, v in extra.items()
            if v is not None
        }
    line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
    try:
        with _LOCK, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass
    return row


def read(path: str, limit: int = 2000) -> list[dict]:
    """The newest `limit` admin rows, newest first."""
    rows = [r for r in parse_rows(tail_lines(path, limit)) if r.get("type") == "admin"]
    return list(reversed(rows))
