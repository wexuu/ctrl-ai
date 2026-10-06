"""Test helper: gateway keys without the admin panel.

Writes schema-valid records to tests/e2e/runtime/state/keys.json, which the test stack's
gateway reads (CTRL_AI_KEYS_FILE=/app/runtime/state/keys.json) and reloads on change.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import UTC, datetime

from tests.e2e import harness as h

KEYS_FILE = h.RUNTIME / "state" / "keys.json"


def _load() -> dict:
    try:
        return json.loads(KEYS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return {"keys": []}


def _save(doc: dict) -> None:
    before = KEYS_FILE.stat().st_mtime if KEYS_FILE.exists() else 0.0
    with KEYS_FILE.open("w", encoding="utf-8") as f:  # in place: keep the host-owned inode
        json.dump(doc, f, indent=2)
    mtime = max(time.time(), before + 2.0)
    os.utime(KEYS_FILE, (mtime, mtime))


def issue_test_key(team: str, user: str = "e2e-user", expires: str | None = None) -> tuple[str, str]:
    """Create a key for `team`; return (raw key, key id). Only the hash is written."""
    key = "sk-ctrl-ai-" + secrets.token_hex(16)
    key_id = "k_" + secrets.token_hex(4)
    doc = _load()
    doc["keys"].append(
        {
            "id": key_id,
            "hash": hashlib.sha256(key.encode()).hexdigest(),
            "prefix": key[:12],
            "team": team,
            "user": user,
            "label": "e2e",
            "created": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires": expires,
            "revoked": False,
        }
    )
    _save(doc)
    return key, key_id


def revoke_test_key(key_id: str) -> None:
    doc = _load()
    for record in doc["keys"]:
        if record["id"] == key_id:
            record["revoked"] = True
    _save(doc)


def key_headers(key: str) -> dict:
    return h.bearer_headers(key)
