"""Append rows to the audit log: one compact JSON object per line."""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import UTC, datetime


def utc_now_iso() -> str:
    """Current UTC time with milliseconds, such as ``2026-10-03T19:40:12.345Z``."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Append-only JSON-lines file, safe for concurrent writers in one process."""

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()

    def write(self, row: dict) -> None:
        """Append one row. Never raises: a logging problem must not fail a request."""
        try:
            line = json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
            with self._lock:
                os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
                # Append only, never recreate: the file is made on the host first
                # so that it is not owned by the container's root user.
                with open(self._path, "a", encoding="utf-8") as handle:
                    handle.write(line)
        except Exception as exc:
            # The class name only; the message could carry row content.
            print(f"ctrl-ai: audit write failed ({type(exc).__name__})", file=sys.stderr)
