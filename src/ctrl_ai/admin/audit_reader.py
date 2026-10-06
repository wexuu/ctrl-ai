"""Read the tail of the audit log and join its rows into one record per request.

Pure Python, no FastAPI, so it can be tested on the host. The file is written by a root
process in another container: it is opened read-only, never locked, and its last line may
still be half written.
"""

from __future__ import annotations

import json
import os
from typing import Any

BLOCK_SIZE = 64 * 1024
# A request has at most a few rows (two decisions and a usage row), so this many rows per
# requested record is enough to fill `limit` records from the tail.
ROWS_PER_RECORD = 4


def tail_lines(path: str, max_lines: int) -> list[str]:
    """The last `max_lines` complete lines of the file, oldest first.

    Reads backwards in blocks, so a large file is never loaded whole. A last line without a
    trailing newline is still being written and is left out. A missing file gives [].
    """
    if max_lines <= 0:
        return []
    try:
        handle = open(path, "rb")  # noqa: SIM115 - entered as a context manager below
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []
    with handle:
        handle.seek(0, os.SEEK_END)
        pos = handle.tell()
        data = b""
        while pos > 0 and data.count(b"\n") <= max_lines:
            step = min(BLOCK_SIZE, pos)
            pos -= step
            handle.seek(pos)
            data = handle.read(step) + data
    if not data:
        return []
    parts = data.split(b"\n")
    parts.pop()  # after the final newline: empty, or a line still being written
    if pos > 0 and parts:
        parts.pop(0)  # cut off at the block boundary
    lines = [p.decode("utf-8", "replace") for p in parts if p.strip()]
    return lines[-max_lines:]


def parse_rows(lines: list[str]) -> list[dict]:
    """The lines that are JSON objects; anything else is skipped."""
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def build_record(request_id: str | None, rows: list[dict]) -> dict:
    """One record from the rows of one request, in file order."""
    decisions = [r for r in rows if r.get("type") == "decision"]
    usages = [r for r in rows if r.get("type") == "usage"]
    decision = decisions[0] if decisions else {}
    usage = usages[-1] if usages else {}
    first = rows[0] if rows else {}
    # Claude Code retries a blocked request with the same id; the last decision is the newest.
    latest = decisions[-1] if decisions else {}
    return {
        "request_id": request_id,
        "time": _first(decision.get("ts"), first.get("ts")),
        "endpoint": _first(decision.get("endpoint"), usage.get("endpoint")),
        "model": _first(decision.get("model"), usage.get("model")),
        "team": _first(decision.get("team"), usage.get("team")),
        "key_id": decision.get("key_id"),
        "user": decision.get("user"),
        "decision": latest.get("decision"),
        "rule": latest.get("rule"),
        "mode": latest.get("mode"),
        "would_block": latest.get("would_block"),
        "policy_version": latest.get("policy_version"),
        "jev": decision.get("jev"),
        "judge": decision.get("judge"),
        "semantic": decision.get("semantic"),
        "guard_ms": decision.get("guard_ms"),
        "status": usage.get("status"),
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "cost_usd": usage.get("cost_usd"),
        "total_ms": usage.get("total_ms"),
        "error": _first(usage.get("error"), decision.get("error")),
        "decision_count": len(decisions),
        "has_usage": bool(usages),
        "rows": {"decisions": decisions, "usage": usages[-1] if usages else None},
    }


NON_REQUEST_TYPES = ("incident", "break_glass", "admin", "tool", "shadow")


def join_rows(rows: list[dict]) -> list[dict]:
    """Group rows by request_id, newest request first (by the position of its first row)."""
    groups: dict[str, list[dict]] = {}
    order: list[tuple[str, str | None]] = []
    for index, row in enumerate(rows):
        if row.get("type") in NON_REQUEST_TYPES:
            continue  # rows that are not about one model request (shown on the dashboard)
        rid = row.get("request_id")
        key = rid if isinstance(rid, str) and rid else f"#row{index}"
        if key not in groups:
            groups[key] = []
            order.append((key, rid if key == rid else None))
        groups[key].append(row)
    return [build_record(rid, groups[key]) for key, rid in reversed(order)]


def read_records(path: str, limit: int = 200, request_id: str | None = None) -> list[dict]:
    """The newest `limit` joined records from the audit log (optionally only one request id)."""
    limit = max(1, min(int(limit), 5000))
    records = join_rows(parse_rows(tail_lines(path, limit * ROWS_PER_RECORD + 8)))
    if request_id:
        records = [r for r in records if r["request_id"] == request_id]
    return records[:limit]
