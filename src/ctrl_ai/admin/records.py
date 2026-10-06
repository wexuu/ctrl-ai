"""The audit log, read once and joined: one record per model request.

The dashboard, the audit page and the admin log page all read through here. The log is
append-only and written by another process: ``LogReader`` reads only the bytes added since the
last read, skips a line that is still being written, starts again when the file is replaced or
shrinks, and keeps the newest ``MAX_ROWS`` rows. Decision and usage rows are joined by request id;
version-1 and version-2 rows are both accepted, and missing identity becomes "unattributed".
"""

from __future__ import annotations

import json
import os
import threading
from collections import deque
from collections.abc import Callable, Iterable
from typing import Any

MAX_ROWS = 500_000
UNATTRIBUTED = "unattributed"
REQUEST_ROW_TYPES = ("decision", "usage")
EXPORT_FIELDS = (
    "request_id",
    "ts",
    "team",
    "department",
    "user",
    "key_id",
    "profile",
    "endpoint",
    "model_requested",
    "model_routed",
    "provider",
    "decision",
    "rule",
    "mode",
    "would_block",
    "flagged",
    "route_reason",
    "data_class_detected",
    "findings",
    "masked",
    "semantic_source",
    "semantic_score",
    "semantic_action",
    "semantic_reason",
    "jev_status",
    "jev_score",
    "judge_status",
    "judge_score",
    "judge_category",
    "break_glass_id",
    "status",
    "error",
    "input_tokens",
    "output_tokens",
    "cost_usd",
    "cost_source",
    "shadow",
    "fallback_used",
    "guard_ms",
    "total_ms",
    "policy_version",
)


# ---------------------------------------------------------------- reading


class LogReader:
    """Incremental reader of an append-only JSON-lines file; keeps the newest MAX_ROWS rows."""

    def __init__(self, path: str, max_rows: int = MAX_ROWS):
        self.path = path
        self.rows: deque = deque(maxlen=max_rows)
        self.offset = 0
        self.inode = None
        self.version = 0  # bumps whenever rows change
        self.lock = threading.Lock()

    def refresh(self) -> bool:
        """Read new complete lines; True when rows changed. A replaced or shrunk file is re-read."""
        with self.lock:
            try:
                st = os.stat(self.path)
            except OSError:
                if self.rows:
                    self.rows.clear()
                    self.offset, self.inode = 0, None
                    self.version += 1
                    return True
                return False
            if self.inode != st.st_ino or st.st_size < self.offset:
                self.rows.clear()
                self.offset, self.inode = 0, st.st_ino
                self.version += 1
            if st.st_size == self.offset:
                return False
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read(st.st_size - self.offset)
            end = data.rfind(b"\n")
            if end < 0:
                return False  # only a line still being written
            for raw in data[:end].split(b"\n"):
                line = raw.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    self.rows.append(row)
            self.offset += end + 1
            self.version += 1
            return True


# Readers and derived views, per file path: the files are shared by every request of the app.
_READERS: dict[str, LogReader] = {}
_VIEWS: dict[tuple[str, str], tuple[tuple, Any]] = {}
_LOCK = threading.Lock()


def _reader(path: str) -> LogReader:
    with _LOCK:
        if path not in _READERS:
            _READERS[path] = LogReader(path)
        reader = _READERS[path]
    reader.refresh()
    return reader


def _view(path: str, name: str, build: Callable[[list[dict]], Any]) -> Any:
    """``build`` over the file's rows, recomputed only when the file changed."""
    reader = _reader(path)
    key = (reader.inode, reader.version)
    cached = _VIEWS.get((path, name))
    if cached and cached[0] == key:
        return cached[1]
    value = build(list(reader.rows))
    _VIEWS[(path, name)] = (key, value)
    return value


def read_rows(path: str) -> list[dict]:
    """Every kept row of the file, oldest first."""
    return list(_reader(path).rows)


# ---------------------------------------------------------------- joining


def group_by_request(rows: Iterable[dict]) -> list[tuple[str | None, list[dict]]]:
    """Decision and usage rows grouped by request id, in the order of each request's first row.
    A row without a request id is a request of its own (id None)."""
    groups: dict[str, list[dict]] = {}
    order: list[tuple[str, str | None]] = []
    for index, row in enumerate(rows):
        if row.get("type") not in REQUEST_ROW_TYPES:
            continue
        rid = row.get("request_id")
        key = rid if isinstance(rid, str) and rid else f"#row{index}"
        if key not in groups:
            groups[key] = []
            order.append((key, rid if key == rid else None))
        groups[key].append(row)
    return [(rid, groups[key]) for key, rid in order]


def num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def day_of(ts) -> str | None:
    return ts[:10] if isinstance(ts, str) and len(ts) >= 10 else None


def build_record(rid: str | None, rows: list[dict]) -> dict:
    """One normalised record per request from its decision and usage rows (v1 or v2)."""
    decisions = [r for r in rows if r.get("type") == "decision"]
    usages = [r for r in rows if r.get("type") == "usage"]
    d = decisions[-1] if decisions else {}
    first = decisions[0] if decisions else {}
    # A provider fallback gives two usage rows under one request id: a failure with 0 tokens,
    # then the success from the fallback model. The success row is the one that counts.
    successes = [r for r in usages if r.get("status") == "success"]
    u = successes[-1] if successes else (usages[-1] if usages else {})
    ts = first.get("ts") or u.get("ts")
    pick = lambda k: d.get(k) if d.get(k) is not None else u.get(k)  # noqa: E731
    cost = num(u.get("cost_usd"))
    cost_source = u.get("cost_source") or ("litellm" if cost is not None else "unknown")
    semantic = d.get("semantic") if isinstance(d.get("semantic"), dict) else None
    jev = d.get("jev")
    jev = jev if isinstance(jev, dict) else {}
    judge = d.get("judge") if isinstance(d.get("judge"), dict) else None
    if semantic is None and jev:
        # v1: Jev only observed; its attack score is the semantic score.
        semantic = {
            "source": "jev" if jev.get("status") == "ok" else None,
            "score": num(jev.get("attack")),
            "action": "observe",
            "reason": None,
        }
    semantic = semantic or {}
    model_requested = d.get("model_requested") or u.get("model_requested") or d.get("model") or u.get("model")
    model_routed = u.get("model_routed") or d.get("model_routed") or u.get("model") or d.get("model")
    if u.get("fallback_used") and u.get("model"):
        # After a fallback, A's usage row keeps the gateway's target in model_routed and the model
        # that actually served (and was priced) in model; spend belongs to the serving model.
        model_routed = u["model"]
    findings = d.get("findings") if isinstance(d.get("findings"), list) else []
    if not findings and d.get("rule") and d.get("v") is None:
        findings = [
            {"rule": d.get("rule"), "pack": "custom", "source": "prompt", "action": "block", "severity": None}
        ]
    masked = d.get("masked")
    masked = masked if isinstance(masked, dict) else {}
    bg = d.get("break_glass") if isinstance(d.get("break_glass"), dict) else None
    error = u.get("error") or d.get("error")
    return {
        "request_id": rid,
        "ts": ts,
        "day": day_of(ts),
        "v": d.get("v") or u.get("v") or 1,
        "endpoint": pick("endpoint"),
        "team": pick("team") or UNATTRIBUTED,
        "department": pick("department") or UNATTRIBUTED,
        "user": pick("user"),
        "key_id": pick("key_id"),
        "profile": d.get("profile"),
        "model_requested": model_requested,
        "model_routed": model_routed,
        "provider": u.get("provider"),
        "decision": d.get("decision") or ("allow" if u else None),
        "rule": d.get("rule"),
        "mode": d.get("mode"),
        "would_block": d.get("would_block"),
        "flagged": bool(d.get("flagged")),
        "route_reason": d.get("route_reason"),
        "data_class_detected": d.get("data_class_detected"),
        "findings": findings,
        "masked": {k: v for k, v in masked.items() if num(v)},
        "normalisation": d.get("normalisation") if isinstance(d.get("normalisation"), dict) else None,
        "semantic_source": semantic.get("source"),
        "semantic_score": num(semantic.get("score")),
        "semantic_action": semantic.get("action"),
        "semantic_reason": semantic.get("reason"),
        "jev_status": jev.get("status"),
        "jev_latency_ms": num(jev.get("latency_ms")),
        "jev_score": num(jev.get("attack")),
        "judge_status": judge.get("status") if judge else None,
        "judge_score": num(judge.get("score")) if judge else None,
        "judge_category": judge.get("category") if judge else None,
        "judge_latency_ms": num(judge.get("latency_ms")) if judge else None,
        "loop": d.get("loop"),
        "budget": d.get("budget"),
        "break_glass_id": bg.get("id") if bg else None,
        "break_glass_relaxed": bg.get("relaxed") if bg else None,
        "status": u.get("status"),
        "error": error if isinstance(error, str) else None,
        "input_tokens": num(u.get("input_tokens")) or 0,
        "output_tokens": num(u.get("output_tokens")) or 0,
        "cost_usd": cost,
        "cost_source": cost_source,
        "shadow": bool(u.get("shadow")),
        "price_known": u.get("price_known") if u.get("price_known") is not None else cost is not None,
        "fallback_used": bool(u.get("fallback_used")),
        "guard_ms": num(d.get("guard_ms")),
        "total_ms": num(u.get("total_ms")),
        "policy_version": d.get("policy_version"),
        "has_usage": bool(usages),
    }


def build_dataset(rows: Iterable[dict]) -> dict:
    """Records (oldest first) and the rows that are not about one request, by type."""
    rows = list(rows)
    by_type: dict[str, list[dict]] = {"tool": [], "break_glass": [], "incident": [], "shadow": []}
    for row in rows:
        if row.get("type") in by_type:
            by_type[row["type"]].append(row)
    records = [build_record(rid, group) for rid, group in group_by_request(rows)]
    records.sort(key=lambda r: r["ts"] or "")
    for kind in ("incident", "shadow"):
        by_type[kind].sort(key=lambda r: r.get("ts") or "")
    return {
        "records": records,
        "tools": by_type["tool"],
        "break_glass": by_type["break_glass"],
        "incidents": by_type["incident"],
        "shadows": by_type["shadow"],
    }


def dataset(path: str) -> dict:
    """Joined records, tool rows and break-glass rows; cached until the file changes."""
    return _view(path, "dataset", build_dataset)


def last_used_by_key(path: str) -> dict:
    out = {}
    for r in dataset(path)["records"]:
        if r["key_id"] and r["ts"]:
            out[r["key_id"]] = max(out.get(r["key_id"], ""), r["ts"])
    return out


def export_row(r: dict) -> dict:
    """The exported fields only: decision and usage fields, identity, findings, masked counts."""
    return {k: r.get(k) for k in EXPORT_FIELDS}


def export_csv_value(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    return str(v)


# ---------------------------------------------------------------- the audit page


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def audit_entry(request_id: str | None, rows: list[dict]) -> dict:
    """What the audit page shows for one request: the decision and usage fields as logged."""
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


def _audit_entries(rows: list[dict]) -> list[dict]:
    return [audit_entry(rid, group) for rid, group in reversed(group_by_request(rows))]


def audit_entries(path: str, limit: int = 200, request_id: str | None = None) -> list[dict]:
    """The newest ``limit`` requests, newest first (optionally only one request id)."""
    limit = max(1, min(int(limit), 5000))
    entries = _view(path, "audit", _audit_entries)
    if request_id:
        entries = [e for e in entries if e["request_id"] == request_id]
    return entries[:limit]
