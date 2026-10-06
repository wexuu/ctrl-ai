"""The audit page's entries from admin/records.py: reading the log and joining rows by request_id."""

from __future__ import annotations

import json

from ctrl_ai.admin import records


def _decision(rid, ts="2026-10-03T19:40:12.345Z", **kw):
    row = {
        "type": "decision",
        "ts": ts,
        "request_id": rid,
        "endpoint": "chat_completions",
        "model": "chat-groq",
        "stream": False,
        "mode": "enforce",
        "decision": "allow",
        "would_block": False,
        "rule": None,
        "policy_version": "a1b2c3d4",
        "text_chars": 10,
        "jev": {
            "status": "ok",
            "attack": 0.12,
            "answers": {"instruction_override": 0.12},
            "latency_ms": 140.0,
        },
        "guard_ms": 150.2,
    }
    row.update(kw)
    return row


def _usage(rid, ts="2026-10-03T19:40:13.101Z", **kw):
    row = {
        "type": "usage",
        "ts": ts,
        "request_id": rid,
        "endpoint": "chat_completions",
        "model": "chat-groq",
        "stream": False,
        "status": "success",
        "input_tokens": 25,
        "output_tokens": 12,
        "cost_usd": 0.00034,
        "total_ms": 812.4,
        "error": None,
    }
    row.update(kw)
    return row


def _write(path, rows, tail=""):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows) + tail, encoding="utf-8")


def test_join_decision_and_usage(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a"), _usage("a")])
    [rec] = records.audit_entries(str(f))
    assert rec["request_id"] == "a"
    assert rec["decision"] == "allow"
    assert rec["jev"]["attack"] == 0.12
    assert rec["guard_ms"] == 150.2
    assert rec["status"] == "success"
    assert (rec["input_tokens"], rec["output_tokens"]) == (25, 12)
    assert rec["cost_usd"] == 0.00034
    assert rec["total_ms"] == 812.4
    assert rec["time"] == "2026-10-03T19:40:12.345Z"
    assert rec["has_usage"] is True
    assert rec["decision_count"] == 1


def test_decision_only(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a")])
    [rec] = records.audit_entries(str(f))
    assert rec["has_usage"] is False
    assert rec["status"] is None and rec["input_tokens"] is None and rec["cost_usd"] is None


def test_two_decisions_for_one_id(tmp_path):
    f = tmp_path / "audit.jsonl"
    blocked = dict(
        decision="block", would_block=True, rule="test-marker", jev={"status": "skipped", "attack": None}
    )
    _write(
        f,
        [
            _decision("a", **blocked),
            _usage("a", status="failure", input_tokens=0, output_tokens=0, error="HTTPException:400"),
            _decision("a", ts="2026-10-03T19:40:14.000Z", **blocked),
        ],
    )
    [rec] = records.audit_entries(str(f))
    assert rec["decision_count"] == 2
    assert len(rec["rows"]["decisions"]) == 2
    assert rec["decision"] == "block" and rec["rule"] == "test-marker"
    assert rec["error"] == "HTTPException:400"


def test_newest_first_and_limit(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a"), _usage("a"), _decision("b"), _decision("c"), _usage("b")])
    recs = records.audit_entries(str(f))
    assert [r["request_id"] for r in recs] == ["c", "b", "a"]
    assert [r["request_id"] for r in records.audit_entries(str(f), limit=2)] == ["c", "b"]
    assert [r["request_id"] for r in records.audit_entries(str(f), request_id="b")] == ["b"]


def test_truncated_last_line_and_junk(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a")], tail='not json\n{"type":"usage","request_id":"a","sta')
    recs = records.audit_entries(str(f))
    assert [r["request_id"] for r in recs] == ["a"]
    assert recs[0]["has_usage"] is False


def test_row_without_request_id_is_its_own_record(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision(None), _decision(None)])
    assert len(records.audit_entries(str(f))) == 2


def test_missing_file(tmp_path):
    assert records.audit_entries(str(tmp_path / "nope.jsonl")) == []
    assert records.read_rows(str(tmp_path / "nope.jsonl")) == []


def test_empty_file(tmp_path):
    f = tmp_path / "audit.jsonl"
    f.write_text("")
    assert records.audit_entries(str(f)) == []


def test_appended_rows_are_read_incrementally(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a")])
    assert [r["request_id"] for r in records.audit_entries(str(f))] == ["a"]
    with f.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_usage("a")) + "\n" + json.dumps(_decision("b")) + "\n")
    entries = records.audit_entries(str(f))
    assert [r["request_id"] for r in entries] == ["b", "a"] and entries[1]["has_usage"] is True


def test_newest_entries_of_a_large_file(tmp_path):
    f = tmp_path / "audit.jsonl"
    n = 20000
    with f.open("w", encoding="utf-8") as h:
        for i in range(n):
            h.write(json.dumps(_decision(f"id-{i:05d}")) + "\n")
    recs = records.audit_entries(str(f), limit=10)
    assert [r["request_id"] for r in recs] == [f"id-{i:05d}" for i in range(n - 1, n - 11, -1)]


def test_rows_that_are_not_requests_are_left_out():
    """Incident, break_glass, admin and tool rows have no model request: no empty records."""
    rows = [
        {"type": "incident", "event": "outage_start"},
        {"type": "break_glass", "event": "issue"},
        {"type": "admin", "action": "config.save"},
        {"type": "tool", "request_id": "t1"},
        {"type": "decision", "request_id": "r1", "decision": "allow"},
    ]
    assert [rid for rid, _ in records.group_by_request(rows)] == ["r1"]
