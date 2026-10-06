"""Unit tests for admin/audit_reader.py: tail reading, row parsing and joining by request_id."""

from __future__ import annotations

import json

from ctrl_ai.admin import audit_reader


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
    [rec] = audit_reader.read_records(str(f))
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
    [rec] = audit_reader.read_records(str(f))
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
    [rec] = audit_reader.read_records(str(f))
    assert rec["decision_count"] == 2
    assert len(rec["rows"]["decisions"]) == 2
    assert rec["decision"] == "block" and rec["rule"] == "test-marker"
    assert rec["error"] == "HTTPException:400"


def test_newest_first_and_limit(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a"), _usage("a"), _decision("b"), _decision("c"), _usage("b")])
    recs = audit_reader.read_records(str(f))
    assert [r["request_id"] for r in recs] == ["c", "b", "a"]
    assert [r["request_id"] for r in audit_reader.read_records(str(f), limit=2)] == ["c", "b"]
    assert [r["request_id"] for r in audit_reader.read_records(str(f), request_id="b")] == ["b"]


def test_truncated_last_line_and_junk(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision("a")], tail='not json\n{"type":"usage","request_id":"a","sta')
    recs = audit_reader.read_records(str(f))
    assert [r["request_id"] for r in recs] == ["a"]
    assert recs[0]["has_usage"] is False


def test_row_without_request_id_is_its_own_record(tmp_path):
    f = tmp_path / "audit.jsonl"
    _write(f, [_decision(None), _decision(None)])
    assert len(audit_reader.read_records(str(f))) == 2


def test_missing_file(tmp_path):
    assert audit_reader.read_records(str(tmp_path / "nope.jsonl")) == []
    assert audit_reader.tail_lines(str(tmp_path / "nope.jsonl"), 10) == []


def test_empty_file(tmp_path):
    f = tmp_path / "audit.jsonl"
    f.write_text("")
    assert audit_reader.read_records(str(f)) == []


def test_tail_of_large_file(tmp_path, monkeypatch):
    f = tmp_path / "audit.jsonl"
    n = 20000
    with f.open("w", encoding="utf-8") as h:
        for i in range(n):
            h.write(json.dumps(_decision(f"id-{i:05d}")) + "\n")
    assert f.stat().st_size > 5 * audit_reader.BLOCK_SIZE

    reads = []
    real_open = open

    def counting_open(*args, **kwargs):
        handle = real_open(*args, **kwargs)
        real_read = handle.read

        def read(size=-1):
            data = real_read(size)
            reads.append(len(data))
            return data

        handle.read = read
        return handle

    monkeypatch.setattr("builtins.open", counting_open)
    lines = audit_reader.tail_lines(str(f), 50)
    monkeypatch.undo()
    assert len(lines) == 50
    assert json.loads(lines[-1])["request_id"] == f"id-{n - 1:05d}"
    assert json.loads(lines[0])["request_id"] == f"id-{n - 50:05d}"
    assert sum(reads) < f.stat().st_size / 10  # only the tail was read

    recs = audit_reader.read_records(str(f), limit=10)
    assert [r["request_id"] for r in recs] == [f"id-{i:05d}" for i in range(n - 1, n - 11, -1)]


def test_tail_lines_exact_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_reader, "BLOCK_SIZE", 7)
    f = tmp_path / "audit.jsonl"
    lines = [f"line-{i}" for i in range(30)]
    f.write_text("\n".join(lines) + "\n")
    for k in (1, 2, 5, 29, 30, 40):
        assert audit_reader.tail_lines(str(f), k) == lines[-k:]


def test_rows_that_are_not_requests_are_left_out():
    """Incident, break_glass, admin and tool rows have no model request: no empty records."""
    from ctrl_ai.admin import audit_reader as ar

    rows = [
        {"type": "incident", "event": "outage_start"},
        {"type": "break_glass", "event": "issue"},
        {"type": "admin", "action": "config.save"},
        {"type": "tool", "request_id": "t1"},
        {"type": "decision", "request_id": "r1", "decision": "allow"},
    ]
    assert [r["request_id"] for r in ar.join_rows(rows)] == ["r1"]
