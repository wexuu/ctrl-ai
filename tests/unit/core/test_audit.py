from __future__ import annotations

import json
import re
import threading

from ctrl_ai.core.audit import AuditLog, utc_now_iso


def test_utc_now_iso_format():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", utc_now_iso())


def test_rows_are_appended_as_compact_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"existing":true}\n', encoding="utf-8")
    log = AuditLog(str(path))
    log.write({"type": "decision", "rule": None, "name": "zażółć"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"existing":true}', '{"type":"decision","rule":null,"name":"zażółć"}']


def test_parent_folder_is_created(tmp_path):
    path = tmp_path / "logs" / "nested" / "audit.jsonl"
    AuditLog(str(path)).write({"n": 1})
    assert json.loads(path.read_text(encoding="utf-8")) == {"n": 1}


def test_concurrent_writes_do_not_interleave(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    writers, rows_each = 8, 200

    def work(writer: int) -> None:
        for n in range(rows_each):
            log.write({"writer": writer, "n": n, "padding": "x" * 500})

    threads = [threading.Thread(target=work, args=(i,)) for i in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == writers * rows_each
    assert {(row["writer"], row["n"]) for row in rows} == {
        (w, n) for w in range(writers) for n in range(rows_each)
    }


def test_write_never_raises_and_reports_no_content(tmp_path, capsys):
    blocker = tmp_path / "a-file"
    blocker.write_text("", encoding="utf-8")
    AuditLog(str(blocker / "audit.jsonl")).write({"secret": "ROW-CONTENT"})  # parent is a file
    AuditLog(str(tmp_path / "audit.jsonl")).write({"secret": object()})  # not serialisable
    err = capsys.readouterr().err
    assert err.count("audit write failed") == 2
    assert "ROW-CONTENT" not in err
    assert not (tmp_path / "audit.jsonl").exists()
