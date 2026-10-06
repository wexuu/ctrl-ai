"""Jev and the judge both down → circuits open → semantic-outage mode."""

from __future__ import annotations

import subprocess
import sys
import time

import yaml

from tests.e2e import harness as h

SCRIPT = h.REPO / "scripts" / "break-glass.py"
REGISTER = h.RUNTIME / "state" / "break_glass.json"
GITHUB_TOKEN = "ghp_" + "A1b2" * 9


def outage_policy(text: str, mode: str = "degrade") -> str:
    doc = yaml.safe_load(text)
    doc["semantic_outage"] = {
        "mode": mode,
        "strict_profiles_fail_closed": True,
        "circuit": {"failures_to_open": 2, "window_s": 60, "cooldown_s": 300},
        "max_manual_minutes": 120,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def script(*args: str) -> str:
    out = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--register",
            str(REGISTER),
            "--audit",
            str(h.AUDIT_FILE),
            "--policy",
            str(h.POLICY_FILE),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def incidents(offset: int) -> list[dict]:
    return [r for r in h.audit_rows_since(offset) if r.get("type") == "incident"]


def test_outage_degrade_fail_closed_and_manual_normal(set_policy, original_policy):
    start = h.audit_offset()
    set_policy(outage_policy(original_policy))
    try:
        for _ in range(2):
            assert (
                h.post_messages(h.messages_body(f"JEV-500-TEST JUDGE-DOWN-TEST {h.tag()}")).status_code == 200
            )
        events = [(r["event"], r["component"]) for r in incidents(start)]
        assert ("open", "jev") in events and ("open", "judge") in events

        offset = h.audit_offset()
        t0 = time.monotonic()
        resp = h.post_messages(h.messages_body(f"a normal question {h.tag()}"))
        elapsed = time.monotonic() - t0
        assert resp.status_code == 200 and elapsed < 1.0, f"{elapsed:.2f}s"
        row = h.decision_row(resp, offset)
        assert row["semantic"] == {"source": None, "score": None, "action": "flag", "reason": "outage"}
        assert row["jev"]["error"] == "circuit_open" and row["judge"]["error"] == "circuit_open"
        assert row["flagged"] is True and row["decision"] == "allow"
        assert h.jev_requests() == [] or all("JEV-500" not in str(r) for r in h.jev_requests())

        # Deterministic controls stay on during the outage.
        blocked = h.post_messages(h.messages_body(f"token {GITHUB_TOKEN} {h.tag()}"))
        assert blocked.status_code == 400 and h.block_info(blocked)[1] == "secret-github-token"
        assert [r["event"] for r in incidents(start)].count("outage_start") == 1

        set_policy(outage_policy(original_policy, mode="fail_closed"))
        refused = h.post_messages(h.messages_body(f"fail closed {h.tag()}"))
        assert refused.status_code == 503
        assert "semantic checks are unavailable" in h.block_info(refused)[0]
    finally:
        # Security on-call: the vendor reports recovery.
        script("outage", "--mode", "normal", "--minutes", "5", "--reason", "vendor recovered", "--by", "e2e")
        offset = h.audit_offset()
        resp = h.post_messages(h.messages_body(f"after recovery {h.tag()}"))
        script("outage", "--end", "--by", "e2e")
    assert resp.status_code == 200
    row = h.decision_row(resp, offset)
    assert row["semantic"]["source"] == "jev" and row["semantic"]["reason"] != "outage"
    events = [r["event"] for r in incidents(start)]
    assert "manual_on" in events and "manual_off" in events and "outage_end" in events
    assert events.count("close") == 2


def test_manual_degrade_switch(set_policy, original_policy):
    start = h.audit_offset()
    script(
        "outage",
        "--mode",
        "degrade",
        "--minutes",
        "10",
        "--reason",
        "Jev vendor incident",
        "--ticket",
        "INC-1240",
        "--by",
        "secops-e2e",
    )
    try:
        resp = h.post_messages(h.messages_body(f"during manual outage {h.tag()}"))
        assert resp.status_code == 200
        row = h.decision_row(resp, start)
        assert row["semantic"]["reason"] == "outage"
        assert h.jev_requests() == []
    finally:
        script("outage", "--end", "--by", "secops-e2e")
    resp = h.post_messages(h.messages_body(f"after manual outage {h.tag()}"))
    assert resp.status_code == 200
    manual = next(r for r in incidents(start) if r["event"] == "manual_on")
    assert (manual["ticket"], manual["by"], manual["mode"]) == ("INC-1240", "secops-e2e", "degrade")


def test_stub_jev_stopped_and_judge_failing(set_policy, original_policy):
    start = h.audit_offset()
    set_policy(outage_policy(original_policy))
    h.compose("stop", "stub-jev")
    try:
        for _ in range(2):
            assert h.post_messages(h.messages_body(f"JUDGE-DOWN-TEST {h.tag()}")).status_code == 200
        offset = h.audit_offset()
        t0 = time.monotonic()
        resp = h.post_messages(h.messages_body(f"while jev is gone {h.tag()}"))
        assert resp.status_code == 200 and time.monotonic() - t0 < 1.0
        assert h.decision_row(resp, offset)["semantic"]["reason"] == "outage"
        assert [r["event"] for r in incidents(start)].count("outage_start") == 1
    finally:
        h.compose("start", "stub-jev")
        time.sleep(2)
        script("outage", "--mode", "normal", "--minutes", "5", "--reason", "jev back", "--by", "e2e")
        h.post_messages(h.messages_body(f"after jev back {h.tag()}"))
        script("outage", "--end", "--by", "e2e")
