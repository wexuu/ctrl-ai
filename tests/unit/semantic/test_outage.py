"""Circuit breaker state machine, outage decisions per mode and profile, manual switch expiry."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.policy import parse_policy
from ctrl_ai.pipeline import evaluator
from ctrl_ai.semantic.circuit import Breaker
from ctrl_ai.semantic.outage import OutageMonitor

REPO = Path(__file__).resolve().parents[3]
POLICY = parse_policy((REPO / "tests" / "fixtures" / "config" / "policy.yaml").read_bytes())
SETTINGS = {**POLICY.semantic_outage, "circuit": {"failures_to_open": 2, "window_s": 60, "cooldown_s": 30}}


def test_breaker_opens_probes_and_closes():
    now = [0.0]
    b = Breaker("jev", failures_to_open=3, window_s=60, cooldown_s=30, clock=lambda: now[0])
    assert b.record(False) is None and b.record(False) is None
    assert b.record(False) == "open" and not b.allow()
    now[0] = 31
    assert b.allow() is True and b.allow() is False  # exactly one probe
    assert b.record(False) is None and b.state == "open"  # failed probe re-opens
    now[0] = 62
    assert b.allow() is True
    assert b.record(True) == "close" and b.allow()


def test_failures_outside_the_window_do_not_count():
    now = [0.0]
    b = Breaker("judge", failures_to_open=2, window_s=10, cooldown_s=5, clock=lambda: now[0])
    b.record(False)
    now[0] = 20
    assert b.record(False) is None and b.state == "closed"


class Register:
    def __init__(self, doc):
        self.doc = doc

    def current(self):
        return self.doc


def monitor(doc=None, now=None):
    rows = []
    m = OutageMonitor(
        write=rows.append,
        register=Register(doc or {"overrides": []}),
        clock=lambda: now or datetime(2026, 10, 4, 8, 0, tzinfo=UTC),
    )
    return m, rows


def open_both(m):
    for comp in ("jev", "judge"):
        m.configure(SETTINGS)
        m.record(comp, False, "timeout")
        m.record(comp, False, "timeout")


def test_outage_when_both_circuits_open_with_incidents_once():
    m, rows = monitor()
    assert m.status(SETTINGS)["outage"] is False
    open_both(m)
    assert m.status(SETTINGS) == {"outage": True, "mode": "degrade", "source": "circuit"}
    m.status(SETTINGS)
    assert [r["event"] for r in rows] == ["open", "open", "outage_start"]
    assert rows[0]["reason"].startswith("2 failures in 60s")


def test_manual_switch_and_expiry():
    now = datetime(2026, 10, 4, 8, 0, tzinfo=UTC)
    entry = {
        "active": True,
        "mode": "fail_closed",
        "reason": "x",
        "issued_by": "a",
        "issued_at": "2026-10-04T07:55:00Z",
        "expires_at": "2026-10-04T08:05:00Z",
    }
    m, rows = monitor({"overrides": [], "semantic_outage": entry}, now)
    assert m.status(SETTINGS) == {"outage": True, "mode": "fail_closed", "source": "manual"}
    m._now = lambda: now + timedelta(minutes=10)
    assert m.status(SETTINGS)["outage"] is False
    assert [r["event"] for r in rows] == ["outage_start", "manual_off", "outage_end"]


def test_manual_normal_closes_the_circuits():
    m, _rows = monitor()
    open_both(m)
    m._register = Register(
        {
            "overrides": [],
            "semantic_outage": {
                "active": True,
                "mode": "normal",
                "reason": "recovered",
                "issued_by": "a",
                "issued_at": "2026-10-04T07:59:00Z",
                "expires_at": "2026-10-04T09:00:00Z",
            },
        }
    )
    assert m.status(SETTINGS)["outage"] is False
    assert not any(b.is_open for b in m.breakers.values())


def decide(profile, mode):
    m, _ = monitor()
    open_both(m)
    policy = parse_policy((REPO / "tests" / "fixtures" / "config" / "policy.yaml").read_bytes())
    policy.semantic_outage.update({"mode": mode, "circuit": SETTINGS["circuit"]})
    ctx = RequestContext(profile=policy.profile(profile), mode="enforce")
    evaluator.apply_outage(ctx, policy, m.status(policy.semantic_outage), "judge-model")
    return ctx


def test_degrade_allows_and_flags():
    ctx = decide("balanced", "degrade")
    assert ctx.decision == "allow" and ctx.flagged
    assert ctx.semantic == {"source": None, "score": None, "action": "flag", "reason": "outage"}
    assert ctx.jev and ctx.judge
    assert ctx.jev.error == "circuit_open" and ctx.judge.error == "circuit_open"
    assert ctx.judge.model == "judge-model"


def test_fail_closed_refuses_with_503():
    ctx = decide("balanced", "fail_closed")
    assert (ctx.decision, ctx.status_code) == ("block", 503)
    assert "semantic checks are unavailable" in ctx.message


def test_strict_profiles_fail_closed_only_when_their_profile_blocks():
    from ctrl_ai.core.context import Profile

    m, _ = monitor()
    open_both(m)
    ctx = RequestContext(profile=Profile("locked", "enforce", "block", "block"), mode="enforce")
    evaluator.apply_outage(ctx, POLICY, m.status(POLICY.semantic_outage), "judge-model")
    assert ctx.status_code == 503
    # Merge: the committed strict profile now fails closed (on_semantic_unavailable: block, user
    # decision on per-team scenarios), so it keeps refusing in degrade; balanced does not.
    assert decide("strict", "degrade").decision == "block"
    assert decide("balanced", "degrade").decision == "allow"


def test_script_refuses_too_long_manual_switch(tmp_path):
    import subprocess
    import sys

    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "break-glass.py"),
            "--register",
            str(tmp_path / "r.json"),
            "--audit",
            str(tmp_path / "a.jsonl"),
            "outage",
            "--mode",
            "degrade",
            "--minutes",
            "999",
            "--reason",
            "too long",
            "--by",
            "x",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 2 and "at most 120 minutes" in out.stderr
    assert not (tmp_path / "r.json").exists()
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "break-glass.py"),
            "--register",
            str(tmp_path / "r.json"),
            "--audit",
            str(tmp_path / "a.jsonl"),
            "outage",
            "--mode",
            "degrade",
            "--minutes",
            "30",
            "--reason",
            "vendor down",
            "--by",
            "x",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0
    doc = json.loads((tmp_path / "r.json").read_text())
    assert doc["semantic_outage"]["mode"] == "degrade" and doc["semantic_outage"]["active"] is True
