"""Token round trip, tampering, expiry, subject, revocation, never-relax, script validation."""

from __future__ import annotations

from ctrl_ai.governance import breakglass as bg

SECRET = "s3cret"
RECORD = {
    "id": "bg_1a2b3c4d",
    "subject": "team:payments-dev",
    "relax": ["semantic", "secret-aws-key"],
    "reason": "fix",
    "issued_by": "alice",
    "issued_at": "2026-10-04T08:00:00Z",
    "expires_at": "2026-10-04T08:30:00Z",
    "revoked": False,
}
NOW = 1791100000 - 10**6  # any time before expiry; computed below
EXP = bg._ts(RECORD["expires_at"])
NEVER = ["secret-aws-key", "secret-private-key", "secret-github-token", "model-banned"]


def check(token, record=RECORD, team="payments-dev", now=EXP - 60):
    return bg.check(token, SECRET, {"overrides": [record]}, team, None, NEVER, now)


def test_round_trip_and_never_relax_removed():
    _record, field, event = check(bg.make_token(RECORD, SECRET))
    assert field == {"id": "bg_1a2b3c4d", "relaxed": ["semantic"]} and event == "use"


def test_tampered_token():
    token = bg.make_token(RECORD, SECRET)
    body, sig = token.split(".")
    assert check(body + "." + "0" * len(sig))[1] == {"id": None, "error": "bad_signature"}
    assert check(bg.make_token(RECORD, "other"))[1]["error"] == "bad_signature"
    assert check("garbage")[1]["error"] == "malformed"


def test_expired_wrong_subject_revoked_unknown():
    token = bg.make_token(RECORD, SECRET)
    assert check(token, now=EXP + 1)[1:] == ({"id": "bg_1a2b3c4d", "error": "expired"}, "expire")
    assert check(token, team="retail-dev")[1]["error"] == "wrong_subject"
    assert check(token, record={**RECORD, "revoked": True})[1]["error"] == "revoked"
    assert check(token, record={**RECORD, "id": "bg_ffffffff"})[1]["error"] == "not_in_register"


def test_use_rows_once_per_window_and_expire_once():
    t = bg.UseTracker()
    assert t.use("bg_1", 0) and not t.use("bg_1", 100) and t.use("bg_1", 700)
    assert t.expire("bg_1") and not t.expire("bg_1")


def test_issue_validation():
    settings = {"enabled": True, "max_minutes": 240, "require_ticket": True, "never_relax": NEVER}
    ok = bg.validate_request(settings, "team:payments-dev", ["semantic"], 30, "INC-1", "urgent fix")
    assert ok is None
    assert "never relaxable" in bg.validate_request(
        settings, "team:x", ["secret-github-token"], 30, "T", "why"
    )
    assert "ticket" in bg.validate_request(settings, "team:x", ["semantic"], 30, "", "why")
    assert "minutes" in bg.validate_request(settings, "team:x", ["semantic"], 999, "T", "why")
    assert "subject" in bg.validate_request(settings, "payments", ["semantic"], 30, "T", "why")
    assert "disabled" in bg.validate_request({**settings, "enabled": False}, "team:x", ["a"], 1, "T", "why")


def test_relaxed_findings_but_not_never_relax():
    from pathlib import Path

    from ctrl_ai.core.context import Piece, RequestContext
    from ctrl_ai.core.policy import parse_policy
    from ctrl_ai.detect.signatures import parse_feed
    from tests.unit.helpers import check_pieces

    config = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "config"
    policy = parse_policy((config / "policy.yaml").read_bytes())
    feed = parse_feed((config / "signatures.yaml").read_bytes())
    ctx = RequestContext(mode="enforce", break_glass={"id": "bg_1", "relaxed": ["secrets", "signatures"]})
    ctx.never_relax = frozenset(NEVER)
    ctx.pieces = [Piece("x trust_remote_code=True", "prompt")]
    check_pieces(ctx, policy, feed)
    assert ctx.decision == "allow" and ctx.flagged
    ctx = RequestContext(mode="enforce", break_glass={"id": "bg_1", "relaxed": ["secrets"]})
    ctx.never_relax = frozenset(NEVER)
    ctx.pieces = [Piece("ghp_" + "A1b2" * 9, "prompt")]
    check_pieces(ctx, policy, feed)
    assert ctx.decision == "block"
