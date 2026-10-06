"""An audited override relaxes what it names, never the never-relaxable controls."""

from __future__ import annotations

import os
import subprocess
import sys

from tests.e2e import harness as h
from tests.e2e.gateway_keys import issue_test_key, key_headers

SCRIPT = h.REPO / "scripts" / "break-glass.py"
REGISTER = h.RUNTIME / "state" / "break_glass.json"
SECRET = "ctrl-ai-test-breakglass-secret"  # tests/e2e/test.env
GITHUB_TOKEN = "ghp_" + "A1b2" * 9


def script(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "CTRL_AI_BREAKGLASS_SECRET": SECRET}
    return subprocess.run(
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
        env=env,
        timeout=30,
        check=False,
    )


def issue(relax: str) -> tuple[str, str]:
    out = script(
        "issue",
        "--subject",
        "team:payments-dev",
        "--relax",
        relax,
        "--minutes",
        "30",
        "--ticket",
        "INC-1234",
        "--reason",
        "urgent payments fix",
        "--by",
        "secops-e2e",
    )
    assert out.returncode == 0, out.stderr
    token = out.stdout.strip()
    override_id = out.stderr.split()[1]
    return token, override_id


def test_semantic_override_then_revoke(audit_start):
    key, _ = issue_test_key("payments-dev")
    blocked = h.post_messages(h.messages_body(f"ATTACKTEST urgent {h.tag()}"), key_headers(key))
    assert blocked.status_code == 400
    token, override_id = issue("semantic")
    headers = {**key_headers(key), "x-ctrl-ai-break-glass": token}
    resp = h.post_messages(h.messages_body(f"ATTACKTEST urgent {h.tag()}"), headers)
    assert resp.status_code == 200, resp.text
    row = h.decision_row(resp, audit_start)
    assert row["break_glass"] == {"id": override_id, "relaxed": ["semantic"]}
    assert row["semantic"]["action"] == "flag" and row["semantic"]["reason"] == "break_glass"
    assert row["flagged"] is True
    assert script("revoke", "--id", override_id, "--by", "secops-e2e").returncode == 0
    offset = h.audit_offset()
    again = h.post_messages(h.messages_body(f"ATTACKTEST urgent {h.tag()}"), headers)
    assert again.status_code == 400
    assert h.decision_row(again, offset)["break_glass"] == {"id": override_id, "error": "revoked"}
    text = h.AUDIT_FILE.read_text(encoding="utf-8")
    assert token not in text and token.split(".")[1] not in text
    events = [r.get("event") for r in h.audit_rows_since(audit_start) if r.get("type") == "break_glass"]
    assert events[:2] == ["issue", "use"] and "revoke" in events


def test_never_relaxable_secret_stays_blocked(audit_start):
    out = script(
        "issue",
        "--subject",
        "team:payments-dev",
        "--relax",
        "secret-github-token",
        "--minutes",
        "5",
        "--ticket",
        "INC-1",
        "--reason",
        "try",
        "--by",
        "x",
    )
    assert out.returncode == 2 and "never relaxable" in out.stderr
    key, _ = issue_test_key("payments-dev")
    token, _ = issue("secrets")
    resp = h.post_messages(
        h.messages_body(f"token {GITHUB_TOKEN} {h.tag()}"),
        {**key_headers(key), "x-ctrl-ai-break-glass": token},
    )
    assert resp.status_code == 400 and h.block_info(resp)[1] == "secret-github-token"


def test_bad_or_foreign_token_is_ignored(audit_start):
    key, _ = issue_test_key("retail-dev")
    token, _ = issue("semantic")  # issued for payments-dev
    resp = h.post_messages(
        h.messages_body(f"hello {h.tag()}"), {**key_headers(key), "x-ctrl-ai-break-glass": token}
    )
    assert resp.status_code == 200
    assert h.decision_row(resp, audit_start)["break_glass"]["error"] == "wrong_subject"
    offset = h.audit_offset()
    resp = h.post_messages(
        h.messages_body(f"hello {h.tag()}"), {**key_headers(key), "x-ctrl-ai-break-glass": "abc.def"}
    )
    assert resp.status_code == 200
    assert h.decision_row(resp, offset)["break_glass"] == {"id": None, "error": "bad_signature"}
