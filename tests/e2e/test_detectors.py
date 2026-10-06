"""Personal and national identifiers flagged with every finding, secrets and signatures blocked."""

from __future__ import annotations

from tests.e2e import harness as h

IBAN_PL = "PL61 1090 1014 0000 0712 1981 2874"
PESEL = "44051401359"
GITHUB_TOKEN = "ghp_" + "A1b2" * 9


def test_iban_and_pesel_are_found_and_not_logged(audit_start):
    resp = h.post_messages(h.messages_body(f"Customer {IBAN_PL}, PESEL {PESEL}, please check {h.tag()}"))
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert row["v"] == 2
    assert [(f["rule"], f["pack"]) for f in row["findings"]] == [("pii-iban", "pii"), ("pl-pesel", "pl")]
    assert all(f["source"] == "prompt" for f in row["findings"])
    assert row["data_class_detected"] == "confidential"
    assert row["flagged"] is True
    assert row["decision"] in ("allow", "reroute")
    text = h.AUDIT_FILE.read_text(encoding="utf-8")
    assert IBAN_PL not in text and IBAN_PL.replace(" ", "") not in text and PESEL not in text


def test_github_token_is_blocked(audit_start):
    resp = h.post_chat(h.chat_body(f"my token {GITHUB_TOKEN} {h.tag()}"))
    assert resp.status_code == 400
    message, rule = h.block_info(resp)
    assert rule == "secret-github-token" and "secret-github-token" in message
    assert h.anthropic_requests() == []
    row = h.decision_row(resp, audit_start)
    assert row["decision"] == "block" and row["rule"] == "secret-github-token"
    assert row["findings"][0]["pack"] == "secrets"
    assert GITHUB_TOKEN not in h.AUDIT_FILE.read_text(encoding="utf-8")


def test_tool_result_with_trust_remote_code(audit_start):
    body = h.messages_conversation(
        [
            {"role": "user", "content": h.remember(f"read the loader {h.tag()}")},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "toolu_a1", "name": "Read", "input": {"path": "load.py"}}
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_a1",
                        "content": h.remember(
                            f"model = AutoModel.from_pretrained(n, trust_remote_code=True) {h.tag()}"
                        ),
                    }
                ],
            },
        ]
    )
    resp = h.post_messages(body)
    assert resp.status_code == 400
    row = h.decision_row(resp, audit_start)
    assert row["rule"] == "sig-trust-remote-code"
    sig = next(f for f in row["findings"] if f["rule"] == "sig-trust-remote-code")
    assert sig["source"] == "tool_result" and sig["pack"] == "signatures"


def test_card_near_miss_is_allowed(audit_start):
    resp = h.post_messages(h.messages_body(f"card 4111 1111 1111 1112 is a test {h.tag()}"))
    assert resp.status_code == 200
    row = h.decision_row(resp, audit_start)
    assert row["findings"] == [] and row["decision"] == "allow" and row["flagged"] is False
