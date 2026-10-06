"""Customer data never leaves on the external route; the client gets it back."""

from __future__ import annotations

import json

from tests.e2e import harness as h
from tests.e2e.constants import FAKE_OAUTH_TOKEN

IBAN_PL = "PL61 1090 1014 0000 0712 1981 2874"
PESEL = "44051401359"


def test_external_route_is_masked_and_restored(audit_start):
    resp = h.post_messages(h.messages_body(f"{IBAN_PL} PESEL {PESEL} check {h.tag()}"))
    assert resp.status_code == 200, resp.text
    [up] = [r for r in h.anthropic_requests() if not r.get("judge")]
    assert up["saw_synthetic_iban"] is False and up["saw_synthetic_pesel"] is False
    answer = resp.json()["content"][0]["text"]
    assert IBAN_PL in answer  # the stub echoed the surrogate; the gateway restored it
    row = h.decision_row(resp, audit_start)
    assert row["masked"] == {"iban": 1, "pesel": 1}
    assert {f["rule"]: f["action"] for f in row["findings"]} == {"pii-iban": "mask", "pl-pesel": "mask"}
    assert h.usage_row(resp, audit_start)["masked_total"] == 2
    audit = h.AUDIT_FILE.read_text(encoding="utf-8")
    assert IBAN_PL not in audit and PESEL not in audit


def test_chat_completions_masked_and_restored(audit_start):
    resp = h.post_chat(h.chat_body(f"{IBAN_PL} on chat {h.tag()}"))
    assert resp.status_code == 200, resp.text
    [up] = [r for r in h.anthropic_requests() if not r.get("judge")]
    assert up["saw_synthetic_iban"] is False
    assert IBAN_PL in resp.json()["choices"][0]["message"]["content"]


def test_subscription_route_is_not_rewritten(audit_start):
    headers = {
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "x-litellm-api-key": f"Bearer {h.TEST_KEY}",
        "authorization": f"Bearer {FAKE_OAUTH_TOKEN}",
    }
    resp = h.post_messages(h.messages_body(f"{IBAN_PL} PESEL {PESEL} sub {h.tag()}"), headers)
    assert resp.status_code == 200, resp.text
    [up] = [r for r in h.anthropic_requests() if not r.get("judge")]
    assert up["saw_synthetic_iban"] is True and up["saw_synthetic_pesel"] is True
    row = h.decision_row(resp, audit_start)
    assert row["masked"] == {"iban": 1, "pesel": 1}  # the semantic copy only
    assert {f["action"] for f in row["findings"]} == {"flag"}


def test_streaming_chat_restores_a_split_surrogate(audit_start):
    status, _, _, raw = h.stream_events(
        "/v1/chat/completions", h.chat_body(f"{IBAN_PL} stream {h.tag()}", stream=True)
    )
    assert status == 200
    text = ""
    for line in raw.splitlines():
        if line.startswith("data:") and "[DONE]" not in line:
            chunk = json.loads(line[5:])
            for choice in chunk.get("choices") or []:
                text += (choice.get("delta") or {}).get("content") or ""
    assert IBAN_PL in text, text
    [up] = [r for r in h.anthropic_requests() if not r.get("judge")]
    assert up["saw_synthetic_iban"] is False
