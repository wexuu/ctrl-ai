"""Surrogates, rewrite, restore (text, JSON, streams), Fernet, fail-closed, route."""

from __future__ import annotations

import asyncio
import json
import types
from pathlib import Path

import pytest

from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.policy import parse_policy
from ctrl_ai.core.state import RedisState
from ctrl_ai.detect import detectors as d
from ctrl_ai.detect import masking
from ctrl_ai.detect.restore import restore_chat_stream, restore_response
from ctrl_ai.pipeline import effects, evaluator

REPO = Path(__file__).resolve().parents[3]
POLICY = parse_policy((REPO / "tests" / "fixtures" / "config" / "policy.yaml").read_bytes())
VALUES = {
    "iban": "PL61 1090 1014 0000 0712 1981 2874",
    "account_pl": "61 1090 1014 0000 0712 1981 2874",
    "pesel": "44051401359",
    "nip": "123-456-32-18",
    "card": "4111 1111 1111 1111",
    "email": "jan.kowalski@example.com",
    "phone": "+48 600 123 456",
}
ALL = masking.detector_entities(["iban", "pesel", "nip", "card", "email", "phone"])


@pytest.mark.parametrize("entity", list(VALUES))
def test_surrogate_is_valid_same_layout_and_different(entity):
    value = VALUES[entity]
    fake = masking.surrogate(entity, value, "s1", "secret")
    assert fake != value
    [m] = d.detect(f"x {fake} y", (entity,))
    assert m.entity == entity
    if entity != "email":
        assert [c.isalnum() for c in fake] == [c.isalnum() for c in value]


@pytest.mark.parametrize("value", ["+1 (415) 555-0132", "+44 20 7946 0958", "+4930123456", "601 234 567"])
def test_phone_surrogate_keeps_the_country_code_and_layout(value):
    fake = masking.surrogate("phone", value, "s1", "secret")
    assert fake != value and [c.isdigit() for c in fake] == [c.isdigit() for c in value]
    if value.startswith("+"):
        assert fake[:3] == value[:3]  # the country code stays
    assert [m.value for m in d.detect(f"x {fake} y", ("phone",))] == [fake]


def test_deterministic_per_session_different_across_sessions():
    a = masking.surrogate("iban", VALUES["iban"], "s1", "k")
    assert a == masking.surrogate("iban", VALUES["iban"], "s1", "k")
    assert a != masking.surrogate("iban", VALUES["iban"], "s2", "k")
    assert a != masking.surrogate("iban", VALUES["iban"], "s1", "other-key")


def test_no_secret_never_masks():
    with pytest.raises(masking.MaskingError):
        masking.surrogate("iban", VALUES["iban"], "s", "")


def test_rewrite_inside_nested_tool_json_and_restore():
    m = masking.Masker(ALL, "s", "k")
    data = {
        "model": "x",
        "messages": [
            {"role": "user", "content": f"pay {VALUES['iban']}"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c",
                        "type": "function",
                        "function": {
                            "name": "transfer",
                            "arguments": json.dumps(
                                {"to": {"iban": VALUES["iban"]}, "note": VALUES["pesel"]}
                            ),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "c",
                "content": [{"type": "text", "text": f"done for {VALUES['email']}"}],
            },
        ],
    }
    m.mask_body(data)
    flat = json.dumps(data)
    assert VALUES["iban"] not in flat and VALUES["pesel"] not in flat and VALUES["email"] not in flat
    assert m.counts == {"iban": 1, "pesel": 1, "email": 1}
    args = data["messages"][1]["tool_calls"][0]["function"]["arguments"]
    assert masking.restore_value(args, m.mapping, "arguments") == json.dumps(
        {"to": {"iban": VALUES["iban"]}, "note": VALUES["pesel"]}, ensure_ascii=False
    )
    assert masking.restore_text(data["messages"][0]["content"], m.mapping) == f"pay {VALUES['iban']}"


def test_restore_response_shapes():
    m = masking.Masker(ALL, "s", "k")
    fake = m.mask_text(VALUES["iban"])
    messages = {
        "content": [
            {"type": "text", "text": f"ok {fake}"},
            {"type": "tool_use", "id": "t", "name": "pay", "input": {"iban": fake}},
        ]
    }
    restore_response(messages, m.mapping)
    assert messages["content"][0]["text"] == f"ok {VALUES['iban']}"
    assert messages["content"][1]["input"]["iban"] == VALUES["iban"]
    chat = types.SimpleNamespace(
        choices=[
            types.SimpleNamespace(
                message=types.SimpleNamespace(
                    content=f"to {fake}",
                    tool_calls=[
                        types.SimpleNamespace(
                            function=types.SimpleNamespace(arguments=json.dumps({"iban": fake}))
                        )
                    ],
                )
            )
        ]
    )
    restore_response(chat, m.mapping)
    assert chat.choices[0].message.content == f"to {VALUES['iban']}"
    assert VALUES["iban"] in chat.choices[0].message.tool_calls[0].function.arguments
    responses = types.SimpleNamespace(
        output=[types.SimpleNamespace(type="message", content=[types.SimpleNamespace(text=f"r {fake}")])]
    )
    restore_response(responses, m.mapping)
    assert responses.output[0].content[0].text == f"r {VALUES['iban']}"


def chunk(text, finish=None):
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(delta=types.SimpleNamespace(content=text), finish_reason=finish)]
    )


def test_stream_restore_across_chunk_boundaries():
    m = masking.Masker(ALL, "s", "k")
    fake = m.mask_text(VALUES["iban"])
    full = f"Your account {fake} is fine."
    pieces = [full[i : i + 5] for i in range(0, len(full), 5)]

    async def source():
        for i, p in enumerate(pieces):
            yield chunk(p, "stop" if i == len(pieces) - 1 else None)

    async def collect():
        return [c.choices[0].delta.content async for c in restore_chat_stream(source(), m.mapping)]

    out = "".join(asyncio.run(collect()))
    assert out == f"Your account {VALUES['iban']} is fine."


def test_stream_restorer_flushes_at_the_end():
    r = masking.StreamRestorer({"FAKE-VALUE-1": "real"})
    first = r.feed("abc FAKE-VA")
    assert "FAKE" not in first  # a possible partial surrogate is held back
    out = first + r.feed("LUE-1 end") + r.flush()
    assert out == "abc real end"


def test_fernet_round_trip():
    pytest.importorskip("cryptography")
    stored = masking.encrypt_map({"FAKE": "PL61..."}, "secret")
    assert stored["FAKE"] != "PL61..."
    assert set(stored) == {"FAKE"} and "PL61" not in stored["FAKE"]


def ctx_for(route="external"):
    ctx = RequestContext(profile=POLICY.profile("balanced"), mode="enforce", route=route, session="s")
    ctx.pieces = []
    return ctx


def test_plan_follows_route_and_secret():
    ctx = ctx_for()
    evaluator.plan_masking(ctx, POLICY, has_secret=True)
    assert ctx.mask_plan == "rewrite"
    ctx = ctx_for("claude_subscription")
    evaluator.plan_masking(ctx, POLICY, has_secret=True)
    assert ctx.mask_plan == "semantic_only"
    ctx = ctx_for()
    evaluator.plan_masking(ctx, POLICY, has_secret=False)
    assert ctx.mask_plan is None and ctx.masking == "no_secret"


def test_rewrite_fails_closed(monkeypatch):
    def broken(self, data):
        raise RuntimeError("bug")

    monkeypatch.setattr(masking.Masker, "mask_body", broken)
    ctx = ctx_for()
    masker = masking.Masker(masking.detector_entities(POLICY.masking["entities"]), "s", "k")
    asyncio.run(effects.rewrite_request(ctx, {"messages": []}, POLICY, masker, RedisState(""), "k"))
    assert (ctx.decision, ctx.status_code, ctx.rule) == ("block", 503, "masking-failed")
    assert ctx.message == "ctrl-ai could not protect this request's data; it was not sent."


def test_compact_form_of_a_surrogate_is_restored_too():
    m = masking.Masker(ALL, "s", "k")
    fake = m.mask_text(VALUES["iban"])
    assert (
        masking.restore_text(f"acct {fake.replace(' ', '')}", m.mapping)
        == f"acct {VALUES['iban'].replace(' ', '')}"
    )


def test_restore_tolerates_no_break_spaces_and_bban_only():
    """Merge live run: gpt-oss printed the surrogate IBAN with no-break spaces, and its 24-digit BBAN alone."""
    from ctrl_ai.detect.masking import Masker, restore_text

    m = Masker(("iban",), "s-nbsp", "secret")
    masked = m.mask_text("IBAN PL61 1090 1014 0000 0712 1981 2874")
    fake = masked.split("IBAN ", 1)[1]
    reply = f"The IBAN {fake.replace(' ', chr(0x202F))} is fine; account {fake.replace(' ', '')[4:]}."
    out = restore_text(reply, m.mapping)
    assert "PL61 1090 1014 0000 0712 1981 2874" in out and "109010140000071219812874" in out
    assert fake.replace(" ", "")[4:] not in out
