from __future__ import annotations

from ctrl_ai.semantic.jev.questions import QUESTIONS, build_request, question_ids


def test_build_request_has_exactly_three_fields() -> None:
    body = build_request("hello", "jev-1.13.0")
    assert set(body) == {"state", "model", "questions"}
    assert body["state"] == "hello"
    assert body["model"] == "jev-1.13.0"


def test_both_questions_are_nouls_with_criteria() -> None:
    body = build_request("x", "jev-1.13.0")
    assert set(body["questions"]) == {"instruction_override", "harmful_misuse"}
    for q in body["questions"].values():
        assert q["type"] == "noul"
        assert q["instructions"].endswith("?")
        assert set(q["criteria"]) == {"true", "false"}


def test_question_ids_follow_the_table() -> None:
    assert question_ids() == ("instruction_override", "harmful_misuse")


def test_build_request_does_not_share_mutable_state() -> None:
    body = build_request("x", "m")
    body["questions"]["instruction_override"]["criteria"]["true"] = "changed"
    assert QUESTIONS["instruction_override"]["criteria"]["true"] != "changed"
