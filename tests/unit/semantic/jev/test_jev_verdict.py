from __future__ import annotations

import pytest

from ctrl_ai.semantic.jev.verdict import cost_usd, normalise

ASKED = ("instruction_override", "harmful_misuse")
KEYS = {
    "status",
    "attack",
    "answers",
    "model",
    "input_tokens",
    "cost_usd",
    "latency_ms",
    "truncated",
    "error",
}


@pytest.mark.parametrize(
    ("name", "attack", "answers", "tokens"),
    [
        ("attack.json", 0.98, {"instruction_override": 0.98, "harmful_misuse": 0.64}, 301),
        ("benign.json", 0.02, {"instruction_override": 0.02, "harmful_misuse": 0.01}, 262),
        ("borderline.json", 0.41, {"instruction_override": 0.41, "harmful_misuse": 0.08}, 281),
    ],
)
def test_fixtures_normalise_to_ok(load_fixture, name: str, attack: float, answers: dict, tokens: int) -> None:
    v = normalise(200, load_fixture(name), 141.23, ASKED)
    assert set(v) == KEYS
    assert v["status"] == "ok"
    assert v["attack"] == attack
    assert v["answers"] == answers
    assert v["model"] == "jev-1.13.0"
    assert v["input_tokens"] == tokens
    assert v["cost_usd"] == pytest.approx(tokens * 0.042 / 1_000_000)
    assert v["latency_ms"] == 141.2
    assert v["truncated"] is False
    assert v["error"] is None


def test_cost_matches_contract_example() -> None:
    assert cost_usd(301) == pytest.approx(0.000012642)


@pytest.mark.parametrize("code", [408, 429, 529, 500, 502, 503, 504])
def test_unavailable_codes(code: int) -> None:
    v = normalise(code, None, 5.0, ASKED)
    assert (v["status"], v["error"]) == ("unavailable", f"http_{code}")


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
def test_error_codes(load_fixture, code: int) -> None:
    body = load_fixture("validation_error_422.json") if code == 422 else None
    v = normalise(code, body, 5.0, ASKED)
    assert (v["status"], v["error"]) == ("error", f"http_{code}")
    for key in ("attack", "answers", "model", "input_tokens", "cost_usd"):
        assert v[key] is None


def test_bad_json() -> None:
    v = normalise(200, None, 5.0, ASKED)
    assert (v["status"], v["error"]) == ("error", "bad_json")


@pytest.mark.parametrize(
    "answers",
    [
        {"instruction_override": {"type": "noul", "noul": 0.5}},  # one missing
        {"instruction_override": {"noul": "high"}, "harmful_misuse": {"noul": 0.1}},  # not a number
        {"instruction_override": {"noul": 1.2}, "harmful_misuse": {"noul": 0.1}},  # above 1
        {"instruction_override": {"noul": -0.1}, "harmful_misuse": {"noul": 0.1}},  # below 0
        {"instruction_override": {"noul": True}, "harmful_misuse": {"noul": 0.1}},  # bool
        {"instruction_override": {"noul": float("nan")}, "harmful_misuse": {"noul": 0.1}},
        {"instruction_override": 0.5, "harmful_misuse": {"noul": 0.1}},  # not an object
    ],
)
def test_missing_or_invalid_answer(answers: dict) -> None:
    body = {"model": "jev-1.13.0", "answers": answers, "usage": {"input_tokens": 10}}
    v = normalise(200, body, 5.0, ASKED)
    assert (v["status"], v["error"]) == ("error", "missing_answer")
    assert v["model"] is None and v["input_tokens"] is None


def test_answers_not_a_dict() -> None:
    v = normalise(200, {"answers": []}, 5.0, ASKED)
    assert (v["status"], v["error"]) == ("error", "missing_answer")


def test_json_list_body_is_bad_json() -> None:
    v = normalise(200, [1, 2], 5.0, ASKED)
    assert v["error"] == "bad_json"


def test_ok_without_usage_has_null_tokens_and_cost() -> None:
    body = {"model": "jev-1.13.0", "answers": {q: {"noul": 0.3} for q in ASKED}}
    v = normalise(200, body, 5.0, ASKED)
    assert v["status"] == "ok"
    assert v["input_tokens"] is None and v["cost_usd"] is None


def test_truncated_flag_is_carried(load_fixture) -> None:
    assert normalise(200, load_fixture("benign.json"), 1.0, ASKED, truncated=True)["truncated"] is True
    assert normalise(503, None, 1.0, ASKED, truncated=True)["truncated"] is True
