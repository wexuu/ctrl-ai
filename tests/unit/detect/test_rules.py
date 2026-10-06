from __future__ import annotations

from ctrl_ai.core.policy import Policy, Rule, parse_policy
from ctrl_ai.detect.rules import first_match

POLICY = parse_policy(b"""\
mode: enforce
rules:
  - id: test-marker
    type: contains
    value: "CTRL-AI-BLOCK-TEST"
  - id: aws-access-key
    type: regex
    value: "AKIA[0-9A-Z]{16}"
  - id: private-key
    type: regex
    value: "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
""")


def matched(text: str) -> str | None:
    rule = first_match(POLICY, text)
    return rule.id if rule else None


def test_contains():
    assert matched("please CTRL-AI-BLOCK-TEST now") == "test-marker"


def test_contains_is_case_sensitive():
    assert matched("ctrl-ai-block-test") is None


def test_regex():
    assert matched("key = AKIA" + "A1B2C3D4E5F6G7H8") == "aws-access-key"
    assert matched("-----BEGIN PRIVATE KEY-----") == "private-key"
    assert matched("-----BEGIN OPENSSH PRIVATE KEY-----") == "private-key"


def test_akia_with_15_characters_does_not_match():
    assert matched("AKIA" + "A1B2C3D4E5F6G7H") is None


def test_no_match_and_empty_text():
    assert matched("nothing to see here") is None
    assert matched("") is None


def test_rules_are_tried_in_file_order():
    text = "CTRL-AI-BLOCK-TEST and AKIA" + "A" * 16
    assert matched(text) == "test-marker"


def test_regex_rule_built_without_a_compiled_pattern():
    policy = Policy(mode="enforce", rules=(Rule("digits", "regex", r"\d{3}"),), jev_enabled=True, version="x")
    assert first_match(policy, "abc 123").id == "digits"
