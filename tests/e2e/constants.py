"""Values the end-to-end tests assert on. Statuses were verified in the LiteLLM trial."""

from __future__ import annotations

MISSING_KEY_STATUS = 401
# ctrl-ai's custom auth answers a wrong key with 401 and its own message
# (LiteLLM alone gave 400 "No connected db.").
WRONG_KEY_STATUS = 401
WRONG_KEY_TEXT = "Invalid or revoked ctrl-ai key"
BLOCK_STATUS = 400  # every endpoint, streaming or not
BLOCK_MARKER_TEXT = "Blocked by ctrl-ai"
FAKE_OAUTH_TOKEN = "sk-ant-oat01-FAKETOKEN-CTRL-AI-TESTS-0000"  # must start with sk-ant-oat to be forwarded

# From tests/e2e/test.env.
TEST_PROVIDER_KEY = "sk-ant-test-dummy"
TEST_JEV_KEY = "jev-test-key"

MODEL = "claude-opus-5-5"
JEV_QUESTION_IDS = ("instruction_override", "harmful_misuse")
STUB_REPLY_PREFIX = "stub-reply:"
STUB_INPUT_TOKENS = 25
STUB_OUTPUT_TOKENS = 12

BLOCK_MARKER = "CTRL-AI-BLOCK-TEST"
ATTACK_MARKER = "ATTACKTEST"
UPSTREAM_400_MARKER = "UPSTREAM-400-TEST"
JEV_500_MARKER = "JEV-500-TEST"
JEV_SLOW_MARKER = "JEV-SLOW-TEST"
