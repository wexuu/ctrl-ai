#!/usr/bin/env bash
# One real Claude Code turn through the gateway. Uses the operator's Claude
# subscription (MODE=subscription, default) or the gateway's provider key
# (MODE=key) for one or two short prompts. Never prints the gateway key.
#
# LIVE_CHECK_EXPECT_BLOCK=1 (default) also sends a prompt the guardrail must
# block. Set it to 0 when running the infra-only config.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODE="${MODE:-subscription}"
EXPECT_BLOCK="${LIVE_CHECK_EXPECT_BLOCK:-1}"
AUDIT_LOG="$REPO_ROOT/logs/audit.jsonl"

case "$MODE" in
  subscription|key) ;;
  *) echo "Unknown MODE '$MODE'. Use MODE=subscription or MODE=key." >&2; exit 1 ;;
esac

command -v claude >/dev/null 2>&1 || { echo "Claude Code ('claude') is not installed; cannot run the live check." >&2; exit 1; }
gateway_alive || { echo "The gateway does not answer at $GATEWAY_URL/health/liveliness. Run: make up" >&2; exit 1; }
KEY="$(require_master_key)"

# A fresh empty directory, so Claude Code picks up no project context or settings.
WORKDIR="$(mktemp -d)"
trap 'rmdir "$WORKDIR" 2>/dev/null || true' EXIT

# Run one prompt. Output goes to OUTPUT, exit code to STATUS. The environment
# is changed in a subshell only, so the key never appears on a command line.
run_claude() {
  OUTPUT="$(
    cd "$WORKDIR" || exit 1
    unset ANTHROPIC_API_KEY
    export ANTHROPIC_BASE_URL="$GATEWAY_URL"
    export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
    if [ "$MODE" = "subscription" ]; then
      # Either variable would replace the subscription login for this traffic.
      unset ANTHROPIC_AUTH_TOKEN
      export ANTHROPIC_CUSTOM_HEADERS="x-litellm-api-key: Bearer $KEY"
    else
      unset ANTHROPIC_CUSTOM_HEADERS
      export ANTHROPIC_AUTH_TOKEN="$KEY"
    fi
    claude -p "$1" </dev/null 2>&1
  )"
  STATUS=$?
}

# Claude Code's output is the diagnosis (it carries the upstream error text).
# The gateway key is masked in case an error message ever echoes a header.
show_output() {
  echo "--- Claude Code output (exit code $STATUS) ---"
  printf '%s\n' "${OUTPUT//$KEY/<gateway key>}"
  echo "---"
}

FAILED=0

echo "Live check, mode: $MODE, gateway: $GATEWAY_URL"

run_claude "Reply with the single word PONG"
if printf '%s' "$OUTPUT" | grep -q 'PONG'; then
  echo "PASS  step 1: a normal prompt got an answer through the gateway"
else
  echo "FAIL  step 1: the output does not contain PONG"
  show_output
  FAILED=1
fi

if [ "$EXPECT_BLOCK" = "1" ]; then
  # AWS's documented example access key: the secrets pack blocks it in every shipped policy.
  run_claude "My key is AKIAIOSFODNN7EXAMPLE, say hi"
  if [ "$STATUS" -ne 0 ] && printf '%s' "$OUTPUT" | grep -q 'ctrl-ai'; then
    echo "PASS  step 2: the prompt with a cloud key was blocked by ctrl-ai"
  else
    echo "FAIL  step 2: expected a non-zero exit and a message naming ctrl-ai"
    show_output
    FAILED=1
  fi
else
  echo "SKIP  step 2: LIVE_CHECK_EXPECT_BLOCK=$EXPECT_BLOCK"
fi

if [ -s "$AUDIT_LOG" ]; then
  # A blocked prompt appears twice: Claude Code retries a 400 once.
  echo "Last audit rows (type, decision, rule, status, jev.status):"
  tail -n 10 "$AUDIT_LOG" | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        row = json.loads(line)
    except ValueError:
        continue
    jev = row.get("jev")
    shown = {
        "type": row.get("type"),
        "decision": row.get("decision"),
        "rule": row.get("rule"),
        "status": row.get("status"),
        "jev.status": jev.get("status") if isinstance(jev, dict) else None,
    }
    print("  " + json.dumps(shown))
'
else
  echo "No audit rows in logs/audit.jsonl (expected with the infra-only config)."
fi

if [ "$FAILED" -ne 0 ]; then
  echo "Live check FAILED."
  exit 1
fi
echo "Live check passed."
