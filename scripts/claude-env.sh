#!/usr/bin/env bash
# Print (not run) the shell lines that point Claude Code at the gateway.
# MODE=subscription (default) or MODE=key. Usage: eval "$(make -s claude-env)"
# The output contains the gateway key: do not paste it into a chat or a ticket.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MODE="${MODE:-subscription}"
KEY="$(require_master_key)"

case "$MODE" in
  subscription)
    cat <<EOF
# Subscription pass-through: Claude Code keeps its own Claude login; the gateway key goes in a custom header.
# ANTHROPIC_AUTH_TOKEN and ANTHROPIC_API_KEY must stay unset: either one replaces the subscription login.
# Do not run the agent that is building this repo through the gateway.
export ANTHROPIC_BASE_URL=$GATEWAY_URL
export ANTHROPIC_CUSTOM_HEADERS="x-litellm-api-key: Bearer $KEY"
unset ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY
EOF
    ;;
  key)
    cat <<EOF
# Provider-key mode: the gateway calls Anthropic with its own ANTHROPIC_API_KEY (must be set in .env).
# Do not run the agent that is building this repo through the gateway.
export ANTHROPIC_BASE_URL=$GATEWAY_URL
export ANTHROPIC_AUTH_TOKEN=$KEY
unset ANTHROPIC_API_KEY ANTHROPIC_CUSTOM_HEADERS
EOF
    ;;
  *)
    echo "Unknown MODE '$MODE'. Use MODE=subscription or MODE=key." >&2
    exit 1
    ;;
esac
