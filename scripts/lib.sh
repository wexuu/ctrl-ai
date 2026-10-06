# Shared helpers for the scripts in this folder. Sourced, not executed.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_URL="${CTRL_AI_GATEWAY_URL:-http://localhost:4000}"

# Print the gateway key: the shell environment wins, then .env, the same
# precedence compose uses. .env is parsed, not sourced, so nothing in it runs.
master_key() {
  local value="${LITELLM_MASTER_KEY:-}"
  if [ -z "$value" ] && [ -f "$REPO_ROOT/.env" ]; then
    value="$(sed -n 's/^[[:space:]]*LITELLM_MASTER_KEY=//p' "$REPO_ROOT/.env" | tail -n 1)"
    value="${value%$'\r'}"
    value="${value%\"}"; value="${value#\"}"
    value="${value%\'}"; value="${value#\'}"
  fi
  printf '%s' "$value"
}

# Like master_key, but exits with a message when there is none.
require_master_key() {
  local value
  value="$(master_key)"
  if [ -z "$value" ]; then
    echo "LITELLM_MASTER_KEY is not set in the environment or in .env." >&2
    exit 1
  fi
  printf '%s' "$value"
}

# True when the gateway answers its unauthenticated liveness endpoint.
# Never GET /health: it makes a real model call for every configured model.
gateway_alive() {
  [ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$GATEWAY_URL/health/liveliness")" = "200" ]
}
