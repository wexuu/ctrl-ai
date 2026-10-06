#!/usr/bin/env bash
# Health and auth checks against a running gateway. One line per check; stops
# at the first failure. Makes no model call and never prints the gateway key.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

KEY="$(require_master_key)"
REQUEST='{"model":"claude-haiku-4-5","max_tokens":8,"messages":[{"role":"user","content":"ping"}]}'

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1" >&2; exit 1; }

# Run curl with the given arguments; set CODE to the status and BODY to the body.
request() {
  local out
  out="$(curl -s -m 10 -w '\n%{http_code}' "$@" || true)"
  CODE="${out##*$'\n'}"
  BODY="${out%$'\n'*}"
}

request "$GATEWAY_URL/health/liveliness"
[ "$CODE" = "200" ] || fail "GET /health/liveliness: expected 200, got $CODE (is the gateway up? try: make up)"
pass "GET /health/liveliness answers 200"

request -X POST "$GATEWAY_URL/v1/messages" -H 'content-type: application/json' -d "$REQUEST"
[ "$CODE" = "401" ] || fail "POST /v1/messages with no key: expected 401, got $CODE"
pass "POST /v1/messages with no key answers 401"

# ctrl-ai's custom auth checks team keys itself: an unknown key is 401.
request -X POST "$GATEWAY_URL/v1/messages" -H 'content-type: application/json' \
  -H 'authorization: Bearer sk-ctrl-ai-smoke-wrong-key' -d "$REQUEST"
[ "$CODE" = "401" ] || fail "POST /v1/messages with a wrong key: expected 401, got $CODE"
case "$BODY" in
  *"Invalid or revoked ctrl-ai key"*) ;;
  *) fail "POST /v1/messages with a wrong key: body does not mention 'Invalid or revoked ctrl-ai key'" ;;
esac
pass "POST /v1/messages with a wrong key answers 401 'Invalid or revoked ctrl-ai key'"

request "$GATEWAY_URL/v1/models" -H "authorization: Bearer $KEY"
[ "$CODE" = "200" ] || fail "GET /v1/models with the gateway key: expected 200, got $CODE"
for model in claude-opus-5-5 claude-sonnet-5-5 claude-haiku-4-5; do
  case "$BODY" in
    *"\"$model\""*) ;;
    *) fail "GET /v1/models: $model is not listed" ;;
  esac
done
pass "GET /v1/models lists claude-opus-5-5, claude-sonnet-5-5, claude-haiku-4-5"

echo "Smoke check passed."
