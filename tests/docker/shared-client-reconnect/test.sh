#!/usr/bin/env bash
# test.sh — Shared client reconnection E2E test
#
# Surfaces the bug described in GitHub issue #3:
# LocalClientInterface does not reconnect when rnsd restarts.
#
# Architecture:
#   daemon container  — standalone node with TCP server (port 8081)
#   client container  — rnsd (share_instance=Yes) + rns-ctl http --daemon (port 8082)
#
# The test:
#   1. Verify baseline connectivity (daemon announces, client sees it)
#   2. Kill rnsd inside the client container
#   3. Restart rnsd inside the client container
#   4. Verify the shared client reconnects and can see new announces
#      (This is expected to FAIL until reconnection is implemented)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../lib/helpers.sh"

_CURRENT_SUITE="shared-client-reconnect"

PORT_DAEMON=8081
PORT_CLIENT=8082
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

echo "=== Shared Client Reconnection E2E Test ==="

poll_client_log_for_announce() {
  local dest_hash="$1" timeout="${2:-30}"
  local deadline=$((SECONDS + timeout))
  local needle="Announce received for ${dest_hash}"
  while (( SECONDS < deadline )); do
    if docker exec reconnect-client sh -c "grep -q '$needle' /tmp/rnsd.log" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "TIMEOUT: /tmp/rnsd.log never contained '${needle}'" >&2
  return 1
}

# ── Step 1: Wait for all nodes healthy ──────────────────────────────────────

echo "  Waiting for daemon to be healthy..."
if ! poll_until "$PORT_DAEMON" "/health" ".status" "healthy" 30; then
  fail_test "daemon healthy"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "daemon healthy"

echo "  Waiting for client to be healthy..."
if ! poll_until "$PORT_CLIENT" "/health" ".status" "healthy" 60; then
  fail_test "client healthy"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "client healthy"

# Let things settle
sleep 3

# ── Step 2: Check client has LocalInterface online ──────────────────────────

echo "  Checking client interface status..."
CLIENT_IFACES=$(ctl_get "$PORT_CLIENT" "/api/interfaces" 2>/dev/null || echo '{"interfaces":[]}')
LOCAL_UP=$(echo "$CLIENT_IFACES" | jq -r \
  '[.interfaces[] | select(.status == "up")] | length' 2>/dev/null || echo "0")
echo "  Client has $LOCAL_UP interface(s) up"
assert_ge "$LOCAL_UP" "1" "client has at least 1 interface up"

# ── Step 3: Baseline — shared client announces, local rnsd receives it ─────

echo "  Creating destination on shared client..."
DEST_BASELINE=$(create_destination "$PORT_CLIENT" "single" "reconntest" "baseline")
if [[ -z "$DEST_BASELINE" || "$DEST_BASELINE" == "null" ]]; then
  fail_test "create baseline destination"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "create baseline destination: ${DEST_BASELINE}"

echo "  Announcing from shared client..."
announce "$PORT_CLIENT" "$DEST_BASELINE"

echo "  Waiting for local rnsd to receive baseline announce..."
if ! poll_client_log_for_announce "$DEST_BASELINE" 30; then
  fail_test "baseline announce received by local rnsd"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
pass_test "baseline announce received by local rnsd"

# ── Step 4: Kill rnsd inside the client container ───────────────────────────

echo ""
echo "  === Killing rnsd inside client container ==="
RNSD_PID=$(docker exec reconnect-client cat /tmp/rnsd.pid 2>/dev/null || echo "")
if [[ -z "$RNSD_PID" ]]; then
  fail_test "read rnsd PID"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi
echo "  rnsd PID: $RNSD_PID"

docker exec reconnect-client sh -c "kill $RNSD_PID"
echo "  Sent SIGTERM to rnsd"

# Wait for the process to die
sleep 3

# Verify rnsd is dead
if docker exec reconnect-client sh -c "kill -0 $RNSD_PID" 2>/dev/null; then
  echo "  rnsd still alive, sending SIGKILL..."
  docker exec reconnect-client sh -c "kill -9 $RNSD_PID" || true
  sleep 2
fi
pass_test "rnsd killed"

# ── Step 5: Verify client's LocalInterface went down ────────────────────────

echo "  Checking client interface status after rnsd kill..."
sleep 2
CLIENT_IFACES_DOWN=$(ctl_get "$PORT_CLIENT" "/api/interfaces" 2>/dev/null || echo '{"interfaces":[]}')
LOCAL_DOWN=$(echo "$CLIENT_IFACES_DOWN" | jq -r \
  '[.interfaces[] | select(.status == "up")] | length' 2>/dev/null || echo "0")
echo "  Client has $LOCAL_DOWN interface(s) up after rnsd killed"
# The interface should be down now
assert_eq "$LOCAL_DOWN" "0" "client interfaces down after rnsd killed"

# ── Step 6: Restart rnsd inside the client container ────────────────────────

echo ""
echo "  === Restarting rnsd inside client container ==="
docker exec -d reconnect-client sh -c 'rns-ctl daemon --config /data >>/tmp/rnsd.log 2>&1 & echo $! > /tmp/rnsd.pid'
echo "  Started new rnsd process"

# Wait for rnsd to start
sleep 5

# Verify new rnsd is running
NEW_PID=$(docker exec reconnect-client cat /tmp/rnsd.pid 2>/dev/null || echo "")
if [[ -n "$NEW_PID" ]] && docker exec reconnect-client sh -c "kill -0 $NEW_PID" 2>/dev/null; then
  pass_test "new rnsd started (PID: $NEW_PID)"
else
  fail_test "new rnsd started"
  suite_result "$_CURRENT_SUITE"
  exit 1
fi

# ── Step 7: Check if shared client reconnected ─────────────────────────────

echo ""
echo "  === Checking if shared client reconnected ==="
echo "  Waiting for client interface to come back up..."

# Give time for reconnection (reconnect_wait default is 8s)
RECONNECTED=false
DEADLINE=$((SECONDS + 30))
while (( SECONDS < DEADLINE )); do
  IFACES=$(ctl_get "$PORT_CLIENT" "/api/interfaces" 2>/dev/null || echo '{"interfaces":[]}')
  UP_COUNT=$(echo "$IFACES" | jq -r \
    '[.interfaces[] | select(.status == "up")] | length' 2>/dev/null || echo "0")
  if [[ "$UP_COUNT" -ge 1 ]]; then
    RECONNECTED=true
    break
  fi
  sleep 2
done

if $RECONNECTED; then
  pass_test "shared client reconnected to rnsd"
else
  fail_test "shared client reconnected to rnsd" \
    "LocalClientInterface did not reconnect after rnsd restart (issue #3)"
fi

# ── Step 8: Verify end-to-end works after reconnection ─────────────────────

if $RECONNECTED; then
  echo "  Creating new destination on shared client..."
  DEST_RECOVERY=$(create_destination "$PORT_CLIENT" "single" "reconntest" "recovery")
  echo "  New dest: $DEST_RECOVERY"
  announce "$PORT_CLIENT" "$DEST_RECOVERY"

  echo "  Waiting for restarted local rnsd to receive post-reconnect announce..."
  if poll_client_log_for_announce "$DEST_RECOVERY" 30; then
    pass_test "post-reconnection announce received by local rnsd"
  else
    fail_test "post-reconnection announce received by local rnsd" \
      "reconnected but shared client could not announce through local daemon"
  fi
else
  echo "  Skipping post-reconnection tests (client did not reconnect)"
fi

# ── Step 9: HTTP API still responsive ───────────────────────────────────────

echo "  Checking client HTTP API still responsive..."
if poll_until "$PORT_CLIENT" "/health" ".status" "healthy" 5; then
  pass_test "client HTTP API responsive after test"
else
  fail_test "client HTTP API responsive after test"
fi

# ── Results ─────────────────────────────────────────────────────────────────

suite_result "$_CURRENT_SUITE"
