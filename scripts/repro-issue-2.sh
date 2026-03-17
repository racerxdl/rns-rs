#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RETICULUM_DIR="${RETICULUM_DIR:-$HOME/Reticulum}"
INSTANCE_NAME="${RNS_INSTANCE_NAME:-default}"
SHARED_PORT="${RNS_SHARED_INSTANCE_PORT:-37428}"
TMP_DIR="$(mktemp -d /tmp/rns-issue-2.XXXXXX)"
RNSD_LOG="$TMP_DIR/rnsd.log"
RNSD_PID=""

cleanup() {
  if [[ -n "$RNSD_PID" ]] && kill -0 "$RNSD_PID" 2>/dev/null; then
    kill "$RNSD_PID" 2>/dev/null || true
    wait "$RNSD_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT

if [[ ! -f "$RETICULUM_DIR/RNS/Utilities/rnsd.py" ]]; then
  echo "Reticulum daemon not found at $RETICULUM_DIR/RNS/Utilities/rnsd.py" >&2
  exit 1
fi

cat >"$TMP_DIR/config" <<EOF
[reticulum]
enable_transport = No
share_instance = Yes
instance_name = $INSTANCE_NAME

[logging]
loglevel = 4

[interfaces]
EOF

echo "Starting temporary rnsd with instance_name=$INSTANCE_NAME"
python3 "$RETICULUM_DIR/RNS/Utilities/rnsd.py" --config "$TMP_DIR" -v >"$RNSD_LOG" 2>&1 &
RNSD_PID=$!

for _ in $(seq 1 50); do
  if python3 - <<PY >/dev/null 2>&1
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("\0rns/$INSTANCE_NAME")
finally:
    s.close()
PY
  then
    break
  fi

  if ! kill -0 "$RNSD_PID" 2>/dev/null; then
    echo "rnsd exited early" >&2
    sed -n '1,200p' "$RNSD_LOG" >&2 || true
    exit 1
  fi

  sleep 0.1
done

echo "Running rns-net repro example"
if (cd "$ROOT_DIR" && RNS_INSTANCE_NAME="$INSTANCE_NAME" RNS_SHARED_INSTANCE_PORT="$SHARED_PORT" cargo run -q -p rns-net --example repro_issue_2); then
  echo "Reproduction result: success"
  echo "On a checkout without the fix, this should fail after the Unix attempt and fall back to TCP."
else
  status=$?
  echo "Reproduction result: failure (exit $status)" >&2
  echo "rnsd log:" >&2
  sed -n '1,200p' "$RNSD_LOG" >&2 || true
  exit "$status"
fi
