#!/bin/sh
# Entrypoint for the client container.
# Runs rnsd (daemon with share_instance=Yes) in background,
# then rns-ctl http --daemon (shared client) in foreground.
set -e

cp /etc/rns/config /data/config
RNSD_LOG=/tmp/rnsd.log
rm -f "$RNSD_LOG"

# Start rnsd in background
rns-ctl daemon --config /data >>"$RNSD_LOG" 2>&1 &
RNSD_PID=$!
echo "$RNSD_PID" > /tmp/rnsd.pid
echo "Started rnsd with PID $RNSD_PID"

# Wait for rnsd to start accepting connections on shared instance port.
# On Linux, LocalClient tries Unix abstract socket first then TCP 37428.
# We poll TCP as a reliable check.
for i in $(seq 1 60); do
  if [ -e /proc/$RNSD_PID ]; then
    # Try connecting to the shared instance port
    if timeout 1 sh -c "echo | curl -sf telnet://127.0.0.1:37428 2>/dev/null" 2>/dev/null; then
      break
    fi
    # Also check via /dev/tcp if available, else just wait
    sleep 0.5
  else
    echo "ERROR: rnsd exited prematurely"
    exit 1
  fi
done

# Extra settle time for rnsd to fully initialize
sleep 2

echo "Starting shared client HTTP API..."
exec rns-ctl http --daemon --config /data --disable-auth --host 0.0.0.0 --port 8080
