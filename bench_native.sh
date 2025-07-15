#!/usr/bin/env bash
set -euo pipefail

##### Adjustable paths ########################################################
SERVER_BIN="./target/release/zk-auth-api"   # built in step 1
K6_SCRIPT="./zk-bench.js"
################################################################################

TIMESTAMP=$(date +%F_%H%M%S)
LOGDIR="bench_logs/${TIMESTAMP}"
mkdir -p "$LOGDIR"

echo "→ starting server"
$SERVER_BIN &               # forks to background
PID=$!
sleep 2                     # give Actix‑Web a moment to bind :8080

echo "→ sampling CPU & RSS with top (PID=$PID)"
# top:  -l 0   run forever;  -s 1   1‑second sampling interval
#       -pid   limit to one process; -stats cpu,mem gives the two columns we need
top -l 0 -s 1 -pid "$PID" -stats pid,cpu,mem >> "$LOGDIR/top.log" &
TOPPID=$!

echo "→ running k6 load"
k6 run --out json="$LOGDIR/k6.json" "$K6_SCRIPT"

echo "→ cleaning up"
kill "$TOPPID" 2>/dev/null || true     # stop top sampler
kill "$PID"    2>/dev/null || true     # stop server

echo "✓ logs are under $LOGDIR"
echo "  • k6.json – per‑request latency & success"
echo "  • top.log – per‑second CPU % and resident memory (MB)"
