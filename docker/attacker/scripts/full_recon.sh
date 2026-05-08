#!/bin/bash
# Full recon sweep: nmap, whatweb, wafw00f, directory bruteforce
set -euo pipefail

TARGET="${1:?Usage: full_recon.sh <target-url>}"
OUTDIR="${2:-/home/attacker/results/recon}"
ATTEMPT_ID="${3:-recon-$(date +%s)}"

mkdir -p "$OUTDIR"

echo "[*] Starting full recon on $TARGET (ID: $ATTEMPT_ID)"

# Extract host and port
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d: -f1 | cut -d/ -f1)
PORT=$(echo "$TARGET" | grep -oP ':\K[0-9]+' || echo "80")

# ---- Phase 1: Port/Service scan ----
echo "[+] Nmap TCP scan..."
nmap -sV -sC -T4 -p- --open -oN "$OUTDIR/nmap_tcp.txt" "$HOST" 2>/dev/null || \
nmap -sV -T4 -p 1-10000 --open -oN "$OUTDIR/nmap_tcp.txt" "$HOST" 2>/dev/null || true

# ---- Phase 2: Web fingerprint ----
echo "[+] WhatWeb fingerprint..."
whatweb -a 3 "$TARGET" > "$OUTDIR/whatweb.txt" 2>/dev/null || true

# ---- Phase 3: WAF detection ----
echo "[+] WAF detection..."
wafw00f "$TARGET" > "$OUTDIR/waf.txt" 2>/dev/null || true

# ---- Phase 4: Directory brute-force ----
echo "[+] Gobuster directory scan..."
WORDLIST="${SECLISTS:-/opt/wordlists}/Discovery/Web-Content/common.txt"
if [ -f "$WORDLIST" ]; then
    gobuster dir -u "$TARGET" -w "$WORDLIST" -t 20 -q --no-error \
        -o "$OUTDIR/gobuster.txt" 2>/dev/null || true
fi

# ---- Phase 5: Nikto vulnerability scan ----
echo "[+] Nikto scan..."
timeout 120 nikto -h "$TARGET" -output "$OUTDIR/nikto.txt" -Format txt 2>/dev/null || true

# ---- Phase 6: SSL/TLS analysis (if HTTPS) ----
if echo "$TARGET" | grep -q "https"; then
    echo "[+] SSL scan..."
    sslscan "$HOST:$PORT" > "$OUTDIR/sslscan.txt" 2>/dev/null || true
fi

echo "[*] Recon complete. Results in $OUTDIR"
cat "$OUTDIR"/*.txt 2>/dev/null | head -200
