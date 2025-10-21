#!/usr/bin/env bash
set -euo pipefail

# Phase 1: Device discovery & basic capture traffic generator
# Usage: make -C B test-b-phase1
# Optional env:
#   IFACE=wlan0     # real interface (for internet traffic); if unset, script will skip real IF steps

echo "[Phase1] Generating simple traffic. In another terminal, run: sudo ./cshark and select interface."

if [[ -n "${IFACE:-}" ]]; then
  echo "[Phase1] Real IF (${IFACE}): ping IPv4 and HTTP HEAD..."
  ping -c 2 8.8.8.8 || true
  curl -I --max-time 5 http://example.com || true
else
  echo "[Phase1] IFACE not set; skipping real-interface traffic."
fi

echo "[Phase1] Loopback (lo): start a quick HTTP server and curl it."
python3 -m http.server 8080 >/dev/null 2>&1 &
srv=$!
sleep 1
curl -I --max-time 5 http://127.0.0.1:8080/ || true
kill ${srv} >/dev/null 2>&1 || true
echo "[Phase1] Done. Use Ctrl+C in cshark to stop capture."


