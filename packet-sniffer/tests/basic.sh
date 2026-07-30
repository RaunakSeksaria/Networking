#!/usr/bin/env bash
set -euo pipefail

# Device discovery & basic capture traffic generator
# Usage: make test-basic
# Optional env:
#   IFACE=wlan0     # real interface (for internet traffic); if unset, script will skip real IF steps

echo "[basic] Generating simple traffic. In another terminal, run: sudo ./cshark and select interface."

if [[ -n "${IFACE:-}" ]]; then
  echo "[basic] Real IF (${IFACE}): ping IPv4 and HTTP HEAD..."
  ping -c 2 8.8.8.8 || true
  curl -I --max-time 5 http://example.com || true
else
  echo "[basic] IFACE not set; skipping real-interface traffic."
fi

echo "[basic] Loopback (lo): start a quick HTTP server and curl it."
python3 -m http.server 8080 >/dev/null 2>&1 &
srv=$!
sleep 1
curl -I --max-time 5 http://127.0.0.1:8080/ || true
kill ${srv} >/dev/null 2>&1 || true
echo "[basic] Done. Use Ctrl+C in cshark to stop capture."


