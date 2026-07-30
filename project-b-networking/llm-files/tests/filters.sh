#!/usr/bin/env bash
set -euo pipefail

# Filters traffic generators. Run cshark Option 2 and select the respective filter, then run:

echo "[Filters] HTTP"
curl -I --max-time 5 http://example.com || true

echo "[Filters] HTTPS"
curl -I --max-time 5 https://example.com || true

echo "[Filters] DNS"
dig example.com || true

echo "[Filters] ARP"
if [[ -n "${GATEWAY:-}" ]]; then
  sudo arping -c 1 "${GATEWAY}" || true
else
  echo "[Filters] GATEWAY not set; skipping ARP."
fi

echo "[Filters] TCP"
curl -s --max-time 5 http://example.com > /dev/null || true

echo "[Filters] UDP"
dig example.com || true

echo "[Filters] Done."


