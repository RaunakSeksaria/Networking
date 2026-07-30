#!/usr/bin/env bash
set -euo pipefail

# Mixed traffic for session storage and inspection

echo "[mixed] Mixed: ping, HTTP, HTTPS, DNS."

ping -c 1 8.8.8.8 || true
curl -I --max-time 5 http://example.com || true
curl -s --max-time 5 https://www.google.com > /dev/null || true
dig +short example.com || true

echo "[mixed] Done."


