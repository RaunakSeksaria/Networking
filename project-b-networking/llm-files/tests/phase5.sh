#!/usr/bin/env bash
set -euo pipefail

# Phase 5: Mixed traffic for session storage and inspection

echo "[Phase5] Mixed: ping, HTTP, HTTPS, DNS."

ping -c 1 8.8.8.8 || true
curl -I --max-time 5 http://example.com || true
curl -s --max-time 5 https://www.google.com > /dev/null || true
dig +short example.com || true

echo "[Phase5] Done."


