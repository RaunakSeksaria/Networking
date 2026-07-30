#!/usr/bin/env bash
set -euo pipefail

# Phase 4: Payload identification and hex dump

echo "[Phase4] HTTPS and HTTP payloads; DNS payload."

curl -s --max-time 5 https://www.google.com > /dev/null || true
curl -I --max-time 5 http://neverssl.com || true
dig +trace example.com || true

echo "[Phase4] Done."


