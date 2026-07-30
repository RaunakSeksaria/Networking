#!/usr/bin/env bash
set -euo pipefail

# Payload identification and hex dump

echo "[payload] HTTPS and HTTP payloads; DNS payload."

curl -s --max-time 5 https://www.google.com > /dev/null || true
curl -I --max-time 5 http://neverssl.com || true
dig +trace example.com || true

echo "[payload] Done."


