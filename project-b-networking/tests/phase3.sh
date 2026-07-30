#!/usr/bin/env bash
set -euo pipefail

# Phase 3: L4 decode (TCP/UDP)

echo "[Phase3] TCP HTTP over real IF (if IFACE set) or loopback; and DNS UDP."

if [[ -n "${IFACE:-}" ]]; then
  curl -s --max-time 5 http://example.com > /dev/null || true
fi

dig +short @1.1.1.1 example.com || true
dig -6 +short @2606:4700:4700::1111 example.com || true

echo "[Phase3] Loopback TCP transfer via netcat."
nc -l 9001 >/dev/null 2>&1 &
srv=$!
sleep 1
printf 'hello tcp\n' | nc 127.0.0.1 9001 || true
kill ${srv} >/dev/null 2>&1 || true

echo "[Phase3] Done."


