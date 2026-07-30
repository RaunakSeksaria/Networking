#!/usr/bin/env bash
set -euo pipefail

# Robustness and edge cases

echo "[Robustness] Very small packet (ARP) if GATEWAY set."
if [[ -n "${GATEWAY:-}" ]]; then
  sudo arping -c 1 "${GATEWAY}" || true
else
  echo "[Robustness] GATEWAY not set; skipping ARP."
fi

echo "[Robustness] Large TCP payload over loopback"
nc -l 9002 >/dev/null 2>&1 &
srv=$!
sleep 1
dd if=/dev/zero bs=1k count=10 2>/dev/null | nc 127.0.0.1 9002 || true
kill ${srv} >/dev/null 2>&1 || true

echo "[Robustness] Done."


