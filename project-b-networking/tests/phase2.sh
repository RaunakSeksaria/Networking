#!/usr/bin/env bash
set -euo pipefail

# Phase 2: L2/L3 decode traffic
# Optional env: IFACE (real interface) and GATEWAY for ARP

echo "[Phase2] Generate IPv4, IPv6, and ARP traffic. Run cshark (All Packets) in parallel."

if [[ -n "${IFACE:-}" ]]; then
  echo "[Phase2] IPv4 ping"
  ping -c 1 1.1.1.1 || true
  echo "[Phase2] IPv6 ping"
  ping -6 -c 1 ipv6.google.com || true
  if [[ -n "${GATEWAY:-}" ]]; then
    echo "[Phase2] ARP to ${GATEWAY}"
    sudo arping -c 1 "${GATEWAY}" || true
  else
    echo "[Phase2] GATEWAY not set; skipping ARP."
  fi
else
  echo "[Phase2] IFACE not set; skipping real-interface tests."
fi

echo "[Phase2] Done."


