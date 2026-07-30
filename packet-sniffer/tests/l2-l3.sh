#!/usr/bin/env bash
set -euo pipefail

# L2/L3 decode traffic
# Optional env: IFACE (real interface) and GATEWAY for ARP

echo "[l2-l3] Generate IPv4, IPv6, and ARP traffic. Run cshark (All Packets) in parallel."

if [[ -n "${IFACE:-}" ]]; then
  echo "[l2-l3] IPv4 ping"
  ping -c 1 1.1.1.1 || true
  echo "[l2-l3] IPv6 ping"
  ping -6 -c 1 ipv6.google.com || true
  if [[ -n "${GATEWAY:-}" ]]; then
    echo "[l2-l3] ARP to ${GATEWAY}"
    sudo arping -c 1 "${GATEWAY}" || true
  else
    echo "[l2-l3] GATEWAY not set; skipping ARP."
  fi
else
  echo "[l2-l3] IFACE not set; skipping real-interface tests."
fi

echo "[l2-l3] Done."


