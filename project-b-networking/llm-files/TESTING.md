# C‑Shark Testing Guide (Part B)

This guide automates traffic generation to validate Phases 1–5. You still operate `cshark` interactively.

## Build & Launch

make -C B
cd B
sudo ./cshark

Select an interface (`wlan0` or `lo`). From the Main Menu, choose the option required by the phase.

## Environment variables

- IFACE: real interface name (e.g., wlan0) to enable internet-based steps.
- GATEWAY: IPv4 gateway address for ARP tests.

## Phase scripts

Run these in another terminal while `cshark` is capturing:

make -C B test-b-phase1
make -C B test-b-phase2
make -C B test-b-phase3
make -C B test-b-phase4
make -C B test-b-phase5
make -C B test-b-filters
make -C B test-b-robustness

Or call scripts directly from B/tests/*.sh.

## Expected results

Use the checklist in /c.plan.md for precise expected observations.

## Tips

- Keep Wireshark/tshark open to cross‑verify a few packets.
- If IPv6 is unavailable, skip those steps; program should not crash.
- Ctrl+C stops capture and returns to menu; Ctrl+D exits from any prompt.
