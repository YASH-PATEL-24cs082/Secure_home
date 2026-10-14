#!/usr/bin/env bash
# ===========================================================================
#  SecureHome — tear the lab DOWN, or just RESET between rehearsals.
#    sudo ./lab-down.sh          # remove namespaces, bridge, listeners
#    sudo ./lab-down.sh reset    # keep the lab, just clear logs + firewall
# ===========================================================================
set -u
if [ "$(id -u)" -ne 0 ]; then echo "run as root"; exit 1; fi
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "reset" ]; then
  echo "[*] resetting for a clean run…"
  nft flush table ip securehome 2>/dev/null || true
  : > "$HERE/logs/actions.jsonl"
  # fresh eve.json: only safe to remove while Suricata is stopped
  rm -f "$HERE/logs/eve.json"
  echo "[✓] cleared nftables + actions.jsonl + eve.json."
  echo "    (restart Suricata so it recreates a fresh eve.json)"
  exit 0
fi

echo "[*] tearing lab down…"
for ns in attacker iot c2; do ip netns del "$ns" 2>/dev/null; done
ip link del br-securehome 2>/dev/null
pkill -f "http.server 80" 2>/dev/null
nft delete table ip securehome 2>/dev/null || true
echo "[✓] lab removed."
