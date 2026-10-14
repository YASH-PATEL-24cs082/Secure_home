#!/usr/bin/env bash
# ===========================================================================
#  SecureHome — PCAP REPLAY fallback
#  Feeds a previously-captured attack pcap back through Suricata so the
#  dashboard lights up deterministically, even with no live attacker.
#
#  How to make the pcap (once, during a good live run):
#     sudo tcpdump -i "$CAPTURE_IFACE" -w attack/attack_demo.pcap
#     ...run run_attack.sh... then Ctrl-C the tcpdump.
# ===========================================================================
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
set -a; source "$HERE/../config.dhruv.env"; set +a
LOGS="$HERE/../logs"
PCAP="${1:-$HERE/attack_demo.pcap}"

if [ ! -f "$PCAP" ]; then
  echo "pcap not found: $PCAP"
  echo "Either capture one (see header) or use the backend's --sim mode instead."
  exit 1
fi

echo "[*] Replaying $PCAP through Suricata -> $LOGS/eve.json"
sudo suricata -r "$PCAP" \
  -S "$HERE/../suricata/securehome.rules" \
  -l "$LOGS" \
  --set vars.address-groups.HOME_NET="[$HOME_NET]"
echo "[*] Done. eve.json regenerated; dashboard will have shown the events."
