#!/usr/bin/env bash
# ===========================================================================
#  SecureHome — one-time setup on the GATEWAY box (Ubuntu/Debian/Kali)
#  Run:  sudo ./setup.sh
# ===========================================================================
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
set -a; source "$HERE/config.dhruv.env"; set +a

echo "[*] Installing packages…"
apt-get update -y
apt-get install -y suricata tcpreplay nmap hydra tcpdump python3-pip nftables curl
pip3 install --break-system-packages -r "$HERE/backend/requirements.txt" || \
  pip3 install -r "$HERE/backend/requirements.txt"

echo "[*] Rendering detection rules from template…"
export SCAN_COUNT SCAN_SECONDS BRUTE_COUNT BRUTE_SECONDS BRUTEFORCE_PORT STAGED_C2_IP
envsubst < "$HERE/suricata/securehome.rules.tmpl" > "$HERE/suricata/securehome.rules"
echo "    -> suricata/securehome.rules"

echo "[*] Adding staged C2 to blocklist dataset…"
grep -qxF "$STAGED_C2_IP" "$HERE/suricata/datasets/c2_blocklist.csv" 2>/dev/null || \
  echo "$STAGED_C2_IP" >> "$HERE/suricata/datasets/c2_blocklist.csv"

echo "[*] Preparing logs dir…"
mkdir -p "$HERE/logs"
: > "$HERE/logs/actions.jsonl"

echo "[*] Setting up nftables table/chain for active response…"
nft add table ip "$NFT_TABLE" 2>/dev/null || true
nft add chain ip "$NFT_TABLE" "$NFT_CHAIN" '{ type filter hook forward priority 0 ; }' 2>/dev/null || true

cat <<EOF

[✓] Setup complete.

Capture interface : $CAPTURE_IFACE
HOME_NET          : $HOME_NET
Staged C2         : $STAGED_C2_IP
Brute-force target: $BRUTEFORCE_TARGET ($BRUTEFORCE_SERVICE/$BRUTEFORCE_PORT)

Next: see README.md  ->  "Pitch-day run sheet"
EOF
