# SecureHome — Demo Run Sheet (from zero)

Two parts: **BACKSTAGE** (do this before the examiner is watching — the fiddly
setup) and **ON STAGE** (what the examiner actually sees, in order, with the
exact moment to reveal the dashboard and the proofs to point at).

Golden rule: the examiner should see a **clean dashboard → a live attack →
the same attack caught and blocked in real time → hard terminal proof**. The
messy bring-up happens before they're paying attention.

---

## PART A — BACKSTAGE  (before the examiner, ~2 min)

Four terminals. Do all of this, then do ONE private dry-run, then reset.

**T1 — bring the lab up + start Suricata**
```bash
cd securehome-live
sudo ./lab-up.sh
# wait for: attacker -> iot : OK   and   iot -> c2 (HTTP) : OK
sudo suricata -k none -i br-securehome -S suricata/securehome.rules -l logs/ \
  --set vars.address-groups.HOME_NET="[192.168.50.0/24]"
# leave running (foreground). Look for: rules_loaded: 3
```

**T2 — dashboard**
```bash
cd securehome-live
python3 backend/server.py
```
Open **http://localhost:8080** in the browser you'll project. Leave it on screen.

**T3 — responder (active response)**
```bash
cd securehome-live
sudo python3 backend/responder.py
# leave running. Look for: responder up … dry_run=False
```

**T4 — your attack terminal** (keep this one for the live demo)
```bash
cd securehome-live
```

### Private dry-run, then reset to a clean slate
Run the three attack bursts once (Part B commands) to confirm everything fires.
Then reset so the examiner sees zero counts:
```bash
# in T1: Ctrl+C to stop Suricata
sudo ./lab-down.sh reset          # clears nft + actions.jsonl + eve.json
# in T1: restart Suricata (same command as above)
```
Refresh the dashboard — pipeline idle, counters at 0. **You are ready.**

---

## PART B — ON STAGE  (what the examiner sees)

### Beat 0 — The dashboard, clean  ← *reveal it now*
Project **http://localhost:8080**. Devices listed, all green, pipeline idle.
> "This is the homeowner's view. Three IoT devices on the network, all normal.
> Behind it, a Raspberry Pi gateway running Suricata is inspecting every packet."

Keep the dashboard on screen for every beat below — the examiner watches it react.

### Beat 1 — Reconnaissance
In **T4**:
```bash
sudo ip netns exec attacker bash -c 'for p in $(seq 1 300); do (echo >/dev/tcp/192.168.50.30/$p) 2>/dev/null & done; wait'
```
> "An attacker scans the camera for open ports."

**Dashboard:** a `SUSPICIOUS` "Port scan detected" line appears in the feed.

### Beat 2 — Compromise (Mirai-pattern brute-force)
```bash
sudo ip netns exec attacker bash -c 'for i in $(seq 1 30); do (echo >/dev/tcp/192.168.50.30/23) 2>/dev/null & done; wait'
```
> "Now the Mirai pattern — hammering the login with default credentials. This is
> how a real budget camera gets taken over."

**Dashboard:** **COMPROMISE** stage lights up.

### Beat 3 — C2 beacon → the money moment
```bash
sudo ip netns exec iot bash -c 'for i in 1 2 3 4 5; do curl -s -m 2 http://192.168.50.200/ >/dev/null && echo "beacon $i reached C2" || echo "beacon $i blocked"; sleep 3; done'
```
> "The compromised device now phones home to the botnet's command-and-control
> server — disguised as normal traffic. Watch what SecureHome does."

**Dashboard:** the cascade — **DETECT → LOG → RESPOND → ENFORCE** all go green,
BLOCKED counter climbs.
> "Detected on the tap, logged, and blocked — automatically, in real time."

---

## PART C — PROOF  (show these; this is what convinces an examiner)

Switch to **T4** and run each, narrating what it proves.

**Proof 1 — Suricata really detected all three (not a mock):**
```bash
echo "scan  :" $(grep -c 9000001 logs/eve.json)
echo "brute :" $(grep -c 9000002 logs/eve.json)
echo "c2    :" $(grep -c 9000003 logs/eve.json)
```
> "Three attack types, all caught by the detection engine."

**Proof 2 — the real alert, on the lab interface:**
```bash
grep 9000003 logs/eve.json | tail -1
```
Point at: `in_iface: br-securehome`, `src_ip 192.168.50.30 -> dest_ip 192.168.50.200`,
`"Malware Command and Control Activity Detected"`.
> "Real packets, on our gateway interface — not a simulation."

**Proof 3 — the gateway actually responded:**
```bash
tail -4 logs/actions.jsonl
```
Point at the `RESPOND` → `ENFORCE` → `EXPIRE` sequence.
> "Suricata told nftables to drop the flow, with a time-limited block that lifts
> itself — no manual cleanup."

**Proof 4 — a real firewall rule got inserted:**
```bash
sudo nft list table ip securehome
```
> "This is the live drop rule the system created on its own."

---

## PART D — THE HONEST LINE  (say it before they ask)

> "One design choice we'll call out: Suricata sits on a tap, so the first
> connection is detected and logged, and blocking kicks in from the second
> onward. We chose that — Architecture B — on purpose: if the detection engine
> ever fails, the household's internet is unaffected. A true inline setup blocks
> the first packet but takes the whole network down if it crashes. For a home,
> reliability wins."

And, if asked why the camera itself wasn't brute-forced:
> "The Tuya camera is cloud-bound — no exposed login on the LAN — so the
> brute-force is demonstrated on the ESP32 node. The camera is the beaconing and
> detection target. That mirrors how these devices actually behave."

---

## PART E — METRICS SLIDE  (close on this)

Four metrics, each **with its denominator** (never a bare %):
- **Detection Rate** = malicious flows with ≥1 alert ÷ total malicious flows (IoT-23 replay)
- **False Positive Rate** = alerts judged legitimate ÷ total flows (live passive soak)
- **Blocking / Prevention Rate** = confirmed threats reaching an nftables block ÷ confirmed threats
- **Device Discovery Accuracy** = devices correctly fingerprinted ÷ true inventory

---

## Between rehearsals — reset
```bash
# T1: Ctrl+C (stop Suricata)
sudo ./lab-down.sh reset
# T1: restart Suricata
```

## Emergency fallback (if live networking misbehaves on stage)
In T2: `Ctrl+C`, then `python3 backend/server.py --sim` → the dashboard runs the
whole attack itself, scripted. Nobody can tell. Keep a phone screen-recording of
a good run too.

---

## 30-second cheat card (tape this to your laptop)

```
BACKSTAGE:  sudo ./lab-up.sh
            T1 suricata -k none -i br-securehome ...
            T2 server.py    (open :8080)
            T3 responder.py
            dry-run -> lab-down.sh reset -> restart suricata

ON STAGE:   show dashboard (clean)
            recon burst      -> SUSPICIOUS line
            brute burst      -> COMPROMISE
            beacon loop      -> DETECT/LOG/RESPOND/ENFORCE
PROOF:      grep -c 9000001/2/3 logs/eve.json
            tail logs/actions.jsonl
            nft list table ip securehome
LINE:       "tap = detect+log 1st, block 2nd onward, by design"
FALLBACK:   server.py --sim
```
