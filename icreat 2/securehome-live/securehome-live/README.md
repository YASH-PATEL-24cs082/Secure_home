# SecureHome — Live Attack & Detection Platform

A small, self-contained platform for the **i Create** pitch. It runs Suricata as
an IDS on a network tap, catches a live attack against an IoT device, and shows
it on a terminal-style dashboard as it happens — exactly the *Camera → botnet C2
→ blocked* story from **secure-home-nine.vercel.app**, using the architecture the
team actually chose: **Architecture B (IDS + active response)**, not inline IPS.

> **One thing to edit:** `config.dhruv.env`. Every script, rule and the dashboard
> read their values from it. Fill it in, run setup, done.

---

## What it does

```
[ Kali attacker ] --\
                     >-- LAN 192.168.50.0/24 --[ SecureHome GW ]-- staged C2
[ ESP32 / camera ] --/                              |
                                          Suricata 7.x (tap, IDS)
                                                    | eve.json
                                          responder.py -> nftables drop (TTL)
                                                    | actions.jsonl
                                          server.py  -> live dashboard (SSE)
```

The dashboard drives a 5-stage pipeline that mirrors the site's animation:

**COMPROMISE → DETECT → LOG → RESPOND → ENFORCE**

| Stage | Fires when | Behind it |
|---|---|---|
| COMPROMISE | Mirai-pattern brute-force alert (ESP32) | Suricata threshold rule sid 9000002 |
| DETECT | C2 beacon alert on the tap | rule sid 9000003 (staged C2 in blocklist) |
| LOG | same event written to eve.json + dashboard | backend ingest |
| RESPOND | responder inserts nftables drop rule | `responder.py` |
| ENFORCE | 2nd+ beacon dropped at the router | nftables, matches "blocks 2nd connection onward" |

The TCP **port scan** is shown in the feed as early context — per the site it is
*not* one of the five stages (those are the C2-beacon lifecycle).

---

## Files

```
securehome-live/
├── config.dhruv.env          <-- THE ONLY FILE YOU EDIT (owner: Dhruv)
├── setup.sh                   one-time install + rule render + nftables
├── README.md                 this file
├── ATTACK_GUIDE.md           very detailed attack how-to
├── suricata/
│   ├── securehome.rules.tmpl  rule template (rendered by setup.sh)
│   └── datasets/c2_blocklist.csv
├── backend/
│   ├── server.py              dashboard backend (SSE, pipeline, sim mode)
│   ├── responder.py           active-response nftables daemon
│   └── requirements.txt
├── frontend/index.html        single-file live dashboard
├── attack/
│   ├── run_attack.sh          live attack orchestrator (narrated pauses)
│   ├── replay_demo.sh         pcap-replay fallback
│   └── mirai_creds.txt        Mirai default-credential list (hydra -C)
└── logs/                      eve.json, actions.jsonl, securehome.db
```

---

## Setup (gateway box — Ubuntu/Debian/Kali)

```bash
cd securehome-live
nano config.dhruv.env          # fill in interface, IPs, MACs, staged C2
sudo ./setup.sh                # installs suricata, hydra, nmap, flask, nftables…
```

`setup.sh` renders `suricata/securehome.rules` from the template with your
thresholds and staged C2 IP, adds that IP to the blocklist, and creates the
nftables table/chain for active response.

---

## Run — three modes

### Mode 1 — SIMULATION (zero infra, cannot fail) — *your safety net*
No Suricata, no attacker, no network. The backend replays a scripted attack so
the dashboard lights up end to end. **Rehearse on this; keep it ready as a
fallback on stage.**
```bash
python3 backend/server.py --sim
# open http://localhost:8080
```

### Mode 2 — PCAP REPLAY (deterministic, real Suricata)
Real detection, but from a captured pcap instead of a live attacker — repeatable
and immune to live-network hiccups.
```bash
# terminal 1
python3 backend/server.py
# terminal 2
sudo ./attack/replay_demo.sh attack/attack_demo.pcap
```

### Mode 3 — FULLY LIVE (the real thing)
```bash
# terminal 1 — Suricata on the tap
sudo suricata -i "$CAPTURE_IFACE" \
  -S suricata/securehome.rules -l logs/ \
  --set vars.address-groups.HOME_NET="[$HOME_NET]"

# terminal 2 — dashboard
python3 backend/server.py

# terminal 3 — active response  (--dry-run on a laptop that shouldn't touch nft)
sudo python3 backend/responder.py

# terminal 4 (on the Kali attacker box)
./attack/run_attack.sh
```
Open `http://<gateway-ip>:8080` on the projector.

---

## Pitch-day run sheet

1. **Before the room:** run Mode 1 (`--sim`) once end to end. Confirm all five
   stages go green and BLOCKED shows 2. This proves the dashboard on any laptop.
2. **Capture a pcap** during one clean Mode 3 rehearsal → `attack/attack_demo.pcap`.
   Now Mode 2 is a deterministic backup of the *real* detection.
3. **On stage, primary plan = Mode 3 (live).** Narrate each pause in
   `run_attack.sh`; point at the matching stage turning green.
4. **If live networking misbehaves:** drop to Mode 2 (pcap replay) — same real
   Suricata output. If the projector/laptop is all you have: Mode 1 (sim).
5. **Close on the metrics** (`ATTACK_GUIDE.md` §7): detection rate, block rate,
   and the separately-measured false-positive rate — the honest part judges
   respect.

**Have ready:** a backup screen-recording of the full run on your phone.

---

## Honesty notes (say these; they make the project stronger)

- Suricata here is on a **tap**, so the **first** C2 connection is *detected and
  logged*, and blocking starts from the **second** — this is Architecture B by
  design, not a limitation to hide.
- The Tuya camera is **cloud-bound** and exposes no login, so the brute-force
  runs against the **ESP32** (its deliberately-weak service). The camera is the
  beaconing/detection target. This matches the site's device roles.
- The "C2" is a **staged IP you control / an unrouted test IP** placed in the
  blocklist — never a real malicious host.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard empty in live mode | check `logs/eve.json` is growing; confirm `CAPTURE_IFACE` is right (`ip -br a`) |
| No alerts under attack | lower `SCAN_COUNT` / `BRUTE_COUNT` in config, re-run `setup.sh` |
| `nft` permission denied | run `responder.py` with `sudo`, or use `--dry-run` for a laptop demo |
| Suricata won't start | `sudo suricata -T -S suricata/securehome.rules` to test the config |
| Offload hiding packets | `sudo ethtool -K $CAPTURE_IFACE gro off lro off` |
```
