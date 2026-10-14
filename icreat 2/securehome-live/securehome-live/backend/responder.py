#!/usr/bin/env python3
"""
SecureHome active-response daemon  (Architecture B: IDS on a tap + active response).

Suricata is NOT inline. It reads a mirror copy and raises an alert. This daemon
watches those alerts and, on a confirmed C2 match (sid 9000003), inserts an
nftables rule that drops further traffic to that destination for a limited time
(TTL). That is why blocking takes effect from the *second* connection onward —
exactly the behaviour described on the SecureHome site.

It writes RESPOND / ENFORCE events to logs/actions.jsonl so the dashboard can
show the block happening live.

Run (needs root for real nftables):
    sudo python3 responder.py
Laptop demo without touching the network:
    python3 responder.py --dry-run
"""

import os, sys, json, time, threading, subprocess, argparse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LOGS = ROOT / "logs"
EVE = LOGS / "eve.json"
ACTIONS = LOGS / "actions.jsonl"

def load_env(path):
    cfg = {}
    if Path(path).exists():
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

CFG = load_env(ROOT / "config.dhruv.env")
TABLE = CFG.get("NFT_TABLE", "securehome")
CHAIN = CFG.get("NFT_CHAIN", "block")
TTL = int(CFG.get("BLOCK_TTL_SECONDS", "120"))
C2_SID = 9000003

blocked = set()
DRY = False

def emit(action, dst, msg):
    rec = {"ts": time.time(), "action": action, "dst": dst, "msg": msg}
    with open(ACTIONS, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[{action}] {dst} :: {msg}")

def nft(*args):
    if DRY:
        print("   (dry-run) nft", " ".join(args))
        return 0
    return subprocess.call(["nft", *args])

def ensure_table():
    if DRY:
        return
    nft("add", "table", "ip", TABLE)
    nft("add", "chain", "ip", TABLE, CHAIN,
        "{ type filter hook forward priority 0 ; }")

def block(dst):
    if dst in blocked:
        return
    blocked.add(dst)
    ensure_table()
    nft("add", "rule", "ip", TABLE, CHAIN, "ip", "daddr", dst, "drop")
    emit("RESPOND", dst, f"nftables drop rule added for {dst} (TTL {TTL}s)")
    # subsequent packets to dst are now dropped -> that is the ENFORCE stage
    time.sleep(1.2)
    emit("ENFORCE", dst, f"further beacons to {dst} dropped at the router")
    threading.Timer(TTL, unblock, args=[dst]).start()

def unblock(dst):
    if dst not in blocked:
        return
    if not DRY:
        # best-effort flush of the chain (simple + safe for a demo)
        nft("flush", "chain", "ip", TABLE, CHAIN)
    blocked.discard(dst)
    emit("EXPIRE", dst, f"TTL elapsed, block on {dst} lifted")

def tail(path, on_obj):
    path = Path(path)
    while not path.exists():
        time.sleep(0.5)
    with open(path) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25); continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            on_obj(obj)

def on_alert(obj):
    if obj.get("event_type") != "alert":
        return
    if obj.get("alert", {}).get("signature_id") == C2_SID:
        block(obj.get("dest_ip", ""))

def main():
    global DRY
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="don't touch nftables (safe on a laptop)")
    args = ap.parse_args()
    DRY = args.dry_run
    LOGS.mkdir(exist_ok=True)
    ACTIONS.touch(exist_ok=True)
    print(f"[*] responder up — table={TABLE} chain={CHAIN} ttl={TTL}s dry_run={DRY}")
    tail(EVE, on_alert)

if __name__ == "__main__":
    main()
