#!/usr/bin/env python3
"""
SecureHome live dashboard backend.

Reads Suricata's eve.json (alerts) and the responder's actions.jsonl (blocks),
turns them into readable events, drives the 5-stage attack pipeline
(COMPROMISE -> DETECT -> LOG -> RESPOND -> ENFORCE) and streams everything to
the browser over Server-Sent Events. No build step, no websockets.

Run:
    python3 server.py                 # live mode (reads Suricata output)
    python3 server.py --sim           # simulation mode (scripted demo, no infra)

Open http://<gateway>:8080/
"""

import os, sys, json, time, threading, queue, sqlite3, argparse
from pathlib import Path
from flask import Flask, Response, jsonify, send_from_directory

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FRONTEND = ROOT / "frontend"
LOGS = ROOT / "logs"
EVE = LOGS / "eve.json"
ACTIONS = LOGS / "actions.jsonl"
DB = LOGS / "securehome.db"

# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
def load_env(path):
    cfg = {}
    if not Path(path).exists():
        return cfg
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.strip()
    return cfg

CFG = load_env(ROOT / "config.dhruv.env")

def devices_from_cfg():
    d = {}
    for ipkey, namekey, mackey, kind in [
        ("CAMERA_IP", "CAMERA_NAME", "CAMERA_MAC", "camera"),
        ("ESP32_IP", "ESP32_NAME", "ESP32_MAC", "esp32"),
        ("PLUG_IP", "PLUG_NAME", "PLUG_MAC", "plug"),
        ("ATTACKER_IP", "ATTACKER_NAME", None, "attacker"),
        ("STAGED_C2_IP", None, None, "c2"),
    ]:
        ip = CFG.get(ipkey)
        if not ip:
            continue
        d[ip] = {
            "ip": ip,
            "name": CFG.get(namekey, kind.upper()) if namekey else ("Botnet C2" if kind == "c2" else kind),
            "mac": CFG.get(mackey, "") if mackey else "",
            "kind": kind,
        }
    return d

DEVICES = devices_from_cfg()

# 5 named stages, matching the SecureHome site's attack animation.
PIPELINE = ["COMPROMISE", "DETECT", "LOG", "RESPOND", "ENFORCE"]

# which Suricata SID advances which pipeline stage.
# Per the SecureHome site the 5 stages are the C2-beacon lifecycle; the port
# scan is early context in the feed but is NOT one of the 5 stages.
SID_STAGE = {
    9000002: "COMPROMISE",   # brute-force = the compromise itself
    9000003: "DETECT",       # C2 beacon detected on the tap
}

STATE = {
    "pipeline": {s: "idle" for s in PIPELINE},   # idle | active | done
    "stats": {"alerts": 0, "blocked": 0, "devices": len([d for d in DEVICES.values() if d["kind"] in ("camera","esp32","plug")])},
    "events": [],   # most recent first, capped
}

# --------------------------------------------------------------------------
# db
# --------------------------------------------------------------------------
def db_init():
    LOGS.mkdir(exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, kind TEXT, severity TEXT, stage TEXT,
        src TEXT, dst TEXT, src_name TEXT, dst_name TEXT,
        signature TEXT, sid INTEGER)""")
    con.commit()
    con.close()

def db_insert(ev):
    con = sqlite3.connect(DB)
    con.execute("""INSERT INTO events(ts,kind,severity,stage,src,dst,src_name,dst_name,signature,sid)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (ev["ts"], ev["kind"], ev["severity"], ev.get("stage",""),
                 ev.get("src",""), ev.get("dst",""), ev.get("src_name",""),
                 ev.get("dst_name",""), ev.get("signature",""), ev.get("sid",0)))
    con.commit()
    con.close()

# --------------------------------------------------------------------------
# event bus (SSE)
# --------------------------------------------------------------------------
subscribers = []
sub_lock = threading.Lock()

def publish(ev):
    STATE["events"].insert(0, ev)
    STATE["events"] = STATE["events"][:200]
    db_insert(ev)
    data = json.dumps({"type": "event", "event": ev, "state": public_state()})
    with sub_lock:
        for q in list(subscribers):
            q.put(data)

def public_state():
    return {"pipeline": STATE["pipeline"], "stats": STATE["stats"],
            "devices": list(DEVICES.values())}

def name_for(ip):
    return DEVICES.get(ip, {}).get("name", ip)

def advance(stage):
    if stage not in PIPELINE:
        return
    idx = PIPELINE.index(stage)
    for i, s in enumerate(PIPELINE):
        if i < idx and STATE["pipeline"][s] != "done":
            STATE["pipeline"][s] = "done"
        if i == idx and STATE["pipeline"][s] != "done":
            STATE["pipeline"][s] = "active"

# --------------------------------------------------------------------------
# ingest Suricata alerts
# --------------------------------------------------------------------------
def classify(sid, severity):
    if sid == 9000003:
        return "SUSPICIOUS"
    if sid in (9000001, 9000002):
        return "SUSPICIOUS"
    return "SAFE"

def handle_alert(obj):
    alert = obj.get("alert", {})
    sid = alert.get("signature_id", 0)
    sig = alert.get("signature", "alert")
    src = obj.get("src_ip", "")
    dst = obj.get("dest_ip", "")
    sev = alert.get("severity", 3)
    ev = {
        "ts": time.strftime("%H:%M:%S"),
        "kind": "alert",
        "severity": classify(sid, sev),
        "stage": SID_STAGE.get(sid, ""),
        "src": src, "dst": dst,
        "src_name": name_for(src), "dst_name": name_for(dst),
        "signature": sig, "sid": sid,
    }
    STATE["stats"]["alerts"] += 1
    stage = SID_STAGE.get(sid)
    if stage:
        advance(stage)
        if sid == 9000003:
            # C2 detected -> LOG follows immediately
            STATE["pipeline"]["DETECT"] = "done"
            STATE["pipeline"]["LOG"] = "done"
    publish(ev)

def handle_action(obj):
    # written by responder.py: {"action":"RESPOND"/"ENFORCE","dst":...}
    act = obj.get("action")
    dst = obj.get("dst", "")
    ev = {
        "ts": time.strftime("%H:%M:%S"),
        "kind": "action",
        "severity": "BLOCKED",
        "stage": act,
        "src": CFG.get("GATEWAY_IP",""), "dst": dst,
        "src_name": "SecureHome GW", "dst_name": name_for(dst),
        "signature": obj.get("msg", f"nftables {act}"),
        "sid": 0,
    }
    if act == "RESPOND":
        STATE["pipeline"]["RESPOND"] = "done"
        STATE["pipeline"]["ENFORCE"] = "active"
    if act == "ENFORCE":
        STATE["pipeline"]["ENFORCE"] = "done"
        STATE["stats"]["blocked"] += 1
    publish(ev)

def tail(path, on_line):
    """follow a growing json-lines file"""
    path = Path(path)
    while not path.exists():
        time.sleep(0.5)
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            on_line(obj)

def eve_worker():
    def on_line(obj):
        if obj.get("event_type") == "alert":
            handle_alert(obj)
    tail(EVE, on_line)

def actions_worker():
    tail(ACTIONS, handle_action)

# --------------------------------------------------------------------------
# simulation mode (no infra needed — for a guaranteed-working demo)
# --------------------------------------------------------------------------
def sim_worker():
    cam = CFG.get("CAMERA_IP","192.168.50.20")
    esp = CFG.get("ESP32_IP","192.168.50.30")
    atk = CFG.get("ATTACKER_IP","192.168.50.100")
    c2  = CFG.get("STAGED_C2_IP","192.168.50.200")
    time.sleep(2)
    script = [
        (0, lambda: handle_alert({"event_type":"alert","src_ip":atk,"dest_ip":cam,
            "alert":{"signature_id":9000001,"signature":"SECUREHOME Recon - TCP port scan detected","severity":2}})),
        (2.2, lambda: handle_alert({"event_type":"alert","src_ip":atk,"dest_ip":esp,
            "alert":{"signature_id":9000002,"signature":"SECUREHOME Compromise - Mirai-pattern brute-force on login service","severity":1}})),
        (2.5, lambda: handle_alert({"event_type":"alert","src_ip":esp,"dest_ip":c2,
            "alert":{"signature_id":9000003,"signature":"SECUREHOME C2 - Outbound beacon to blocklisted host","severity":1}})),
        (1.8, lambda: handle_action({"action":"RESPOND","dst":c2,"msg":"nftables drop rule added (TTL 120s)"})),
        (1.5, lambda: handle_action({"action":"ENFORCE","dst":c2,"msg":"2nd beacon dropped inline at router"})),
        (1.5, lambda: handle_action({"action":"ENFORCE","dst":c2,"msg":"3rd beacon dropped inline at router"})),
    ]
    for delay, fn in script:
        time.sleep(delay)
        fn()

# --------------------------------------------------------------------------
# flask app
# --------------------------------------------------------------------------
app = Flask(__name__)

@app.route("/")
def index():
    return send_from_directory(FRONTEND, "index.html")

@app.route("/api/state")
def api_state():
    return jsonify({"state": public_state(), "events": STATE["events"][:50],
                    "pipeline_order": PIPELINE})

@app.route("/stream")
def stream():
    q = queue.Queue()
    with sub_lock:
        subscribers.append(q)
    def gen():
        # prime the client with current state
        yield f"data: {json.dumps({'type':'state','state':public_state(),'events':STATE['events'][:50],'pipeline_order':PIPELINE})}\n\n"
        try:
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        finally:
            with sub_lock:
                if q in subscribers:
                    subscribers.remove(q)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sim", action="store_true", help="simulation mode (no Suricata needed)")
    args = ap.parse_args()
    db_init()
    if args.sim:
        print("[*] SIMULATION MODE — scripted demo, no live capture")
        threading.Thread(target=sim_worker, daemon=True).start()
    else:
        print(f"[*] LIVE MODE — tailing {EVE}")
        threading.Thread(target=eve_worker, daemon=True).start()
        threading.Thread(target=actions_worker, daemon=True).start()
    host = CFG.get("DASHBOARD_HOST", "0.0.0.0")
    port = int(CFG.get("DASHBOARD_PORT", "8080"))
    print(f"[*] Dashboard: http://{host}:{port}/")
    app.run(host=host, port=port, threaded=True)

if __name__ == "__main__":
    main()
