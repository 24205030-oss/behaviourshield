from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import numpy as np
import hashlib
import json
import time
import math
import random
import os
from datetime import datetime
from collections import defaultdict
import threading

app = Flask(__name__)
CORS(app)

# ── DATA ──────────────────────────────────────────────────────────────────────
ACCOUNTS = {
    "ACC001": {
        "name": "Priya Sharma",
        "phone": "+91-98765-XXXXX",
        "dna": {
            "amounts":   [450, 500, 520, 600, 480, 510, 490, 550, 475, 505],
            "hours":     [9, 10, 11, 10, 9, 14, 11, 10, 9, 10],
            "locations": {"Chennai": 9, "Coimbatore": 1},
            "devices":   {"DeviceA-iPhone13": 10},
        }
    }
}

AUDIT     = []
INCIDENTS = []
PROBE_LOG = defaultdict(list)
FROZEN    = set()
STATS     = {"approved": 0, "review": 0, "blocked": 0, "total": 0}
DATA_LOCK = threading.Lock()

SIM_LOCATIONS = ["Chennai", "Mumbai", "Delhi", "Bangalore", "Hyderabad",
                 "London", "New York", "Dubai", "Singapore", "Moscow"]
SIM_DEVICES   = ["DeviceA-iPhone13", "DeviceA-iPhone13", "DeviceA-iPhone13",
                 "HackerDevice-001", "NewDevice-Android"]

# ── SCORING ───────────────────────────────────────────────────────────────────
def amount_score(amount, hist):
    arr = sorted(hist)
    q1, q3 = np.percentile(arr, 25), np.percentile(arr, 75)
    iqr = max(q3 - q1, 1)
    return 0.0 if amount <= q3 + 1.5 * iqr else min((amount - q3) / (3 * iqr), 1.0)

def time_score(hour, hist):
    mean = np.mean(hist)
    std  = max(np.std(hist), 1)
    return min(abs(hour - mean) / (3 * std), 1.0)

def location_score(loc, known):
    return 0.0 if loc in known else 0.5

def device_score(dev, known):
    return 0.0 if dev in known else 1.0

def composite(a, t, l, d):
    device_known = (d == 0.0)
    loc_w = 0.5 if device_known else 1.0
    if not device_known and l > 0:
        l = min(l * 1.5, 1.0)
    z = 1.6*a + 0.9*t + 1.5*loc_w*l + 1.3*d - 2.4
    return 1 / (1 + math.exp(-z))

def is_probing(ip):
    now = time.time()
    PROBE_LOG[ip] = [t for t in PROBE_LOG[ip] if now - t < 300]
    PROBE_LOG[ip].append(now)
    return len(PROBE_LOG[ip]) >= 4

def add_audit(rec):
    with DATA_LOCK:
        prev = AUDIT[-1]["hash"] if AUDIT else "GENESIS"
        h = hashlib.sha256(
            (json.dumps(rec, default=str) + prev).encode()
        ).hexdigest()
        AUDIT.append({**rec, "hash": h})
    return h

def open_incident(account_id, txn, risk, ahash):
    acc = ACCOUNTS[account_id]
    FROZEN.add(account_id)
    inc = {
        "id":         f"INC-{int(time.time())}",
        "account_id": account_id,
        "victim":     acc["name"],
        "phone":      acc["phone"],
        "amount":     txn["amount"],
        "location":   txn["location"],
        "device":     txn["device"],
        "risk":       round(risk, 3),
        "audit_hash": ahash,
        "timestamp":  datetime.now().isoformat(),
        "steps": [
            {"n": 1, "title": "Account frozen",       "detail": f"{account_id} locked. No further transactions allowed."},
            {"n": 2, "title": "Audit trail captured",  "detail": f"Hash: {ahash[:20]}... stored immutably."},
            {"n": 3, "title": "Victim notified",       "detail": f"SMS sent to {acc['phone']}. Dispute form linked."},
            {"n": 4, "title": "SAR filed",             "detail": "Suspicious Activity Report sent to RBI fraud cell."},
            {"n": 5, "title": "AI retrained",          "detail": "Fraud pattern added to DNA. Attack permanently blocked."},
        ]
    }
    with DATA_LOCK:
        INCIDENTS.append(inc)
    return inc

def process_transaction(account_id, amount, hour, location, device, ip="internal"):
    if account_id in FROZEN:
        return {"decision": "BLOCKED", "reason": "Account frozen due to prior fraud incident.",
                "risk": 1.0, "breakdown": {}, "probing": False, "audit_hash": "", "incident": None}
    acc = ACCOUNTS.get(account_id)
    if not acc:
        return {"decision": "BLOCKED", "reason": "Unknown account.",
                "risk": 1.0, "breakdown": {}, "probing": False, "audit_hash": "", "incident": None}

    dna = acc["dna"]
    a   = amount_score(amount, dna["amounts"])
    ti  = time_score(hour, dna["hours"])
    l   = location_score(location, dna["locations"])
    d   = device_score(device, dna["devices"])
    r   = composite(a, ti, l, d)

    probing = is_probing(ip) if r > 0.35 else False

    if probing:
        decision, reason = "BLOCKED", "Systematic probing detected. IP flagged."
    elif r > 0.72:
        decision, reason = "BLOCKED", "High-risk transaction blocked. Fraud pattern matches DNA deviation."
    elif r > 0.38:
        decision, reason = "REVIEW",  "Unusual pattern detected. OTP challenge sent to registered phone."
    else:
        decision, reason = "APPROVED", "Transaction matches user DNA profile."

    rec = {
        "account_id": account_id, "amount": amount, "location": location,
        "device": device, "hour": hour, "risk": round(r, 3),
        "decision": decision, "reason": reason, "probing": probing,
        "breakdown": {"amount": round(a,3), "time": round(ti,3),
                      "location": round(l,3), "device": round(d,3)},
        "timestamp": datetime.now().isoformat()
    }
    ahash    = add_audit(rec)
    incident = None
    if decision == "BLOCKED" and not probing:
        incident = open_incident(account_id, rec, r, ahash)

    with DATA_LOCK:
        STATS["total"] += 1
        if decision == "APPROVED":   STATS["approved"] += 1
        elif decision == "REVIEW":   STATS["review"]   += 1
        else:                        STATS["blocked"]  += 1

    return {**rec, "audit_hash": ahash, "incident": incident}

def make_random_txn():
    r = random.random()
    if r < 0.60:
        return {"account_id":"ACC001","amount":round(random.uniform(300,700),2),
                "hour":random.choice([9,10,11,14]),"location":"Chennai","device":"DeviceA-iPhone13"}
    elif r < 0.85:
        return {"account_id":"ACC001","amount":round(random.uniform(1000,5000),2),
                "hour":random.randint(0,23),"location":random.choice(["Delhi","Mumbai","Bangalore"]),
                "device":random.choice(SIM_DEVICES)}
    else:
        return {"account_id":"ACC001","amount":round(random.uniform(10000,80000),2),
                "hour":random.randint(1,4),"location":random.choice(["London","New York","Moscow","Dubai"]),
                "device":"HackerDevice-001"}

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status":"ok","transactions_processed":STATS["total"],"frozen_accounts":list(FROZEN)})

@app.route("/api/stats")
def get_stats():
    rate = round(STATS["blocked"]/STATS["total"]*100,1) if STATS["total"] > 0 else 0
    return jsonify({**STATS, "fraud_rate": rate})

@app.route("/txn", methods=["POST"])
def transaction():
    data = request.get_json(force=True) or {}
    ip   = request.remote_addr or "unknown"
    result = process_transaction(
        data.get("account_id","ACC001"),
        float(data.get("amount",500)),
        int(data.get("hour", datetime.now().hour)),
        data.get("location","Chennai"),
        data.get("device","DeviceA-iPhone13"),
        ip
    )
    return jsonify(result)

@app.route("/api/simulate")
@app.route("/api/stream")
def simulate_one():
    txn    = make_random_txn()
    result = process_transaction(txn["account_id"],txn["amount"],txn["hour"],
                                 txn["location"],txn["device"],ip="simulator")
    return jsonify({"transaction":txn,"result":result,"timestamp":result["timestamp"]})

@app.route("/api/simulate/bulk", methods=["POST"])
def simulate_bulk():
    body  = request.get_json(force=True) or {}
    count = min(int(body.get("count",10)), 50)
    results = []
    for _ in range(count):
        txn    = make_random_txn()
        result = process_transaction(txn["account_id"],txn["amount"],txn["hour"],
                                     txn["location"],txn["device"],ip="simulator-bulk")
        results.append({"transaction":txn,"result":result,"timestamp":result["timestamp"]})
    return jsonify({"transactions":results,"count":len(results)})

@app.route("/confirm-otp", methods=["POST"])
def confirm_otp():
    body   = request.get_json(force=True) or {}
    acc_id = body.get("account_id")
    loc    = body.get("location")
    if acc_id and loc and acc_id in ACCOUNTS:
        ACCOUNTS[acc_id]["dna"]["locations"][loc] = \
            ACCOUNTS[acc_id]["dna"]["locations"].get(loc,0) + 1
    return jsonify({"status":"confirmed"})

@app.route("/api/fraud/report", methods=["POST"])
def fraud_report():
    body   = request.get_json(force=True) or {}
    action = body.get("action","unknown")
    steps  = []
    if action == "confirmed":
        steps = ["Card frozen (0-30s)","SAR filed to RBI",
                 "NPCI 30-min reversal activated","Device & IP blacklisted",
                 "Bank agent calling within 5 min"]
    elif action == "false_alarm":
        steps = ["Transaction verified legitimate","Account restored","False positive logged"]
    return jsonify({"action":action,"steps":steps,"timestamp":datetime.now().isoformat()})

@app.route("/incidents")
def get_incidents():
    return jsonify(INCIDENTS)

@app.route("/audit")
def get_audit():
    return jsonify(AUDIT)

@app.route("/dna/<account_id>")
def get_dna(account_id):
    acc = ACCOUNTS.get(account_id)
    return jsonify({"name":acc["name"],"dna":acc["dna"]}) if acc else (jsonify({"error":"Not found"}),404)

@app.route("/")
def home():
    return Response(HTML, mimetype="text/html")

HTML = open("index.html", encoding="utf-8").read() if os.path.exists("index.html") else "<h1>Put index.html in same folder</h1>"

if __name__ == "__main__":
    print("\n✅ BehaviourShield (Flask) running!")
    print("   Open: http://localhost:5000\n")
    app.run(debug=False, port=5000, host="0.0.0.0")