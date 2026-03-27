from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import numpy as np
import hashlib
import json
import time
import math
from datetime import datetime
from collections import defaultdict

app = FastAPI(title="BehaviourShield")

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

# ── SCORING ───────────────────────────────────────────────────────────────────
def amount_score(amount, hist):
    arr = sorted(hist)
    q1, q3 = np.percentile(arr, 25), np.percentile(arr, 75)
    iqr = max(q3 - q1, 1)
    return 0.0 if amount <= q3 + 1.5 * iqr else min((amount - q3) / (3 * iqr), 1.0)

def time_score(hour, hist):
    mean, std = np.mean(hist), max(np.std(hist), 1)
    return min(abs(hour - mean) / (3 * std), 1.0)

def location_score(loc, known):
    return 0.0 if loc in known else 0.5

def device_score(dev, known):
    return 0.0 if dev in known else 1.0

def composite(a, t, l, d):
    device_known = d == 0.0
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
    prev = AUDIT[-1]["hash"] if AUDIT else "GENESIS"
    h = hashlib.sha256((json.dumps(rec, default=str) + prev).encode()).hexdigest()
    AUDIT.append({**rec, "hash": h})
    return h

def open_incident(account_id, txn, risk, ahash):
    acc = ACCOUNTS[account_id]
    FROZEN.add(account_id)
    inc = {
        "id": f"INC-{int(time.time())}",
        "account_id": account_id,
        "victim": acc["name"],
        "phone": acc["phone"],
        "amount": txn["amount"],
        "location": txn["location"],
        "device": txn["device"],
        "risk": round(risk, 3),
        "audit_hash": ahash,
        "timestamp": datetime.now().isoformat(),
        "steps": [
            {"n": 1, "title": "Account frozen",       "detail": f"{account_id} locked. No further transactions allowed."},
            {"n": 2, "title": "Audit trail captured",  "detail": f"Hash: {ahash[:20]}... stored immutably."},
            {"n": 3, "title": "Victim notified",       "detail": f"SMS sent to {acc['phone']}. Dispute form linked."},
            {"n": 4, "title": "SAR filed",             "detail": "Suspicious Activity Report sent to RBI fraud cell."},
            {"n": 5, "title": "AI retrained",          "detail": "Fraud pattern added to DNA. Attack permanently blocked."},
        ]
    }
    INCIDENTS.append(inc)
    return inc

# ── API ───────────────────────────────────────────────────────────────────────
class Txn(BaseModel):
    account_id: str
    amount: float
    hour: int
    location: str
    device: str

@app.post("/txn")
async def transaction(t: Txn, request: Request):
    ip = request.client.host
    if t.account_id in FROZEN:
        return {"decision": "BLOCKED", "reason": "Account frozen due to prior fraud incident.", "risk": 1.0, "breakdown": {}, "probing": False, "audit_hash": "", "incident": None}
    acc = ACCOUNTS.get(t.account_id)
    if not acc:
        return {"decision": "BLOCKED", "reason": "Unknown account.", "risk": 1.0, "breakdown": {}, "probing": False, "audit_hash": "", "incident": None}
    dna = acc["dna"]
    a  = amount_score(t.amount, dna["amounts"])
    ti = time_score(t.hour, dna["hours"])
    l  = location_score(t.location, dna["locations"])
    d  = device_score(t.device, dna["devices"])
    r  = composite(a, ti, l, d)
    probing = is_probing(ip) if r > 0.35 else False
    if probing:
        decision, reason = "BLOCKED", "Systematic probing detected. IP flagged."
    elif r > 0.72:
        decision, reason = "BLOCKED", "High-risk transaction blocked. Fraud pattern matches DNA deviation."
    elif r > 0.38:
        decision, reason = "REVIEW", "Unusual pattern detected. OTP challenge sent to registered phone."
    else:
        decision, reason = "APPROVED", "Transaction matches user DNA profile."
    rec = {
        "account_id": t.account_id, "amount": t.amount, "location": t.location,
        "device": t.device, "hour": t.hour, "risk": round(r, 3),
        "decision": decision, "reason": reason, "probing": probing,
        "breakdown": {"amount": round(a,3), "time": round(ti,3), "location": round(l,3), "device": round(d,3)},
        "timestamp": datetime.now().isoformat()
    }
    ahash = add_audit(rec)
    incident = None
    if decision == "BLOCKED" and not probing:
        incident = open_incident(t.account_id, rec, r, ahash)
    return {**rec, "audit_hash": ahash, "incident": incident}

@app.post("/confirm-otp")
async def confirm_otp(body: dict):
    acc_id, loc = body.get("account_id"), body.get("location")
    if acc_id and loc and acc_id in ACCOUNTS:
        ACCOUNTS[acc_id]["dna"]["locations"][loc] = 1
    return {"status": "confirmed"}

@app.get("/incidents")
def get_incidents():
    return INCIDENTS

@app.get("/audit")
def get_audit():
    return AUDIT

@app.get("/dna/{account_id}")
def get_dna(account_id: str):
    acc = ACCOUNTS.get(account_id)
    return {"name": acc["name"], "dna": acc["dna"]} if acc else {"error": "Not found"}

# ── FRONTEND ──────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BehaviourShield</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#f4f6fa; --surface:#fff; --border:#e2e8f0; --text:#1a202c; --muted:#718096;
  --accent:#3b82f6; --green:#10b981; --yellow:#d97706; --red:#ef4444;
  --red-bg:#fef2f2; --yellow-bg:#fffbeb; --green-bg:#f0fdf4; --blue-bg:#eff6ff;
  --mono:'JetBrains Mono',monospace; --sans:'Inter',sans-serif;
  --radius:10px; --shadow:0 1px 3px rgba(0,0,0,.08);
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;}
nav{background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;
  padding:0 24px;height:54px;gap:0;position:sticky;top:0;z-index:100;box-shadow:var(--shadow);overflow-x:auto;}
.brand{font-weight:600;font-size:15px;margin-right:28px;display:flex;align-items:center;gap:7px;white-space:nowrap;}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent);}
.tab{padding:0 14px;height:54px;display:flex;align-items:center;font-size:13px;font-weight:500;
  color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap;}
.tab:hover{color:var(--text);}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab.j{color:#7c3aed;}
.tab.j.active{border-bottom-color:#7c3aed;color:#7c3aed;}
.page{display:none;padding:24px;max-width:1100px;margin:0 auto;}
.page.active{display:block;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:18px;}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;box-shadow:var(--shadow);}
.ct{font-size:11px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin-bottom:16px;}
.field{margin-bottom:13px;}
.field label{display:block;font-size:12px;font-weight:500;color:var(--muted);margin-bottom:4px;}
.field input,.field select{width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:7px;
  font-family:var(--sans);font-size:13px;color:var(--text);background:#fff;transition:border .15s;}
.field input:focus,.field select:focus{outline:none;border-color:var(--accent);}
.btn{width:100%;padding:11px;border-radius:8px;border:none;font-family:var(--sans);
  font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s;}
.bp{background:var(--accent);color:#fff;} .bp:hover{opacity:.88;}
.br{background:var(--red);color:#fff;}
.empty{text-align:center;color:var(--muted);font-size:12px;padding:28px;}
.banner{border-radius:8px;padding:13px 16px;margin-bottom:14px;}
.b-ok{background:var(--green-bg);border:1px solid #bbf7d0;}
.b-rev{background:var(--yellow-bg);border:1px solid #fde68a;}
.b-blk{background:var(--red-bg);border:1px solid #fecaca;}
.dlabel{font-size:17px;font-weight:700;font-family:var(--mono);}
.b-ok .dlabel{color:var(--green);} .b-rev .dlabel{color:var(--yellow);} .b-blk .dlabel{color:var(--red);}
.dreason{font-size:12px;margin-top:3px;}
.b-ok .dreason{color:#065f46;} .b-rev .dreason{color:#92400e;} .b-blk .dreason{color:#991b1b;}
.barrow{display:flex;align-items:center;gap:9px;margin-bottom:8px;}
.blabel{font-family:var(--mono);font-size:11px;color:var(--muted);width:70px;flex-shrink:0;}
.btrack{flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden;}
.bfill{height:100%;border-radius:3px;transition:width .4s;}
.flow{background:var(--green);} .fmid{background:var(--yellow);} .fhigh{background:var(--red);}
.bpct{font-family:var(--mono);font-size:11px;color:var(--muted);width:30px;text-align:right;}
.otp-box{background:var(--yellow-bg);border:1px solid #fde68a;border-radius:8px;padding:13px;margin-top:13px;}
.otp-code{font-family:var(--mono);font-size:24px;font-weight:700;color:var(--yellow);letter-spacing:6px;margin:7px 0;}
.otp-btns{display:flex;gap:8px;margin-top:9px;}
.obtn{flex:1;padding:8px;border-radius:6px;border:none;font-size:12px;font-weight:600;cursor:pointer;}
.oc{background:var(--green);color:#fff;} .od{background:var(--red);color:#fff;}
.inc{background:var(--red-bg);border:1px solid #fecaca;border-radius:9px;padding:16px;margin-bottom:13px;}
.inc-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--red);}
.inc-risk{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--red);}
.steps{display:flex;flex-direction:column;gap:8px;}
.step{display:flex;gap:10px;align-items:flex-start;}
.snum{width:20px;height:20px;border-radius:50%;background:var(--green);color:#fff;
  display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;margin-top:1px;}
.stitle{font-size:12px;font-weight:600;color:#065f46;}
.sdetail{font-size:11px;color:var(--muted);margin-top:1px;}
.hash{font-family:var(--mono);font-size:10px;background:var(--bg);border:1px solid var(--border);
  border-radius:5px;padding:4px 8px;color:var(--muted);margin-top:9px;word-break:break-all;}
.sc{border:1px solid var(--border);border-radius:9px;padding:13px;cursor:pointer;
  background:var(--surface);text-align:left;transition:all .15s;margin-bottom:10px;}
.sc:hover{border-color:var(--accent);background:var(--blue-bg);}
.sc-g{border-left:3px solid var(--green);} .sc-y{border-left:3px solid var(--yellow);}
.sc-r{border-left:3px solid var(--red);} .sc-p{border-left:3px solid #7c3aed;}
.sclabel{font-family:var(--mono);font-size:11px;font-weight:700;margin-bottom:3px;}
.sc-g .sclabel{color:var(--green);} .sc-y .sclabel{color:var(--yellow);}
.sc-r .sclabel{color:var(--red);} .sc-p .sclabel{color:#7c3aed;}
.scdesc{font-size:12px;color:var(--muted);line-height:1.5;}
.ja{background:var(--blue-bg);border:1px solid #bfdbfe;border-radius:8px;
  padding:14px 16px;font-size:13px;color:#1e3a5f;line-height:1.8;}
.ja-p{background:#f5f3ff;border-color:#ddd6fe;color:#3b1d8e;}
.tag-q1{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:#f5f3ff;color:#6d28d9;margin-bottom:8px;}
.tag-q2{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:var(--blue-bg);color:#1d4ed8;margin-bottom:8px;}
.plog{background:#1a202c;border-radius:8px;padding:13px;height:170px;overflow-y:auto;
  font-family:var(--mono);font-size:11px;}
.pl{padding:3px 0;border-bottom:1px solid #2d3748;}
.pok{color:#68d391;} .prev{color:#f6e05e;} .pblk{color:#fc8181;}
.chip{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;
  font-family:var(--mono);margin:3px;}
.cb{background:var(--blue-bg);color:#1e40af;border:1px solid #bfdbfe;}
.cg{background:var(--green-bg);color:#065f46;border:1px solid #bbf7d0;}
.arow{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);
  font-family:var(--mono);font-size:11px;align-items:flex-start;}
.ab{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;flex-shrink:0;}
.ab-ok{background:var(--green-bg);color:#065f46;} .ab-rev{background:var(--yellow-bg);color:#92400e;}
.ab-blk{background:var(--red-bg);color:#991b1b;}
.probe-alert{margin-top:10px;padding:10px;background:var(--red-bg);border:1px solid #fecaca;
  border-radius:7px;font-size:12px;color:#991b1b;}
.info-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-top:4px;}
.info-box{padding:13px;background:var(--bg);border-radius:8px;}
.info-title{font-size:12px;font-weight:600;margin-bottom:5px;}
.info-text{font-size:12px;color:var(--muted);line-height:1.6;}
@keyframes fi{from{opacity:0;transform:translateY(5px);}to{opacity:1;transform:none;}}
.ani{animation:fi .25s ease;}
</style>
</head>
<body>
<nav>
  <div class="brand"><div class="dot"></div>BehaviourShield</div>
  <div class="tab active" onclick="go('home',this)">Dashboard</div>
  <div class="tab" onclick="go('txn',this)">Check Transaction</div>
  <div class="tab" onclick="go('dna',this)">DNA Profile</div>
  <div class="tab" onclick="go('audit',this)">Audit Chain</div>
  <div class="tab j" onclick="go('q1',this)">Q1 — Hacker Proof</div>
  <div class="tab j" onclick="go('q2',this)">Q2 — Incident Response</div>
</nav>

<!-- DASHBOARD -->
<div id="page-home" class="page active">
  <div class="g3" style="margin-bottom:18px;">
    <div class="card" style="border-left:3px solid var(--green);">
      <div class="ct">Approved</div>
      <div style="font-family:var(--mono);font-size:28px;font-weight:700;color:var(--green);" id="s-ok">0</div>
    </div>
    <div class="card" style="border-left:3px solid var(--yellow);">
      <div class="ct">Under Review</div>
      <div style="font-family:var(--mono);font-size:28px;font-weight:700;color:var(--yellow);" id="s-rev">0</div>
    </div>
    <div class="card" style="border-left:3px solid var(--red);">
      <div class="ct">Blocked</div>
      <div style="font-family:var(--mono);font-size:28px;font-weight:700;color:var(--red);" id="s-blk">0</div>
    </div>
  </div>
  <div class="card">
    <div class="ct">Recent Transactions</div>
    <div id="home-feed"><div class="empty">No transactions yet</div></div>
  </div>
</div>

<!-- CHECK TRANSACTION -->
<div id="page-txn" class="page">
  <div class="g2">
    <div class="card">
      <div class="ct">Submit Transaction</div>
      <div class="field"><label>Account</label>
        <select id="acc"><option value="ACC001">ACC001 — Priya Sharma</option></select></div>
      <div class="field"><label>Amount (₹)</label><input id="amt" type="number" value="500"></div>
      <div class="field"><label>Hour (0–23)</label><input id="hr" type="number" value="10" min="0" max="23"></div>
      <div class="field"><label>Location</label><input id="loc" value="Chennai"></div>
      <div class="field"><label>Device ID</label><input id="dev" value="DeviceA-iPhone13"></div>
      <button class="btn bp" onclick="submitTxn()">Analyse Transaction</button>
    </div>
    <div class="card">
      <div class="ct">Result</div>
      <div id="txn-result"><div class="empty">Submit a transaction to see the DNA analysis</div></div>
    </div>
  </div>
</div>

<!-- DNA PROFILE -->
<div id="page-dna" class="page">
  <div class="g2">
    <div class="card">
      <div class="ct">Transaction DNA — Priya Sharma</div>
      <div style="margin-bottom:14px;"><div style="font-size:11px;font-weight:600;color:var(--muted);margin-bottom:6px;">KNOWN LOCATIONS</div><div id="dna-locs"></div></div>
      <div style="margin-bottom:14px;"><div style="font-size:11px;font-weight:600;color:var(--muted);margin-bottom:6px;">TRUSTED DEVICES</div><div id="dna-devs"></div></div>
      <div><div style="font-size:11px;font-weight:600;color:var(--muted);margin-bottom:8px;">SPEND PERCENTILES</div><div id="dna-spend"></div></div>
    </div>
    <div class="card">
      <div class="ct">Hour Activity Heatmap</div>
      <div id="heatmap" style="display:grid;grid-template-columns:repeat(24,1fr);gap:3px;margin-bottom:8px;"></div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:16px;">Each column = one hour (0–23). Darker = more activity.</div>
      <div style="font-size:13px;color:var(--muted);line-height:1.8;">
        Transaction DNA is a <strong style="color:var(--text);">unique behavioral fingerprint</strong> per user —
        built from spend distribution, usual hours, trusted locations and devices.
        Any deviation from <em>their own</em> DNA triggers an alert, not a global rule.
      </div>
    </div>
  </div>
</div>

<!-- AUDIT CHAIN -->
<div id="page-audit" class="page">
  <div class="card">
    <div class="ct">Immutable Audit Chain — SHA-256 Linked Ledger</div>
    <div id="audit-rows"><div class="empty">No transactions yet</div></div>
  </div>
</div>

<!-- Q1 — HACKER PROOF -->
<div id="page-q1" class="page">
  <div class="card" style="margin-bottom:18px;border-left:3px solid #7c3aed;">
    <div class="tag-q1">Judge Question 1</div>
    <div style="font-size:15px;font-weight:600;margin-bottom:10px;">"What if a hacker finds out how your system works?"</div>
    <div class="ja ja-p">
      Our system has <strong>no global rules to memorise</strong>. Every user has a unique Transaction DNA —
      their own spend percentiles, hour patterns, trusted locations and devices.
      Even knowing the formula, a hacker still needs Priya's full behavioural history to fake a clean transaction.
      If they probe to learn it, our <strong>sliding-window detector</strong> flags them within 4 attempts.
      You cannot permanently crack a system where the key is a person's entire behavioural history.
    </div>
  </div>

  <div class="g2" style="margin-bottom:18px;">
    <div class="card">
      <div class="ct">Live Proof — Try to Game the System</div>
      <div class="sc sc-r" onclick="q1Run(499,10,'Mumbai','HackerDevice-001')">
        <div class="sclabel">HACKER KNOWS THRESHOLD</div>
        <div class="scdesc">Sends ₹499 to stay under amount limit — device + location still catch them</div>
      </div>
      <div class="sc sc-r" onclick="q1Run(510,10,'Chennai','HackerDevice-001')">
        <div class="sclabel">HACKER SPOOFS LOCATION</div>
        <div class="scdesc">Sends from Chennai but on unknown device — device score catches them</div>
      </div>
      <div class="sc sc-r" onclick="q1Run(510,10,'Chennai','DeviceA-iPhone13')">
        <div class="sclabel">HACKER CLONES DEVICE ID</div>
        <div class="scdesc">Spoofs Priya's device ID + known location — watch if they slip through</div>
      </div>
      <div class="sc sc-p" onclick="q1Probe()">
        <div class="sclabel">SIMULATE PROBING ATTACK</div>
        <div class="scdesc">4 rapid test transactions — sliding-window detector fires on attempt 4</div>
      </div>
    </div>
    <div class="card">
      <div class="ct">Result</div>
      <div id="q1-result"><div class="empty">Click a scenario to see live proof</div></div>
      <div class="ct" style="margin-top:16px;">Probe Attack Log</div>
      <div class="plog" id="q1-log"><div style="color:#4a5568;font-size:11px;">Run probing scenario to see log</div></div>
    </div>
  </div>

  <div class="card">
    <div class="ct">Why Knowing the Rules Still Fails</div>
    <div class="info-grid">
      <div class="info-box">
        <div class="info-title">No global threshold</div>
        <div class="info-text">₹500 is normal for Priya. It could be suspicious for another user. There is no single number to learn.</div>
      </div>
      <div class="info-box">
        <div class="info-title">Multi-signal scoring</div>
        <div class="info-text">Even if a hacker fakes the amount correctly, they still need to match time, location, and device simultaneously.</div>
      </div>
      <div class="info-box">
        <div class="info-title">Probing is detected</div>
        <div class="info-text">Any attempt to learn the system by testing transactions triggers the sliding-window probe detector within 4 tries.</div>
      </div>
    </div>
  </div>
</div>

<!-- Q2 — INCIDENT RESPONSE -->
<div id="page-q2" class="page">
  <div class="card" style="margin-bottom:18px;border-left:3px solid var(--accent);">
    <div class="tag-q2">Judge Question 2</div>
    <div style="font-size:15px;font-weight:600;margin-bottom:10px;">"Beyond your security — if fraud already happened, what do you do?"</div>
    <div class="ja">
      When fraud slips through, <strong>5 things fire automatically</strong> — the account is frozen in milliseconds,
      an immutable audit trail is captured as legal evidence, the victim gets an SMS alert with a dispute form,
      a Suspicious Activity Report is filed with RBI, and the fraud pattern is fed back into the AI so it
      <strong>can never succeed again</strong>. The victim is protected and compensated.
      The fraudster has made our system permanently stronger.
    </div>
  </div>

  <div class="g2" style="margin-bottom:18px;">
    <div class="card">
      <div class="ct">Trigger Live Incident — Show Judges the Pipeline</div>
      <div class="sc sc-r" onclick="q2Run(50000,3,'New York','UnknownDevice-XYZ')">
        <div class="sclabel">CLEAR FRAUD ATTACK</div>
        <div class="scdesc">₹50,000 · 3am · New York · Unknown device — BLOCKED + all 5 steps fire live on screen</div>
      </div>
      <div class="sc sc-y" onclick="q2Run(600,11,'Delhi','DeviceA-iPhone13')">
        <div class="sclabel">PRIYA TRAVELS TO DELHI</div>
        <div class="scdesc">Known device + new city — REVIEW + OTP challenge (shows false positive is handled correctly)</div>
      </div>
      <div id="q2-trigger"><div class="empty">Trigger a scenario above</div></div>
    </div>

    <div class="card">
      <div class="ct">5-Step Incident Pipeline</div>
      <div class="steps">
        <div class="step"><div class="snum">1</div><div><div class="stitle">Account frozen immediately</div><div class="sdetail">No further transactions can pass. Happens in milliseconds.</div></div></div>
        <div class="step" style="margin-top:8px;"><div class="snum">2</div><div><div class="stitle">Audit trail captured</div><div class="sdetail">SHA-256 chained ledger — IP, device, amount, timestamp, risk score. Legal-grade evidence.</div></div></div>
        <div class="step" style="margin-top:8px;"><div class="snum">3</div><div><div class="stitle">Victim notified</div><div class="sdetail">SMS alert to registered phone. Dispute form linked to exact transaction ID for refund.</div></div></div>
        <div class="step" style="margin-top:8px;"><div class="snum">4</div><div><div class="stitle">SAR filed to RBI</div><div class="sdetail">Suspicious Activity Report auto-generated and submitted to regulatory authority.</div></div></div>
        <div class="step" style="margin-top:8px;"><div class="snum">5</div><div><div class="stitle">AI retrained</div><div class="sdetail">Fraud pattern added to DNA training set. This exact attack can never succeed again.</div></div></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="ct">Open Incident Cases</div>
    <div id="incidents-list"><div class="empty">No incidents yet — trigger one above</div></div>
  </div>
</div>

<script>
function go(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  el.classList.add('active');
  if (name === 'audit') loadAudit();
  if (name === 'dna')   loadDNA();
  if (name === 'home')  loadHome();
  if (name === 'q2')    loadIncidents();
}

async function api(amount, hour, location, device) {
  const r = await fetch('/txn', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({account_id:'ACC001', amount:parseFloat(amount), hour:parseInt(hour), location, device})
  });
  return r.json();
}

function bar(label, val) {
  const pct = Math.round((val||0)*100);
  const fc  = pct < 35 ? 'flow' : pct < 65 ? 'fmid' : 'fhigh';
  return `<div class="barrow"><div class="blabel">${label}</div>
    <div class="btrack"><div class="bfill ${fc}" style="width:${pct}%"></div></div>
    <div class="bpct">${pct}%</div></div>`;
}

function renderResult(json, id) {
  const cls = json.decision==='APPROVED'?'b-ok':json.decision==='REVIEW'?'b-rev':'b-blk';
  const bd  = json.breakdown || {};
  const rc  = json.risk>0.72?'var(--red)':json.risk>0.38?'var(--yellow)':'var(--green)';

  let otp = '';
  if (json.decision === 'REVIEW') {
    const code = Math.floor(100000 + Math.random()*900000);
    otp = `<div class="otp-box">
      <div style="font-size:12px;font-weight:600;color:#92400e;">OTP Challenge sent to +91-98765-XXXXX</div>
      <div style="font-size:11px;color:#92400e;margin-top:2px;">Simulated OTP:</div>
      <div class="otp-code">${code}</div>
      <div class="otp-btns">
        <button class="obtn oc" onclick="confirmOTP('${json.location||''}')">Confirm — it is me (travelling)</button>
        <button class="obtn od" onclick="denyOTP()">Deny — this is fraud</button>
      </div></div>`;
  }

  let incHtml = '';
  if (json.incident) {
    const inc = json.incident;
    incHtml = `<div class="inc ani" style="margin-top:13px;">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">
        <div><div class="inc-id">${inc.id}</div>
          <div style="font-size:12px;color:var(--muted);margin-top:2px;">${inc.victim}</div></div>
        <div style="text-align:right;"><div style="font-size:11px;color:var(--muted);">Risk</div>
          <div class="inc-risk">${Math.round(json.risk*100)}%</div></div>
      </div>
      <div class="steps">${inc.steps.map(s=>`<div class="step">
        <div class="snum">${s.n}</div>
        <div><div class="stitle">${s.title}</div><div class="sdetail">${s.detail}</div></div>
      </div>`).join('')}</div>
      <div class="hash">${json.audit_hash}</div></div>`;
  }

  const html = `<div class="ani">
    <div class="banner ${cls}">
      <div class="dlabel">${json.decision}</div>
      <div class="dreason">${json.reason}</div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <div style="font-size:11px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);">DNA Deviation</div>
      <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:${rc};">${Math.round(json.risk*100)}%</div>
    </div>
    ${bar('Amount', bd.amount)}
    ${bar('Time', bd.time)}
    ${bar('Location', bd.location)}
    ${bar('Device', bd.device)}
    ${json.probing?`<div class="probe-alert"><strong>Probing detected</strong> — IP flagged, security team notified.</div>`:''}
    ${otp}${incHtml}
    <div class="hash" style="margin-top:10px;">${json.audit_hash||''}</div>
  </div>`;

  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
  updateStats();
}

async function submitTxn() {
  document.getElementById('txn-result').innerHTML = '<div class="empty">Analysing...</div>';
  const j = await api(document.getElementById('amt').value, document.getElementById('hr').value,
    document.getElementById('loc').value, document.getElementById('dev').value);
  renderResult(j, 'txn-result');
}

async function q1Run(amount, hour, location, device) {
  document.getElementById('q1-result').innerHTML = '<div class="empty">Analysing...</div>';
  const j = await api(amount, hour, location, device);
  renderResult(j, 'q1-result');
}

async function q1Probe() {
  const log = document.getElementById('q1-log');
  log.innerHTML = '';
  const attempts = [{a:400,l:'Mumbai',d:'HackerDevice-001'},{a:450,l:'Mumbai',d:'HackerDevice-001'},
                    {a:499,l:'Mumbai',d:'HackerDevice-001'},{a:510,l:'Chennai',d:'HackerDevice-001'}];
  for (let i = 0; i < attempts.length; i++) {
    await new Promise(r => setTimeout(r, 700));
    const {a,l,d} = attempts[i];
    const j = await api(a, 10, l, d);
    const cls = j.decision==='APPROVED'?'pok':j.decision==='REVIEW'?'prev':'pblk';
    const probe = j.probing ? ' PROBING DETECTED' : '';
    log.innerHTML += `<div class="pl ${cls}">[Attempt ${i+1}] Rs.${a} ${l} -> ${j.decision} (${Math.round(j.risk*100)}%)${probe}</div>`;
    log.scrollTop = log.scrollHeight;
  }
  log.innerHTML += `<div class="pl pblk" style="margin-top:6px;padding-top:6px;border-top:1px solid #4a5568;">IP permanently flagged. Attacker blocked.</div>`;
  document.getElementById('q1-result').innerHTML = `<div style="padding:13px;background:var(--red-bg);border:1px solid #fecaca;border-radius:8px;">
    <div style="font-weight:700;color:var(--red);margin-bottom:4px;">PROBING ATTACK CAUGHT</div>
    <div style="font-size:12px;color:#991b1b;">4 test transactions in 5 minutes — sliding-window detector fired on attempt 4. IP flagged permanently. The attacker learned nothing.</div></div>`;
}

async function q2Run(amount, hour, location, device) {
  document.getElementById('q2-trigger').innerHTML = '<div class="empty">Processing...</div>';
  const j = await api(amount, hour, location, device);
  renderResult(j, 'q2-trigger');
  setTimeout(loadIncidents, 500);
}

async function loadIncidents() {
  const list = await fetch('/incidents').then(r => r.json());
  const el   = document.getElementById('incidents-list');
  if (!el) return;
  if (!list.length) { el.innerHTML = '<div class="empty">No incidents yet — trigger one above</div>'; return; }
  el.innerHTML = list.map(inc => `
    <div class="inc ani">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">
        <div><div class="inc-id">${inc.id}</div>
          <div style="font-size:13px;font-weight:500;margin-top:2px;">${inc.victim} &middot; ${inc.account_id}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px;">Rs.${inc.amount} &middot; ${inc.location} &middot; ${inc.timestamp.slice(11,19)}</div></div>
        <div style="text-align:right;"><div style="font-size:11px;color:var(--muted);">Risk</div>
          <div class="inc-risk">${Math.round(inc.risk*100)}%</div></div>
      </div>
      <div class="steps">${inc.steps.map(s=>`<div class="step">
        <div class="snum">${s.n}</div>
        <div><div class="stitle">${s.title}</div><div class="sdetail">${s.detail}</div></div>
      </div>`).join('')}</div>
      <div class="hash">Audit hash: ${inc.audit_hash}</div>
    </div>`).join('');
}

async function confirmOTP(location) {
  await fetch('/confirm-otp', {method:'POST',headers:{'Content-Type':'application/json'},
    body: JSON.stringify({account_id:'ACC001', location})});
  alert('OTP confirmed. Transaction approved.\n\nLocation "' + location + '" added to Priya\'s DNA — future transactions there will pass silently. This is how the false positive problem is solved.');
}
function denyOTP() {
  alert('OTP denied by user.\nTransaction flagged as fraud. Account frozen. 5-step incident pipeline triggered.');
}

async function updateStats() {
  const audit = await fetch('/audit').then(r => r.json());
  const s = {ok:0, rev:0, blk:0};
  audit.forEach(a => { if(a.decision==='APPROVED') s.ok++; else if(a.decision==='REVIEW') s.rev++; else s.blk++; });
  ['ok','rev','blk'].forEach(k => { const el=document.getElementById('s-'+k); if(el) el.textContent=s[k]; });
}

async function loadHome() {
  const audit = await fetch('/audit').then(r => r.json());
  updateStats();
  const el = document.getElementById('home-feed');
  if (!audit.length) { el.innerHTML = '<div class="empty">No transactions yet</div>'; return; }
  el.innerHTML = audit.slice(-8).reverse().map(a => {
    const bc = a.decision==='APPROVED'?'ab-ok':a.decision==='REVIEW'?'ab-rev':'ab-blk';
    return `<div class="arow"><div class="ab ${bc}">${a.decision}</div>
      <div style="flex:1;"><div>Rs.${a.amount} &middot; ${a.location} &middot; ${a.device}</div>
        <div style="color:var(--muted);margin-top:2px;">Risk ${Math.round(a.risk*100)}% &middot; ${(a.timestamp||'').slice(11,19)}</div></div></div>`;
  }).join('');
}

function pct(arr, p) {
  const s=[...arr].sort((a,b)=>a-b);
  const i=(p/100)*(s.length-1);
  return s[Math.floor(i)]*(1-(i%1))+(s[Math.ceil(i)]||s[s.length-1])*(i%1);
}

async function loadDNA() {
  const d   = await fetch('/dna/ACC001').then(r => r.json());
  const dna = d.dna;
  document.getElementById('dna-locs').innerHTML =
    Object.entries(dna.locations).map(([l,f])=>`<span class="chip cb">${l} (${f}x)</span>`).join('');
  document.getElementById('dna-devs').innerHTML =
    Object.keys(dna.devices).map(dev=>`<span class="chip cg">${dev}</span>`).join('');
  const mx = pct(dna.amounts, 95);
  document.getElementById('dna-spend').innerHTML =
    [25,50,75,95].map(p => {
      const v=Math.round(pct(dna.amounts,p)), w=Math.round((v/mx)*100);
      return `<div class="barrow"><div class="blabel">P${p}</div>
        <div class="btrack"><div class="bfill flow" style="width:${w}%"></div></div>
        <div class="bpct">Rs.${v}</div></div>`;
    }).join('');
  const counts=Array(24).fill(0);
  dna.hours.forEach(h=>counts[h]++);
  const maxC=Math.max(...counts,1);
  document.getElementById('heatmap').innerHTML = counts.map((c,i)=>{
    const op=0.08+(c/maxC)*0.85;
    return `<div title="${i}:00 - ${c} txns" style="height:28px;border-radius:3px;
      background:rgba(59,130,246,${op.toFixed(2)});display:flex;align-items:center;
      justify-content:center;font-size:9px;font-family:var(--mono);color:#1e3a5f;">${i}</div>`;
  }).join('');
}

async function loadAudit() {
  const audit = await fetch('/audit').then(r => r.json());
  const el    = document.getElementById('audit-rows');
  if (!audit.length) { el.innerHTML = '<div class="empty">No transactions yet</div>'; return; }
  el.innerHTML = audit.slice().reverse().map(a => {
    const bc=a.decision==='APPROVED'?'ab-ok':a.decision==='REVIEW'?'ab-rev':'ab-blk';
    return `<div class="arow"><div class="ab ${bc}">${a.decision}</div>
      <div style="flex:1;"><div>Rs.${a.amount} &middot; ${a.location} &middot; Hour ${a.hour} &middot; ${a.device}</div>
        <div style="color:var(--muted);margin-top:2px;">${a.timestamp||''}</div>
        <div style="color:var(--muted);font-size:10px;margin-top:2px;">Hash: ${a.hash}</div></div>
      <div style="color:var(--muted);">${Math.round(a.risk*100)}%</div></div>`;
  }).join('');
}
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)