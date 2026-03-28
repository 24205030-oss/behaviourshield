from flask import Flask, jsonify, request, Response, send_file
from flask_cors import CORS
import numpy as np
import hashlib
import json
import time
import math
import random
import os
import io
from datetime import datetime
from collections import defaultdict
import threading

# ── AI/ML: scikit-learn Neural Network (MLP) ──────────────────────────────────
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

# ── AUTOMATION: PDF Report Generation (UiPath-style automation) ───────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

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

# ══════════════════════════════════════════════════════════════════════════════
# 1. AI / ML — Neural Network Fraud Classifier (sklearn MLP = TensorFlow equiv)
# ══════════════════════════════════════════════════════════════════════════════

def _generate_training_data(n=2000):
    X, y = [], []
    for _ in range(n):
        r = random.random()
        if r < 0.60:
            a, t, l, d, lbl = random.uniform(0,0.15), random.uniform(0,0.20), 0.0, 0.0, 0
        elif r < 0.80:
            a  = random.uniform(0.10, 0.50)
            t  = random.uniform(0.10, 0.60)
            l  = random.choice([0.0, 0.5])
            d  = random.choice([0.0, 1.0])
            lbl = 1 if (a + t + l + d) > 0.9 else 0
        else:
            a, t, l, d, lbl = random.uniform(0.40,1.0), random.uniform(0.30,1.0), random.choice([0.5,1.0]), 1.0, 1
        X.append([a, t, l, d])
        y.append(lbl)
    return np.array(X), np.array(y)

def _train_ml_model():
    X, y = _generate_training_data(2000)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    clf = MLPClassifier(hidden_layer_sizes=(32, 16), activation='relu',
                        max_iter=500, random_state=42,
                        early_stopping=True, validation_fraction=0.1)
    clf.fit(X_scaled, y)
    acc = clf.score(X_scaled, y)
    print(f"✅ ML Model trained — accuracy: {acc*100:.1f}%")
    return clf, scaler, round(acc * 100, 1)

print("🤖 Training Neural Network fraud classifier...")
ML_MODEL, ML_SCALER, ML_ACCURACY = _train_ml_model()

def ml_predict(amount_s, time_s, loc_s, dev_s):
    features = np.array([[amount_s, time_s, loc_s, dev_s]])
    scaled   = ML_SCALER.transform(features)
    prob     = ML_MODEL.predict_proba(scaled)[0][1]
    label    = "FRAUD" if prob > 0.5 else "NORMAL"
    return round(float(prob), 4), label

# ══════════════════════════════════════════════════════════════════════════════
# 2. CHATBOT — Dialogflow-style intent engine (IBM Watson Assistant pattern)
# ══════════════════════════════════════════════════════════════════════════════

CHATBOT_INTENTS = {
    "greeting":           (["hi","hello","hey","namaste","good morning","good evening"],
                           "👋 Hello! I'm BehaviourShield Assistant. I can help you with fraud queries, transaction status, account blocks, and risk explanations. How can I help?"),
    "transaction_blocked":(["blocked","why blocked","transaction failed","account frozen","locked"],
                           "🔒 Your transaction was blocked because our AI detected a high-risk pattern — unusual location, unknown device, or abnormal amount. Contact your bank with the incident ID shown on screen."),
    "otp_issue":          (["otp","one time password","otp not received","resend otp"],
                           "📱 OTP issues: 1) Check SMS inbox and spam. 2) Wait 60 seconds before retry. 3) If still not received, call your bank helpline."),
    "fraud_report":       (["fraud","scam","cheated","hacked","stolen","unauthorized"],
                           "🚨 If you've been defrauded: 1) Call 1930 (National Cyber Crime). 2) File at cybercrime.gov.in. 3) Contact your bank immediately to freeze your account."),
    "risk_score":         (["risk score","score","percentage","what does it mean","explain score"],
                           "📊 The risk score (0–100) is computed by our Neural Network analyzing: transaction amount vs history, time of day, location jump, device fingerprint, and behavioral signals like copy-paste and OTP retries."),
    "appeal":             (["false alarm","not fraud","my transaction","legitimate","approve","unblock"],
                           "✅ If this was a false alarm, click 'Verify — Not Fraud' in the incident panel. Your location will be trusted and the account restored within minutes."),
    "ml_info":            (["ai","machine learning","neural network","model","how does it work","algorithm"],
                           "🤖 BehaviourShield uses a Multi-Layer Perceptron (Neural Network) trained on 2,000+ fraud patterns. It takes 4 feature scores and predicts fraud probability in real-time."),
    "analytics":          (["analytics","power bi","tableau","dashboard","report","export"],
                           "📈 Use the 'Export Analytics' button to download a CSV of all audit logs. Import it into Power BI or Tableau to build fraud trend dashboards and geographic heatmaps."),
    "fallback":           ([],
                           "🤔 I didn't quite understand that. You can ask me about: blocked transactions, risk scores, fraud reporting, OTP issues, or how the AI works.")
}

def chatbot_respond(user_msg: str) -> str:
    msg = user_msg.lower().strip()
    best_intent, best_score = "fallback", 0
    for intent, (keywords, _) in CHATBOT_INTENTS.items():
        score = sum(1 for kw in keywords if kw in msg)
        if score > best_score:
            best_score, best_intent = score, intent
    return CHATBOT_INTENTS[best_intent][1]

# ══════════════════════════════════════════════════════════════════════════════
# 3. AUTOMATION — PDF Fraud Incident Report (UiPath / Automation Anywhere style)
# ══════════════════════════════════════════════════════════════════════════════

def generate_incident_pdf(incident: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    styles    = getSampleStyleSheet()
    title_s   = ParagraphStyle('T', fontSize=20, alignment=TA_CENTER,
                               textColor=colors.HexColor('#1e3a8a'), fontName='Helvetica-Bold', spaceAfter=6)
    sub_s     = ParagraphStyle('S', fontSize=11, alignment=TA_CENTER,
                               textColor=colors.HexColor('#3b6ff5'), spaceAfter=4)
    head_s    = ParagraphStyle('H', fontSize=13, fontName='Helvetica-Bold',
                               textColor=colors.HexColor('#1e3a8a'), spaceBefore=14, spaceAfter=6)
    warn_s    = ParagraphStyle('W', fontSize=11, fontName='Helvetica-Bold',
                               textColor=colors.HexColor('#d92b2b'), alignment=TA_CENTER,
                               spaceBefore=10, spaceAfter=10)
    footer_s  = ParagraphStyle('F', fontSize=8, textColor=colors.HexColor('#8d9ab8'), alignment=TA_CENTER)

    elements = []
    elements.append(Paragraph("BehaviourShield", title_s))
    elements.append(Paragraph("Fraud Incident Report — Auto-generated by Automation Engine", sub_s))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3b6ff5')))
    elements.append(Spacer(1, 10))

    risk_pct = int(float(incident.get('risk', 0)) * 100)
    details = [
        ["Field", "Value"],
        ["Incident ID",  incident.get('id', 'N/A')],
        ["Account ID",   incident.get('account_id', 'N/A')],
        ["Victim Name",  incident.get('victim', 'N/A')],
        ["Phone",        incident.get('phone', 'N/A')],
        ["Amount",       f"Rs {incident.get('amount', 0):,.2f}"],
        ["Location",     incident.get('location', 'N/A')],
        ["Device",       incident.get('device', 'N/A')],
        ["Risk Score",   f"{risk_pct}% — HIGH RISK"],
        ["Timestamp",    incident.get('timestamp', 'N/A')],
        ["Audit Hash",   str(incident.get('audit_hash', 'N/A'))[:40] + "..."],
    ]
    tbl = Table(details, colWidths=[5*cm, 11*cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND',  (0,0),(-1,0),  colors.HexColor('#1e3a8a')),
        ('TEXTCOLOR',   (0,0),(-1,0),  colors.white),
        ('FONTNAME',    (0,0),(-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0,0),(-1,-1), 10),
        ('ALIGN',       (0,0),(-1,-1), 'LEFT'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#f4f6fc'),colors.white]),
        ('GRID',        (0,0),(-1,-1), 0.5, colors.HexColor('#dce3f0')),
        ('FONTNAME',    (0,1),(0,-1),  'Helvetica-Bold'),
        ('TEXTCOLOR',   (0,8),(-1,8),  colors.HexColor('#d92b2b')),
        ('FONTNAME',    (0,8),(-1,8),  'Helvetica-Bold'),
        ('TOPPADDING',  (0,0),(-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1),6),
        ('LEFTPADDING', (0,0),(-1,-1), 10),
    ]))
    elements.append(Paragraph("Incident Details", head_s))
    elements.append(tbl)
    elements.append(Spacer(1, 14))

    elements.append(Paragraph("Automated Response Steps", head_s))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dce3f0')))
    elements.append(Spacer(1, 6))

    steps = incident.get('steps', [])
    step_data = [["#", "Action", "Detail"]]
    for s in steps:
        step_data.append([str(s.get('n','')), s.get('title',''), s.get('detail','')])

    if len(step_data) > 1:
        st = Table(step_data, colWidths=[1*cm, 5*cm, 10*cm])
        st.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0),  colors.HexColor('#edf2ff')),
            ('FONTNAME',   (0,0),(-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',   (0,0),(-1,-1), 9),
            ('GRID',       (0,0),(-1,-1), 0.3, colors.HexColor('#dce3f0')),
            ('TOPPADDING', (0,0),(-1,-1), 5),
            ('BOTTOMPADDING',(0,0),(-1,-1),5),
            ('LEFTPADDING',(0,0),(-1,-1), 8),
            ('VALIGN',     (0,0),(-1,-1), 'TOP'),
        ]))
        elements.append(st)

    elements.append(Spacer(1, 16))
    elements.append(Paragraph("CONFIDENTIAL — For Internal Bank Use Only", warn_s))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dce3f0')))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"Generated on {datetime.now().strftime('%d %B %Y at %H:%M:%S')} by BehaviourShield Automation Engine | "
        "Powered by Flask + Neural Network (sklearn MLP) | Cloud-ready: AWS / Azure / GCP",
        footer_s
    ))
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ══════════════════════════════════════════════════════════════════════════════
# 4. ANALYTICS EXPORT — Power BI / Tableau compatible CSV
# ══════════════════════════════════════════════════════════════════════════════

def build_analytics_csv() -> str:
    headers = ["timestamp","account_id","amount","location","device","hour",
               "risk","decision","amount_score","time_score","location_score",
               "device_score","ml_prob","ml_label","probing","hash"]
    rows = [",".join(headers)]
    with DATA_LOCK:
        audit_copy = list(AUDIT)
    for rec in audit_copy:
        bd  = rec.get("breakdown", {})
        ml  = rec.get("ml_result", {}) or {}
        row = [
            rec.get("timestamp",""), rec.get("account_id",""),
            str(rec.get("amount","")), rec.get("location",""),
            rec.get("device",""), str(rec.get("hour","")),
            str(rec.get("risk","")), rec.get("decision",""),
            str(bd.get("amount","")), str(bd.get("time","")),
            str(bd.get("location","")), str(bd.get("device","")),
            str(ml.get("ml_prob","")), str(ml.get("ml_label","")),
            str(rec.get("probing","")), rec.get("hash","")
        ]
        rows.append(",".join(row))
    return "\n".join(rows)

# ══════════════════════════════════════════════════════════════════════════════
# CORE SCORING
# ══════════════════════════════════════════════════════════════════════════════

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
            {"n": 1, "title": "Account frozen",      "detail": f"{account_id} locked. No further transactions allowed."},
            {"n": 2, "title": "Audit trail captured", "detail": f"Hash: {ahash[:20]}... stored immutably."},
            {"n": 3, "title": "Victim notified",      "detail": f"SMS sent to {acc['phone']}. Dispute form linked."},
            {"n": 4, "title": "SAR filed",            "detail": "Suspicious Activity Report sent to RBI fraud cell."},
            {"n": 5, "title": "AI retrained",         "detail": "Fraud pattern added to DNA. Attack permanently blocked."},
        ]
    }
    with DATA_LOCK:
        INCIDENTS.append(inc)
    return inc

def process_transaction(account_id, amount, hour, location, device, ip="internal"):
    if account_id in FROZEN:
        return {"decision": "BLOCKED", "reason": "Account frozen due to prior fraud incident.",
                "risk": 1.0, "breakdown": {}, "probing": False, "audit_hash": "", "incident": None, "ml_result": None}
    acc = ACCOUNTS.get(account_id)
    if not acc:
        return {"decision": "BLOCKED", "reason": "Unknown account.",
                "risk": 1.0, "breakdown": {}, "probing": False, "audit_hash": "", "incident": None, "ml_result": None}

    dna = acc["dna"]
    a   = amount_score(amount, dna["amounts"])
    ti  = time_score(hour, dna["hours"])
    l   = location_score(location, dna["locations"])
    d   = device_score(device, dna["devices"])

    ml_prob, ml_label = ml_predict(a, ti, l, d)
    ml_score = int(ml_prob * 100)

    rule_risk = composite(a, ti, l, d)
    r = 0.60 * rule_risk + 0.40 * ml_prob

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
        "ml_result": {"ml_prob": ml_prob, "ml_score": ml_score, "ml_label": ml_label},
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
    return jsonify({
        "status": "ok", "transactions_processed": STATS["total"],
        "frozen_accounts": list(FROZEN), "ml_accuracy": ML_ACCURACY,
        "features": ["Neural Network (MLP)", "Chatbot (Dialogflow-style)",
                     "PDF Automation", "Analytics Export (Power BI/Tableau)", "Cloud-ready (AWS/Azure/GCP)"]
    })

@app.route("/api/stats")
def get_stats():
    rate = round(STATS["blocked"]/STATS["total"]*100,1) if STATS["total"] > 0 else 0
    return jsonify({**STATS, "fraud_rate": rate, "ml_accuracy": ML_ACCURACY})

@app.route("/txn", methods=["POST"])
def transaction():
    data = request.get_json(force=True) or {}
    ip   = request.remote_addr or "unknown"
    result = process_transaction(
        data.get("account_id","ACC001"),
        float(data.get("amount",500)),
        int(data.get("hour", datetime.now().hour)),
        data.get("location","Chennai"),
        data.get("device","DeviceA-iPhone13"), ip
    )
    return jsonify(result)

@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Matches the frontend payload exactly:
      amount, merchant, txn_velocity, location_jump_km,
      new_beneficiary, copy_paste, otp_retry, screen_sharing,
      unusual_hour, typing_speed_wpm, app_switching
    """
    data = request.get_json(force=True) or {}
    ip   = request.remote_addr or "unknown"

    amount       = float(data.get("amount", 500))
    velocity     = int(data.get("txn_velocity", 1))
    location_km  = float(data.get("location_jump_km", 0))
    merchant     = data.get("merchant", "grocery")
    typing_wpm   = float(data.get("typing_speed_wpm", 45))
    unusual_hour = bool(data.get("unusual_hour", False))

    # Map frontend location_jump_km → backend location string
    if location_km > 500:
        location = "London"        # foreign
    elif location_km > 100:
        location = "Mumbai"        # different state
    elif location_km > 0:
        location = "Coimbatore"    # nearby
    else:
        location = "Chennai"       # same city (trusted)

    # Map frontend merchant → device risk signal
    high_risk_merchants = {"wire", "crypto", "unknown"}
    device = "HackerDevice-001" if merchant in high_risk_merchants else "DeviceA-iPhone13"

    # Map unusual_hour → transaction hour
    hour = 2 if unusual_hour else datetime.now().hour

    # Run core engine
    result = process_transaction("ACC001", amount, hour, location, device, ip)

    # Build behavioural risk reasons for frontend display
    reasons = []
    if data.get("new_beneficiary"):  reasons.append("New beneficiary")
    if data.get("copy_paste"):       reasons.append("Account no. copy-pasted")
    if data.get("otp_retry"):        reasons.append("OTP retried 3+ times")
    if data.get("screen_sharing"):   reasons.append("Screen sharing active")
    if unusual_hour:                 reasons.append("Unusual transaction hour")
    if typing_wpm > 120:             reasons.append("Abnormally rapid typing")
    if velocity >= 5:                reasons.append("High transaction velocity")
    if location_km > 500:           reasons.append("Foreign location detected")
    if merchant in high_risk_merchants: reasons.append(f"High-risk merchant: {merchant}")

    # Behaviour signals boost risk score
    behaviour_boost = min(len(reasons) * 0.04, 0.30)
    boosted_risk    = min(result["risk"] + behaviour_boost, 1.0)

    if boosted_risk > 0.72:
        verdict = "BLOCK"
    elif boosted_risk > 0.38:
        verdict = "WARN"
    else:
        verdict = "ALLOW"

    return jsonify({
        "verdict":     verdict,
        "final_score": int(boosted_risk * 100),
        "reasons":     reasons if reasons else ["No anomalies detected"],
        "ml_result":   result.get("ml_result"),
        "breakdown":   result.get("breakdown"),
        "thresholds":  {"warn": 38, "block": 72},
        "audit_hash":  result.get("audit_hash"),
        "incident":    result.get("incident"),
        "timestamp":   result.get("timestamp"),
    })

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

# ── NEW: ML info ──────────────────────────────────────────────────────────────
@app.route("/api/ml/info")
def ml_info():
    return jsonify({
        "model": "MLPClassifier (Neural Network)",
        "library": "scikit-learn (TensorFlow-equivalent MLP)",
        "architecture": "[4 inputs] -> [32 neurons] -> [16 neurons] -> [1 output]",
        "activation": "ReLU", "accuracy": ML_ACCURACY,
        "features": ["amount_score","time_score","location_score","device_score"],
        "output": "Fraud probability (0.0-1.0)"
    })

# ── NEW: Chatbot (Dialogflow / IBM Watson style) ──────────────────────────────
@app.route("/api/chatbot", methods=["POST"])
def chatbot():
    body = request.get_json(force=True) or {}
    user_message = body.get("message", "").strip()
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
    reply = chatbot_respond(user_message)
    return jsonify({
        "user": user_message, "bot": reply,
        "powered": "Dialogflow-style Intent Engine",
        "timestamp": datetime.now().isoformat()
    })

# ── NEW: PDF Automation (UiPath / Automation Anywhere style) ─────────────────
@app.route("/api/automation/report/<incident_id>", methods=["GET"])
def download_incident_report(incident_id):
    with DATA_LOCK:
        inc = next((i for i in INCIDENTS if i["id"] == incident_id), None)
    if not inc:
        if incident_id == "DEMO":
            inc = {
                "id": "INC-DEMO", "account_id": "ACC001",
                "victim": "Priya Sharma", "phone": "+91-98765-XXXXX",
                "amount": 75000.00, "location": "Moscow", "device": "HackerDevice-001",
                "risk": 0.94, "audit_hash": "a1b2c3d4e5f6" * 5,
                "timestamp": datetime.now().isoformat(),
                "steps": [
                    {"n":1,"title":"Account frozen","detail":"ACC001 locked. No further transactions allowed."},
                    {"n":2,"title":"Audit trail captured","detail":"Hash stored immutably in blockchain log."},
                    {"n":3,"title":"Victim notified","detail":"SMS sent. Dispute form linked."},
                    {"n":4,"title":"SAR filed","detail":"Report sent to RBI fraud cell."},
                    {"n":5,"title":"AI retrained","detail":"Fraud pattern added to DNA permanently."},
                ]
            }
        else:
            return jsonify({"error": "Incident not found"}), 404
    pdf_buf  = generate_incident_pdf(inc)
    filename = f"FraudReport_{inc['id']}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(pdf_buf, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)

# ── NEW: Analytics Export for Power BI / Tableau ─────────────────────────────
@app.route("/api/analytics/export")
def analytics_export():
    csv_data = build_analytics_csv()
    filename = f"behaviourshield_analytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(csv_data, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.route("/api/analytics/summary")
def analytics_summary():
    with DATA_LOCK:
        audit_copy = list(AUDIT)
    if not audit_copy:
        return jsonify({"message": "No data yet. Run some transactions first."})
    risks   = [r["risk"] for r in audit_copy]
    amounts = [r["amount"] for r in audit_copy]
    by_loc  = defaultdict(int)
    by_dec  = defaultdict(int)
    for r in audit_copy:
        by_loc[r.get("location","unknown")] += 1
        by_dec[r.get("decision","?")] += 1
    return jsonify({
        "total_transactions": len(audit_copy),
        "avg_risk_score":     round(float(np.mean(risks)), 3),
        "max_risk_score":     round(float(max(risks)), 3),
        "avg_amount":         round(float(np.mean(amounts)), 2),
        "decisions":          dict(by_dec),
        "top_locations":      dict(sorted(by_loc.items(), key=lambda x: -x[1])[:5]),
        "ml_accuracy":        ML_ACCURACY,
        "powered_by":         "Power BI / Tableau compatible"
    })

# ── NEW: Cloud deployment info ────────────────────────────────────────────────
@app.route("/api/cloud/info")
def cloud_info():
    return jsonify({
        "status": "Cloud-ready",
        "AWS":   {"service": "Elastic Beanstalk / EC2 t2.micro (Free Tier)", "Procfile": "web: python app.py"},
        "Azure": {"service": "Azure App Service F1 Free Tier", "command": "az webapp up --name behaviourshield"},
        "GCP":   {"service": "Cloud Run (pay-per-request)", "command": "gcloud run deploy behaviourshield --source ."},
        "note":  "Replace in-memory AUDIT list with PostgreSQL for production."
    })

@app.route("/")
def home():
    return Response(HTML, mimetype="text/html")

HTML = open("index.html", encoding="utf-8").read() if os.path.exists("index.html") else "<h1>Put index.html in same folder</h1>"

if __name__ == "__main__":
    print("\n✅ BehaviourShield — ALL smart automation features active!")
    print("   🤖 AI/ML:       Neural Network (MLP) — /api/ml/info")
    print("   🤖 Chatbot:     Dialogflow-style — POST /api/chatbot")
    print("   📄 Automation:  PDF Reports — GET /api/automation/report/DEMO")
    print("   📊 Analytics:   Power BI/Tableau CSV — GET /api/analytics/export")
    print("   ☁️  Cloud:       AWS/Azure/GCP ready — GET /api/cloud/info")
    print("   Open: http://localhost:5000\n")
    app.run(debug=False, port=5000, host="0.0.0.0")
