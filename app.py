from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
import random
import time
import json
import os
from datetime import datetime
from collections import defaultdict
import threading

# ── ML imports ──────────────────────────────────────────────────────────────
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  scikit-learn not installed. Run: pip install scikit-learn numpy")

app = Flask(__name__)
CORS(app)

# ── In-memory storage ────────────────────────────────────────────────────────
transaction_log = []
ip_last_blocked = {}
ip_transaction_times = defaultdict(list)
stats = {"total": 0, "blocked": 0, "warned": 0, "allowed": 0}

# ── ML Model (trained on startup) ───────────────────────────────────────────
ml_model = None
ml_scaler = None
ML_TRAINED = False

MERCHANTS = [
    "Amazon", "Netflix", "Walmart", "Shell", "Starbucks",
    "Apple Store", "Steam", "Uber", "AliExpress", "Best Buy",
    "Unknown Vendor", "CryptoExchange", "OffshoreShop"
]
LOCATIONS = ["Chennai", "Mumbai", "Delhi", "Bangalore", "Hyderabad",
             "London", "New York", "Dubai", "Singapore", "Moscow"]

HIGH_RISK_MERCHANTS = {"Unknown Vendor", "CryptoExchange", "OffshoreShop"}
HIGH_RISK_LOCATIONS = {"Moscow", "Unknown"}


def extract_features(txn: dict) -> list:
    """Convert a transaction dict into a numeric feature vector for ML."""
    amount = float(txn.get("amount", 0))
    hour = int(txn.get("hour", datetime.now().hour))
    merchant = txn.get("merchant", "")
    location = txn.get("location", "")
    velocity = int(txn.get("velocity", 1))
    typing_speed = float(txn.get("typing_speed", 1.0))
    location_jump = int(txn.get("location_jump", 0))

    is_high_risk_merchant = 1 if merchant in HIGH_RISK_MERCHANTS else 0
    is_high_risk_location = 1 if location in HIGH_RISK_LOCATIONS else 0
    is_odd_hour = 1 if (hour >= 2 and hour <= 5) else 0
    is_high_amount = 1 if amount > 5000 else 0
    is_very_high_amount = 1 if amount > 15000 else 0

    return [
        amount / 20000.0,           # normalised amount
        hour / 23.0,                 # normalised hour
        velocity / 10.0,             # normalised velocity
        typing_speed,
        location_jump,
        is_high_risk_merchant,
        is_high_risk_location,
        is_odd_hour,
        is_high_amount,
        is_very_high_amount,
    ]


def train_ml_model():
    """Generate synthetic training data and fit Isolation Forest."""
    global ml_model, ml_scaler, ML_TRAINED

    if not ML_AVAILABLE:
        return

    print("🤖 Training Isolation Forest ML model...")

    training_samples = []
    for _ in range(1000):
        # Normal transactions (majority)
        training_samples.append([
            random.uniform(10, 3000) / 20000.0,
            random.randint(8, 22) / 23.0,
            random.randint(1, 3) / 10.0,
            random.uniform(0.8, 2.0),
            0,
            0,
            0,
            0,
            0,
            0,
        ])

    for _ in range(150):
        # Anomalous / fraud-like transactions (minority)
        training_samples.append([
            random.uniform(8000, 20000) / 20000.0,
            random.randint(2, 5) / 23.0,
            random.randint(6, 10) / 10.0,
            random.uniform(0.1, 0.4),
            1,
            random.choice([0, 1]),
            random.choice([0, 1]),
            1,
            1,
            random.choice([0, 1]),
        ])

    X = np.array(training_samples)
    ml_scaler = StandardScaler()
    X_scaled = ml_scaler.fit_transform(X)

    ml_model = IsolationForest(
        n_estimators=200,
        contamination=0.12,
        random_state=42,
        n_jobs=-1
    )
    ml_model.fit(X_scaled)
    ML_TRAINED = True
    print("✅ ML model trained! (200 trees, 1150 samples, contamination=12%)")


def ml_score(txn: dict) -> dict:
    """Return ML anomaly score and label for a transaction."""
    if not ML_TRAINED or not ML_AVAILABLE:
        return {"ml_score": None, "ml_label": "N/A", "ml_confidence": 0}

    features = extract_features(txn)
    X = np.array([features])
    X_scaled = ml_scaler.transform(X)

    prediction = ml_model.predict(X_scaled)[0]       # 1 = normal, -1 = anomaly
    raw_score = ml_model.decision_function(X_scaled)[0]  # more negative = more anomalous

    # Convert to 0-100 risk score (higher = riskier)
    # decision_function typically ranges from ~ -0.5 to +0.5
    normalised = max(0, min(100, int((0.5 - raw_score) * 100)))

    label = "ANOMALY" if prediction == -1 else "NORMAL"
    confidence = min(100, int(abs(raw_score) * 200))

    return {
        "ml_score": normalised,
        "ml_label": label,
        "ml_confidence": confidence,
        "raw_score": round(float(raw_score), 4)
    }


# ── Rule-based risk engine ───────────────────────────────────────────────────
def rule_based_score(data: dict) -> tuple[int, list]:
    score = 0
    signals = []

    amount = float(data.get("amount", 0))
    if amount > 10000:
        score += 30
        signals.append("HIGH_AMOUNT")
    elif amount > 5000:
        score += 15
        signals.append("MEDIUM_AMOUNT")

    merchant = data.get("merchant", "")
    if merchant in HIGH_RISK_MERCHANTS:
        score += 25
        signals.append("HIGH_RISK_MERCHANT")

    hour = int(data.get("hour", datetime.now().hour))
    if 2 <= hour <= 5:
        score += 20
        signals.append("UNUSUAL_HOUR")

    if data.get("location_jump"):
        score += 25
        signals.append("LOCATION_JUMP")

    velocity = int(data.get("velocity", 1))
    if velocity >= 5:
        score += 20
        signals.append("HIGH_VELOCITY")
    elif velocity >= 3:
        score += 10
        signals.append("MEDIUM_VELOCITY")

    typing_speed = float(data.get("typing_speed", 1.0))
    if typing_speed < 0.3:
        score += 15
        signals.append("BOT_TYPING_SPEED")
    elif typing_speed > 3.5:
        score += 10
        signals.append("FAST_TYPING")

    location = data.get("location", "")
    if location in HIGH_RISK_LOCATIONS:
        score += 15
        signals.append("HIGH_RISK_LOCATION")

    device = data.get("device_fingerprint", "known")
    if device == "new":
        score += 10
        signals.append("NEW_DEVICE")

    if data.get("multiple_declines"):
        score += 20
        signals.append("MULTIPLE_DECLINES")

    return min(score, 100), signals


def combined_verdict(rule_score: int, ml_result: dict) -> dict:
    """Combine rule engine + ML model into final verdict."""
    ml_s = ml_result.get("ml_score")

    if ml_s is not None:
        # Weighted: 60% rules, 40% ML
        final_score = int(rule_score * 0.6 + ml_s * 0.4)
    else:
        final_score = rule_score

    if final_score >= 70:
        verdict = "BLOCK"
    elif final_score >= 40:
        verdict = "WARN"
    else:
        verdict = "ALLOW"

    return {"final_score": final_score, "verdict": verdict}


# ── Flask routes ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(BUILT_IN_UI)


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "ml_ready": ML_TRAINED,
        "ml_available": ML_AVAILABLE,
        "transactions_processed": stats["total"]
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True) or {}
    ip = request.remote_addr or "unknown"
    now = time.time()

    # 30-second cooldown block
    if ip in ip_last_blocked and (now - ip_last_blocked[ip]) < 30:
        remaining = int(30 - (now - ip_last_blocked[ip]))
        result = {
            "verdict": "BLOCK",
            "final_score": 100,
            "rule_score": 100,
            "signals": ["COOLDOWN_ACTIVE"],
            "ml_result": {"ml_score": None, "ml_label": "COOLDOWN", "ml_confidence": 0},
            "cooldown_remaining": remaining,
            "timestamp": datetime.now().isoformat()
        }
        _log_transaction(data, result)
        return jsonify(result)

    # Velocity tracking
    ip_transaction_times[ip] = [t for t in ip_transaction_times[ip] if now - t < 120]
    ip_transaction_times[ip].append(now)
    data["velocity"] = len(ip_transaction_times[ip])

    rule_s, signals = rule_based_score(data)
    ml_result = ml_score(data)
    verdict_data = combined_verdict(rule_s, ml_result)

    result = {
        "verdict": verdict_data["verdict"],
        "final_score": verdict_data["final_score"],
        "rule_score": rule_s,
        "signals": signals,
        "ml_result": ml_result,
        "timestamp": datetime.now().isoformat()
    }

    if verdict_data["verdict"] == "BLOCK":
        ip_last_blocked[ip] = now

    _log_transaction(data, result)
    return jsonify(result)


@app.route("/api/log")
def get_log():
    return jsonify({"transactions": transaction_log[-50:]})


@app.route("/api/stats")
def get_stats():
    fraud_rate = round(stats["blocked"] / stats["total"] * 100, 1) if stats["total"] > 0 else 0
    return jsonify({**stats, "fraud_rate": fraud_rate, "ml_ready": ML_TRAINED})


@app.route("/api/stream")
def stream_transaction():
    """Generate a random transaction and analyze it (for auto-simulation)."""
    now = datetime.now()
    txn = {
        "amount": round(random.uniform(10, 18000), 2),
        "merchant": random.choice(MERCHANTS),
        "location": random.choice(LOCATIONS),
        "hour": now.hour,
        "velocity": random.randint(1, 8),
        "typing_speed": round(random.uniform(0.1, 4.0), 2),
        "location_jump": random.choices([0, 1], weights=[75, 25])[0],
        "device_fingerprint": random.choice(["known", "known", "new"]),
        "multiple_declines": random.choices([False, True], weights=[85, 15])[0],
    }
    rule_s, signals = rule_based_score(txn)
    ml_result = ml_score(txn)
    verdict_data = combined_verdict(rule_s, ml_result)

    result = {
        **txn,
        "verdict": verdict_data["verdict"],
        "final_score": verdict_data["final_score"],
        "rule_score": rule_s,
        "signals": signals,
        "ml_result": ml_result,
        "timestamp": now.isoformat()
    }
    _log_transaction(txn, result)
    return jsonify(result)


def _log_transaction(txn: dict, result: dict):
    stats["total"] += 1
    v = result.get("verdict", "ALLOW")
    if v == "BLOCK":
        stats["blocked"] += 1
    elif v == "WARN":
        stats["warned"] += 1
    else:
        stats["allowed"] += 1

    entry = {
        "id": stats["total"],
        "amount": txn.get("amount"),
        "merchant": txn.get("merchant"),
        "location": txn.get("location"),
        "verdict": v,
        "final_score": result.get("final_score"),
        "rule_score": result.get("rule_score"),
        "ml_score": result.get("ml_result", {}).get("ml_score"),
        "ml_label": result.get("ml_result", {}).get("ml_label"),
        "signals": result.get("signals", []),
        "timestamp": result.get("timestamp")
    }
    transaction_log.append(entry)
    if len(transaction_log) > 200:
        transaction_log.pop(0)


# ── Minimal built-in UI (fallback — judges should use index.html) ─────────────
BUILT_IN_UI = """
<!DOCTYPE html><html><head><title>BehaviorShield API</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#00ff88;padding:40px}
h1{color:#00ffcc}a{color:#00aaff}</style></head><body>
<h1>🛡️ BehaviorShield API Running</h1>
<p>ML Model: <strong id="ml">checking...</strong></p>
<p>Open <a href="index.html">index.html</a> for the full cyberpunk UI.</p>
<h3>Endpoints:</h3>
<ul>
<li><a href="/api/health">/api/health</a> — server + ML status</li>
<li><a href="/api/stats">/api/stats</a> — live fraud stats</li>
<li><a href="/api/log">/api/log</a> — last 50 transactions</li>
<li>/api/analyze (POST) — analyze a transaction</li>
<li><a href="/api/stream">/api/stream</a> — simulate one random transaction</li>
</ul>
<script>
fetch('/api/health').then(r=>r.json()).then(d=>{
  document.getElementById('ml').textContent = d.ml_ready ? '✅ Isolation Forest Ready' : '⚠️ Not trained yet';
});
</script></body></html>
"""

# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if ML_AVAILABLE:
        t = threading.Thread(target=train_ml_model, daemon=True)
        t.start()
        t.join()  # wait for training before serving
    else:
        print("⚠️  Running WITHOUT ML — install scikit-learn for full functionality")

    print("\n✅ BehaviorShield is running!")
    print("   API:  http://localhost:5000/api/health")
    print("   UI:   open index.html in Chrome\n")
    app.run(debug=False, port=5000, host="0.0.0.0")