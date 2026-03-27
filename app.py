from flask import Flask, jsonify, request, render_template_string, Response
from flask_cors import CORS
import random
import time
import json
import os
from datetime import datetime
from collections import defaultdict
import threading
import uuid
import csv
import io
import logging
from typing import Any, Optional, Tuple

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

# ── Fraud response storage (demo-grade, in-memory) ───────────────────────────
accounts = {}  # account_id -> {"status": "ACTIVE"|"FROZEN", "frozen_until": epoch|None, "notes": [...]}
case_reports = []  # disputes / reports

# ── Security / ops knobs ─────────────────────────────────────────────────────
ADMIN_TOKEN = os.environ.get("BEHAVIORSHIELD_ADMIN_TOKEN")  # optional
LOG_PATH = os.environ.get("BEHAVIORSHIELD_LOG_PATH", "behaviorshield_audit.jsonl")

# Very small anti-abuse guardrails suitable for demos.
RATE_LIMITS = {
    "analyze_per_min": int(os.environ.get("BEHAVIORSHIELD_RL_PER_MIN", "30")),
    "analyze_burst_5s": int(os.environ.get("BEHAVIORSHIELD_RL_BURST_5S", "8")),
}

# ── Logging ─────────────────────────────────────────────────────────────────
logger = logging.getLogger("behaviorshield")
logger.setLevel(logging.INFO)
_h = logging.StreamHandler()
_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_h)


def _is_admin(req: Any) -> bool:
    """Admin-only operations. For demos, allow localhost without token."""
    ip = req.remote_addr or ""
    if ip in {"127.0.0.1", "::1"} and not ADMIN_TOKEN:
        return True
    token = req.headers.get("X-Admin-Token", "")
    return bool(ADMIN_TOKEN) and token == ADMIN_TOKEN


def _audit_write(event: dict) -> None:
    """Write JSONL audit trail for investigations."""
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning("audit_write_failed=%s", str(e))


def _now_iso() -> str:
    return datetime.now().isoformat()


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def _safe_str(v: Any, max_len: int = 64) -> str:
    if v is None:
        return ""
    s = str(v)
    s = s.replace("\x00", "")
    return s[:max_len]


def _rate_limit_key(req: Any, account_id: str) -> str:
    ip = req.remote_addr or "unknown"
    return f"{ip}:{account_id or 'na'}"


rate_state = defaultdict(list)  # key -> list[timestamps]


def _rate_limited(req: Any, account_id: str) -> Tuple[bool, dict]:
    """Sliding-window limiter to reduce bots / brute forcing."""
    key = _rate_limit_key(req, account_id)
    now = time.time()
    window_60 = 60
    window_5 = 5
    times = rate_state[key]
    # keep only last 60s
    times = [t for t in times if now - t < window_60]
    burst_5s = [t for t in times if now - t < window_5]
    limited = False
    info = {"rl_key": key, "per_min": len(times), "burst_5s": len(burst_5s)}
    if len(times) >= RATE_LIMITS["analyze_per_min"] or len(burst_5s) >= RATE_LIMITS["analyze_burst_5s"]:
        limited = True
    else:
        times.append(now)
    rate_state[key] = times
    return limited, info


def _get_account(account_id: str) -> dict:
    if not account_id:
        account_id = "anon"
    if account_id not in accounts:
        accounts[account_id] = {"status": "ACTIVE", "frozen_until": None, "notes": []}
    # auto-unfreeze
    au = accounts[account_id].get("frozen_until")
    if au and time.time() >= au:
        accounts[account_id]["status"] = "ACTIVE"
        accounts[account_id]["frozen_until"] = None
        accounts[account_id]["notes"].append({"ts": _now_iso(), "event": "AUTO_UNFREEZE"})
    return accounts[account_id]


def _freeze_account(account_id: str, seconds: int, reason: str, meta: Optional[dict] = None) -> dict:
    acc = _get_account(account_id)
    until = time.time() + max(0, int(seconds))
    acc["status"] = "FROZEN"
    acc["frozen_until"] = until
    acc["notes"].append({"ts": _now_iso(), "event": "FREEZE", "reason": reason, "meta": meta or {}})
    return acc


def _send_alert(channel: str, to: str, message: str, meta: Optional[dict] = None) -> None:
    """Mock SMS/email alert hook. In prod you'd integrate Twilio/SES/etc."""
    evt = {"ts": _now_iso(), "type": "ALERT", "channel": channel, "to": to, "message": message, "meta": meta or {}}
    logger.info("alert channel=%s to=%s msg=%s", channel, to, message[:80])
    _audit_write(evt)


def normalize_and_validate(payload: dict, req: Any) -> Tuple[dict, list, list]:
    """
    Normalize inputs from UI / API clients into the internal schema.

    Returns: (txn, validation_errors, security_signals)
    """
    errors = []
    sec_signals = []

    # Honeypot fields: bots often fill hidden inputs.
    for hp_key in ("website", "homepage", "company_url", "fax_number", "hp_email"):
        if payload.get(hp_key):
            sec_signals.append("HONEYPOT_FILLED")
            break

    # Basic request metadata (for logs + risk features)
    ip = req.remote_addr or "unknown"
    ua = _safe_str(req.headers.get("User-Agent", ""), 160)

    # Account identity: in real systems comes from auth/session.
    account_id = _safe_str(payload.get("account_id") or payload.get("user_id") or payload.get("customer_id") or ip, 48)
    session_id = _safe_str(payload.get("session_id") or payload.get("sid") or "", 64)

    # Amount
    try:
        amount = float(payload.get("amount", 0))
    except Exception:
        amount = 0.0
        errors.append("amount_invalid")
    if not (0 <= amount <= 1_000_000):
        errors.append("amount_out_of_range")
        amount = _clamp(amount, 0, 1_000_000)

    # Hour
    hour_raw = payload.get("hour", datetime.now().hour)
    try:
        hour = int(hour_raw)
    except Exception:
        hour = datetime.now().hour
        errors.append("hour_invalid")
    if not (0 <= hour <= 23):
        errors.append("hour_out_of_range")
        hour = max(0, min(23, hour))

    # Velocity mapping (UI uses txn_velocity)
    vel_raw = payload.get("velocity", payload.get("txn_velocity", 1))
    try:
        velocity = int(vel_raw)
    except Exception:
        velocity = 1
        errors.append("velocity_invalid")
    velocity = max(0, min(50, velocity))

    # Typing speed mapping (UI uses typing_speed_wpm)
    typing_speed = payload.get("typing_speed", None)
    if typing_speed is None and payload.get("typing_speed_wpm") is not None:
        try:
            wpm = float(payload.get("typing_speed_wpm"))
            # Convert WPM to a stable normalized feature roughly matching existing 0.1–4.0 scale
            typing_speed = _clamp(wpm / 60.0, 0.05, 6.0)
        except Exception:
            typing_speed = 1.0
            errors.append("typing_speed_wpm_invalid")
    try:
        typing_speed = float(typing_speed if typing_speed is not None else 1.0)
    except Exception:
        typing_speed = 1.0
        errors.append("typing_speed_invalid")
    typing_speed = _clamp(typing_speed, 0.05, 6.0)

    # Location mapping: accept both categorical location or jump distance.
    location_jump = payload.get("location_jump", None)
    if location_jump is None and payload.get("location_jump_km") is not None:
        try:
            km = float(payload.get("location_jump_km"))
            location_jump = 1 if km >= 500 else 0
        except Exception:
            location_jump = 0
            errors.append("location_jump_km_invalid")
    location_jump = 1 if _to_bool(location_jump) else 0

    location = _safe_str(payload.get("location", ""), 32)
    if not location:
        # UI sends "same/diff_state/foreign/vpn"
        loc_ui = _safe_str(payload.get("loc") or payload.get("geo") or payload.get("location_category") or "", 32)
        location = loc_ui
    # Normalize common UI options
    loc_map = {"same": "Chennai", "diff_state": "Mumbai", "foreign": "London", "vpn": "Unknown"}
    if location in loc_map:
        location = loc_map[location]
    if location_jump and location not in {"London", "New York", "Dubai", "Singapore", "Moscow"}:
        # force a "travel-like" destination for consistent rules
        location = "London"

    # Merchant mapping: accept UI categories and map to demo merchant set
    merchant = _safe_str(payload.get("merchant", ""), 48)
    merch_map = {
        "grocery": "Walmart",
        "electronics": "Apple Store",
        "travel": "Uber",
        "crypto": "CryptoExchange",
        "wire": "OffshoreShop",
        "unknown": "Unknown Vendor",
    }
    if merchant in merch_map:
        merchant = merch_map[merchant]
    if not merchant:
        merchant = "Unknown Vendor"

    device = _safe_str(payload.get("device_fingerprint", payload.get("device") or "known"), 24)
    if device not in {"known", "new"}:
        device = "known"

    multiple_declines = _to_bool(payload.get("multiple_declines"))

    # Soft bot telemetry expectations (not enforced to keep demo usable)
    if not session_id:
        sec_signals.append("MISSING_SESSION_ID")
    if not ua:
        sec_signals.append("MISSING_USER_AGENT")

    txn = {
        "request_id": _safe_str(payload.get("request_id") or str(uuid.uuid4()), 64),
        "account_id": account_id,
        "session_id": session_id,
        "ip": ip,
        "user_agent": ua,
        "amount": amount,
        "hour": hour,
        "merchant": merchant,
        "location": location,
        "velocity": velocity,
        "typing_speed": typing_speed,
        "location_jump": location_jump,
        "device_fingerprint": device,
        "multiple_declines": multiple_declines,
    }

    return txn, errors, sec_signals

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
        amount / 20000.0,
        hour / 23.0,
        velocity / 10.0,
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
        training_samples.append([
            random.uniform(10, 3000) / 20000.0,
            random.randint(8, 22) / 23.0,
            random.randint(1, 3) / 10.0,
            random.uniform(0.8, 2.0),
            0, 0, 0, 0, 0, 0,
        ])

    for _ in range(150):
        training_samples.append([
            random.uniform(8000, 20000) / 20000.0,
            random.randint(2, 5) / 23.0,
            random.randint(6, 10) / 10.0,
            random.uniform(0.1, 0.4),
            1,
            random.choice([0, 1]),
            random.choice([0, 1]),
            1, 1,
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

    prediction = ml_model.predict(X_scaled)[0]
    raw_score = ml_model.decision_function(X_scaled)[0]  # higher = more normal

    # Robust normalization: map raw_score range into a 0–100 risk scale.
    # For IsolationForest, typical decision_function values are small (e.g., ~[-0.2, 0.2]).
    risk = (0.15 - raw_score) / 0.30  # center around 0.15; widen range for stability
    normalised = int(_clamp(risk * 100.0, 0, 100))
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
        final_score = int(rule_score * 0.6 + ml_s * 0.4)
    else:
        final_score = rule_score

    # Randomized block threshold reduces trivial "hover under threshold" gaming.
    block_threshold = random.randint(65, 75)
    warn_threshold = 40

    if final_score >= block_threshold:
        verdict = "BLOCK"
    elif final_score >= warn_threshold:
        verdict = "WARN"
    else:
        verdict = "ALLOW"

    return {
        "final_score": final_score,
        "verdict": verdict,
        "thresholds": {"block": block_threshold, "warn": warn_threshold},
    }


def _build_txn_result(txn: dict) -> dict:
    """Shared helper: run rule + ML engines on a transaction dict."""
    rule_s, signals = rule_based_score(txn)
    ml_result = ml_score(txn)
    verdict_data = combined_verdict(rule_s, ml_result)

    # Explainability: include "why" in a stable, explicit field.
    reasons = list(signals)
    if ml_result.get("ml_score") is not None and ml_result.get("ml_label") == "ANOMALY":
        reasons.append("ML_ANOMALY")

    result = {
        "verdict": verdict_data["verdict"],
        "final_score": verdict_data["final_score"],
        "rule_score": rule_s,
        "signals": signals,
        "reasons": reasons,
        "ml_result": ml_result,
        "thresholds": verdict_data.get("thresholds", {}),
        "timestamp": datetime.now().isoformat()
    }
    _log_transaction(txn, result)
    return result


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
    data = request.get_json(force=True, silent=True) or {}
    ip = request.remote_addr or "unknown"
    now = time.time()

    txn, errors, sec_signals = normalize_and_validate(data, request)
    account_id = txn.get("account_id", ip)
    acc = _get_account(account_id)

    # Rate limiting (anti-bot / brute forcing)
    limited, rl_info = _rate_limited(request, account_id)
    if limited:
        result = {
            "verdict": "BLOCK",
            "final_score": 100,
            "rule_score": 100,
            "signals": ["RATE_LIMITED"],
            "reasons": ["RATE_LIMITED"],
            "ml_result": {"ml_score": None, "ml_label": "RATE_LIMITED", "ml_confidence": 0},
            "thresholds": {"block": 0, "warn": 0},
            "errors": errors,
            "security_signals": sec_signals,
            "rate_limit": rl_info,
            "timestamp": _now_iso(),
        }
        _log_transaction(txn, result)
        return jsonify(result), 429

    # Honeypot: immediate hard block.
    if "HONEYPOT_FILLED" in sec_signals:
        _freeze_account(account_id, seconds=300, reason="HONEYPOT", meta={"ip": ip})
        _send_alert("email", to=account_id, message="BehaviorShield: bot-like form submission blocked (honeypot).")
        result = {
            "verdict": "BLOCK",
            "final_score": 100,
            "rule_score": 100,
            "signals": ["HONEYPOT_FILLED"],
            "reasons": ["HONEYPOT_FILLED"],
            "ml_result": {"ml_score": None, "ml_label": "HONEYPOT", "ml_confidence": 0},
            "thresholds": {"block": 0, "warn": 0},
            "errors": errors,
            "security_signals": sec_signals,
            "timestamp": _now_iso(),
            "account": {"id": account_id, **_get_account(account_id)},
        }
        _log_transaction(txn, result)
        return jsonify(result)

    # Account freeze gate
    if acc.get("status") == "FROZEN":
        until = acc.get("frozen_until") or now + 30
        remaining = int(max(0, until - now))
        result = {
            "verdict": "BLOCK",
            "final_score": 100,
            "rule_score": 100,
            "signals": ["ACCOUNT_FROZEN"],
            "reasons": ["ACCOUNT_FROZEN"],
            "ml_result": {"ml_score": None, "ml_label": "FROZEN", "ml_confidence": 0},
            "thresholds": {"block": 0, "warn": 0},
            "cooldown_remaining": remaining,
            "errors": errors,
            "security_signals": sec_signals,
            "timestamp": _now_iso(),
            "account": {"id": account_id, **acc},
        }
        _log_transaction(txn, result)
        return jsonify(result)

    # 30-second cooldown block
    if ip in ip_last_blocked and (now - ip_last_blocked[ip]) < 30:
        remaining = int(30 - (now - ip_last_blocked[ip]))
        result = {
            "verdict": "BLOCK",
            "final_score": 100,
            "rule_score": 100,
            "signals": ["COOLDOWN_ACTIVE"],
            "reasons": ["COOLDOWN_ACTIVE"],
            "ml_result": {"ml_score": None, "ml_label": "COOLDOWN", "ml_confidence": 0},
            "cooldown_remaining": remaining,
            "errors": errors,
            "security_signals": sec_signals,
            "timestamp": datetime.now().isoformat()
        }
        _log_transaction(txn, result)
        return jsonify(result)

    # Velocity tracking
    ip_transaction_times[ip] = [t for t in ip_transaction_times[ip] if now - t < 120]
    ip_transaction_times[ip].append(now)
    txn["velocity"] = len(ip_transaction_times[ip])

    # Security signals can influence score without breaking ML feature contract.
    if "MISSING_SESSION_ID" in sec_signals:
        txn["multiple_declines"] = True if txn.get("multiple_declines") is False else txn.get("multiple_declines")

    result = _build_txn_result(txn)

    if result["verdict"] == "BLOCK":
        ip_last_blocked[ip] = now
        # Fraud response: auto-freeze account and alert (simulation)
        _freeze_account(account_id, seconds=120, reason="AUTO_FREEZE_ON_BLOCK", meta={"request_id": txn.get("request_id")})
        _send_alert("sms", to=account_id, message="BehaviorShield: transaction blocked; account temporarily frozen.", meta={"ip": ip})

    # Attach validation + account info for transparency (explainability/debugging)
    result["errors"] = errors
    result["security_signals"] = sec_signals
    result["account"] = {"id": account_id, **_get_account(account_id)}

    return jsonify(result)


@app.route("/api/log")
def get_log():
    return jsonify({"transactions": transaction_log[-50:]})

@app.route("/api/log/export")
def export_log():
    if not _is_admin(request):
        return jsonify({"error": "admin_required"}), 403

    fmt = (request.args.get("format") or "json").lower()
    try:
        limit = int(request.args.get("limit") or "200")
    except Exception:
        limit = 200
    limit = max(1, min(2000, limit))
    rows = transaction_log[-limit:]

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "id", "timestamp", "ip", "account_id", "amount", "merchant", "location",
                "verdict", "final_score", "rule_score", "ml_score", "ml_label", "signals", "reasons"
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow({
                "id": r.get("id"),
                "timestamp": r.get("timestamp"),
                "ip": r.get("ip"),
                "account_id": r.get("account_id"),
                "amount": r.get("amount"),
                "merchant": r.get("merchant"),
                "location": r.get("location"),
                "verdict": r.get("verdict"),
                "final_score": r.get("final_score"),
                "rule_score": r.get("rule_score"),
                "ml_score": r.get("ml_score"),
                "ml_label": r.get("ml_label"),
                "signals": ",".join(r.get("signals") or []),
                "reasons": ",".join(r.get("reasons") or []),
            })
        return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=behaviorshield_log.csv"})

    return jsonify({"transactions": rows, "count": len(rows), "format": "json"})


@app.route("/api/report", methods=["POST"])
def report_fraud():
    body = request.get_json(force=True, silent=True) or {}
    account_id = _safe_str(body.get("account_id") or body.get("user_id") or "", 48)
    tx_id = _safe_str(body.get("transaction_id") or body.get("request_id") or "", 64)
    message = _safe_str(body.get("message") or body.get("details") or "", 500)

    if not account_id:
        return jsonify({"error": "account_id_required"}), 400
    if not message:
        return jsonify({"error": "message_required"}), 400

    report = {
        "id": len(case_reports) + 1,
        "ts": _now_iso(),
        "ip": request.remote_addr or "unknown",
        "account_id": account_id,
        "transaction_id": tx_id,
        "message": message,
        "status": "OPEN",
    }
    case_reports.append(report)
    _send_alert("email", to=account_id, message="BehaviorShield: fraud/dispute report received.", meta={"case_id": report["id"]})
    _audit_write({"ts": report["ts"], "type": "CASE_REPORT", "report": report})
    return jsonify({"ok": True, "report": report})


@app.route("/api/account/<account_id>")
def get_account(account_id: str):
    account_id = _safe_str(account_id, 48)
    return jsonify({"id": account_id, **_get_account(account_id)})


@app.route("/api/account/freeze", methods=["POST"])
def api_freeze_account():
    if not _is_admin(request):
        return jsonify({"error": "admin_required"}), 403
    body = request.get_json(force=True, silent=True) or {}
    account_id = _safe_str(body.get("account_id") or "", 48)
    try:
        seconds = int(body.get("seconds") or 300)
    except Exception:
        seconds = 300
    reason = _safe_str(body.get("reason") or "MANUAL_FREEZE", 120)
    if not account_id:
        return jsonify({"error": "account_id_required"}), 400
    acc = _freeze_account(account_id, seconds=seconds, reason=reason, meta={"by": "admin"})
    _audit_write({"ts": _now_iso(), "type": "ADMIN_FREEZE", "account_id": account_id, "seconds": seconds, "reason": reason})
    return jsonify({"ok": True, "account": {"id": account_id, **acc}})


@app.route("/api/stats")
def get_stats():
    fraud_rate = round(stats["blocked"] / stats["total"] * 100, 1) if stats["total"] > 0 else 0
    return jsonify({**stats, "fraud_rate": fraud_rate, "fraud_rate_pct": fraud_rate, "ml_ready": ML_TRAINED})


# ── FIX: /api/stream AND /api/simulate both work ────────────────────────────
@app.route("/api/stream")
@app.route("/api/simulate")
def stream_transaction():
    """Generate a random transaction and analyze it (for auto-simulation).
    Accessible as both /api/stream and /api/simulate.
    """
    now = datetime.now()
    txn = {
        "amount":             round(random.uniform(10, 18000), 2),
        "merchant":           random.choice(MERCHANTS),
        "location":           random.choice(LOCATIONS),
        "hour":               now.hour,
        "velocity":           random.randint(1, 8),
        "typing_speed":       round(random.uniform(0.1, 4.0), 2),
        "location_jump":      random.choices([0, 1], weights=[75, 25])[0],
        "device_fingerprint": random.choice(["known", "known", "new"]),
        "multiple_declines":  random.choices([False, True], weights=[85, 15])[0],
    }

    result = _build_txn_result(txn)
    return jsonify({"transaction": txn, "result": result, "timestamp": result["timestamp"]})


# ── /api/simulate/bulk — burst endpoint ─────────────────────────────────────
@app.route("/api/simulate/bulk", methods=["POST"])
def simulate_bulk():
    """Generate N transactions at once for the burst button."""
    body  = request.get_json(force=True) or {}
    count = min(int(body.get("count", 10)), 50)   # cap at 50

    now = datetime.now()
    results = []
    for _ in range(count):
        txn = {
            "amount":             round(random.uniform(10, 18000), 2),
            "merchant":           random.choice(MERCHANTS),
            "location":           random.choice(LOCATIONS),
            "hour":               now.hour,
            "velocity":           random.randint(1, 8),
            "typing_speed":       round(random.uniform(0.1, 4.0), 2),
            "location_jump":      random.choices([0, 1], weights=[75, 25])[0],
            "device_fingerprint": random.choice(["known", "known", "new"]),
            "multiple_declines":  random.choices([False, True], weights=[85, 15])[0],
        }
        result = _build_txn_result(txn)
        results.append({
            "transaction": txn,
            "result":      result,
            "timestamp":   result["timestamp"]
        })

    return jsonify({"transactions": results, "count": len(results)})

@app.route("/api/stress_test")
def stress_test():
    """
    Simulate common attacker strategies and show system behavior.
    This is intentionally deterministic-ish for demo judging.
    """
    scenarios = []

    def run(name: str, payload: dict):
        fake_req = request
        txn, errors, sec = normalize_and_validate(payload, fake_req)
        res = _build_txn_result(txn)
        scenarios.append({"name": name, "payload": payload, "normalized": txn, "result": res, "errors": errors, "security_signals": sec})

    # 1) Threshold gaming: keep amount just below big step-ups, rotate merchants/locations.
    run("threshold_gaming_low_and_slow", {
        "amount": 4950, "merchant": "electronics", "location": "same", "txn_velocity": 2,
        "typing_speed_wpm": 55, "location_jump_km": 0, "device_fingerprint": "known", "account_id": "attacker_1"
    })

    # 2) Credential takeover-ish: new device + unusual hour + foreign jump but modest amount.
    run("account_takeover_modest_amount", {
        "amount": 1800, "merchant": "unknown", "location": "foreign", "hour": 3,
        "txn_velocity": 4, "typing_speed_wpm": 35, "location_jump_km": 1200, "device_fingerprint": "new",
        "multiple_declines": True, "account_id": "victim_7"
    })

    # 3) Bot automation: very low typing speed, high velocity.
    run("bot_high_velocity", {
        "amount": 2500, "merchant": "grocery", "location": "same", "txn_velocity": 9,
        "typing_speed": 0.12, "location_jump": 0, "device_fingerprint": "new", "account_id": "botnet_a"
    })

    # 4) Feature poisoning / bad types: strings, NaNs, huge values.
    run("payload_poisoning_types", {
        "amount": "9999999999", "hour": "99", "txn_velocity": "a lot",
        "typing_speed_wpm": "fast", "location_jump_km": "infinite", "merchant": {"$ne": "Amazon"},
        "location": ["London"], "account_id": "poisoner"
    })

    # 5) Honeypot triggered: bot fills hidden website field.
    run("honeypot_form_fill", {
        "amount": 900, "merchant": "grocery", "location": "same", "txn_velocity": 1,
        "typing_speed_wpm": 45, "website": "http://spam.example", "account_id": "bot_hp"
    })

    return jsonify({"count": len(scenarios), "scenarios": scenarios})


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
        "id":         stats["total"],
        "request_id": txn.get("request_id"),
        "account_id": txn.get("account_id"),
        "ip":         txn.get("ip"),
        "amount":     txn.get("amount"),
        "merchant":   txn.get("merchant"),
        "location":   txn.get("location"),
        "verdict":    v,
        "final_score": result.get("final_score"),
        "rule_score": result.get("rule_score"),
        "ml_score":   result.get("ml_result", {}).get("ml_score"),
        "ml_label":   result.get("ml_result", {}).get("ml_label"),
        "signals":    result.get("signals", []),
        "reasons":    result.get("reasons", []),
        "thresholds": result.get("thresholds", {}),
        "errors":     result.get("errors", []),
        "security_signals": result.get("security_signals", []),
        "timestamp":  result.get("timestamp")
    }
    transaction_log.append(entry)
    if len(transaction_log) > 200:
        transaction_log.pop(0)

    # Audit trail: store enough to reconstruct investigations (without secrets).
    _audit_write({
        "ts": entry["timestamp"],
        "type": "TXN",
        "txn": {
            "request_id": txn.get("request_id"),
            "account_id": txn.get("account_id"),
            "ip": txn.get("ip"),
            "user_agent": txn.get("user_agent"),
            "amount": txn.get("amount"),
            "merchant": txn.get("merchant"),
            "location": txn.get("location"),
            "hour": txn.get("hour"),
            "velocity": txn.get("velocity"),
            "typing_speed": txn.get("typing_speed"),
            "location_jump": txn.get("location_jump"),
            "device_fingerprint": txn.get("device_fingerprint"),
            "multiple_declines": txn.get("multiple_declines"),
        },
        "result": {
            "verdict": result.get("verdict"),
            "final_score": result.get("final_score"),
            "rule_score": result.get("rule_score"),
            "reasons": result.get("reasons"),
            "ml_result": result.get("ml_result"),
            "thresholds": result.get("thresholds"),
        },
    })


# ── Minimal built-in UI ───────────────────────────────────────────────────────
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
<li><a href="/api/simulate">/api/simulate</a> — alias for /api/stream (fixes 404)</li>
<li>/api/simulate/bulk (POST) — burst simulate N transactions</li>
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
        t.join()
    else:
        print("⚠️  Running WITHOUT ML — install scikit-learn for full functionality")

    print("\n✅ BehaviorShield is running!")
    print("   API:  http://localhost:5000/api/health")
    print("   UI:   open index.html in Chrome\n")
    app.run(debug=False, port=5000, host="0.0.0.0")