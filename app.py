from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import time
import json

app = Flask(__name__)
CORS(app)

# --- In-memory log store (no DB needed for hackathon) ---
transaction_log = []
blocked_ips = {}  # ip -> timestamp of last block (30-sec cooldown)

# ─────────────────────────────────────────
#  CORE RISK ENGINE
# ─────────────────────────────────────────
def compute_risk(data):
    score = 0
    reasons = []

    amount = data.get("amount", 0)
    new_beneficiary   = data.get("new_beneficiary", False)
    copy_paste        = data.get("copy_paste", False)
    otp_retry         = data.get("otp_retry", False)
    screen_sharing    = data.get("screen_sharing", False)
    app_switching     = data.get("app_switching", False)
    typing_speed_wpm  = data.get("typing_speed_wpm", 40)
    location_jump_km  = data.get("location_jump_km", 0)
    txn_velocity      = data.get("txn_velocity", 1)   # txns in last 2 min
    unusual_hour      = data.get("unusual_hour", False)

    # --- Amount thresholds ---
    if amount > 100000:
        score += 25
        reasons.append("Very high transaction amount (>₹1L)")
    elif amount > 50000:
        score += 15
        reasons.append("High transaction amount (>₹50K)")
    elif amount > 10000:
        score += 5

    # --- Behavioural signals ---
    if new_beneficiary:
        score += 20
        reasons.append("New / unverified beneficiary")

    if copy_paste:
        score += 15
        reasons.append("Account number pasted — not typed manually")

    if otp_retry:
        score += 15
        reasons.append("Multiple OTP retries detected")

    if screen_sharing:
        score += 25
        reasons.append("Screen-sharing app active during transaction")

    if app_switching:
        score += 10
        reasons.append("Rapid app-switching detected")

    # --- Typing speed (too fast = bot / dictated) ---
    if typing_speed_wpm > 120:
        score += 15
        reasons.append("Abnormally fast typing — possible dictation/bot")

    # --- Location jump ---
    if location_jump_km > 500:
        score += 20
        reasons.append(f"Impossible location jump ({location_jump_km} km)")
    elif location_jump_km > 100:
        score += 10
        reasons.append(f"Unusual location change ({location_jump_km} km)")

    # --- Transaction velocity ---
    if txn_velocity >= 5:
        score += 20
        reasons.append(f"{txn_velocity} transactions in last 2 minutes")
    elif txn_velocity >= 3:
        score += 10
        reasons.append(f"{txn_velocity} transactions in last 2 minutes")

    # --- Unusual hour ---
    if unusual_hour:
        score += 5
        reasons.append("Transaction at unusual hour (2 AM–5 AM)")

    # Cap at 100
    score = min(score, 100)

    # --- Verdict ---
    if score >= 70:
        verdict = "blocked"
        action  = "BLOCK"
        message = (
            "Transaction BLOCKED. High manipulation risk detected. "
            "A bank agent will contact you within 5 minutes."
        )
    elif score >= 40:
        verdict = "warned"
        action  = "WARN"
        message = (
            "Suspicious activity detected. Please verify this transaction "
            "by answering the chatbot question before proceeding."
        )
    else:
        verdict = "allowed"
        action  = "ALLOW"
        message = "Transaction approved. No suspicious behaviour detected."

    return {
        "score":   score,
        "verdict": verdict,
        "action":  action,
        "message": message,
        "reasons": reasons
    }


# ─────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "BehaviorShield"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}

    result = compute_risk(data)

    # --- 30-second cooldown for blocked IPs ---
    ip = request.remote_addr
    now = time.time()
    if result["verdict"] == "blocked":
        blocked_ips[ip] = now
    else:
        last_block = blocked_ips.get(ip, 0)
        if now - last_block < 30:
            result["verdict"] = "blocked"
            result["action"]  = "BLOCK"
            result["message"] = "Transaction blocked — 30-second cooldown active after previous block."

    # --- Log it ---
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ip":        ip,
        "input":     data,
        "result":    result
    }
    transaction_log.append(log_entry)

    return jsonify(result)


@app.route("/api/log")
def get_log():
    """Returns last 50 transactions — useful for dashboard."""
    return jsonify(transaction_log[-50:])


@app.route("/api/stats")
def stats():
    total   = len(transaction_log)
    blocked = sum(1 for t in transaction_log if t["result"]["verdict"] == "blocked")
    warned  = sum(1 for t in transaction_log if t["result"]["verdict"] == "warned")
    allowed = sum(1 for t in transaction_log if t["result"]["verdict"] == "allowed")
    avg_score = (
        sum(t["result"]["score"] for t in transaction_log) / total
        if total > 0 else 0
    )
    return jsonify({
        "total": total,
        "blocked": blocked,
        "warned": warned,
        "allowed": allowed,
        "avg_risk_score": round(avg_score, 1),
        "fraud_rate_pct": round((blocked / total * 100), 1) if total else 0
    })


# ─────────────────────────────────────────
#  BUILT-IN DEMO UI  (no separate HTML file needed)
# ─────────────────────────────────────────
DEMO_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>BehaviorShield — Live Demo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 18px 32px;
             display: flex; align-items: center; gap: 12px; }
    header h1 { font-size: 1.4rem; color: #58a6ff; }
    header span { font-size: 0.8rem; color: #8b949e; }
    .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
    h2 { color: #58a6ff; margin-bottom: 16px; font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; }

    /* Score meter */
    .meter-wrap { background: #161b22; border: 1px solid #30363d; border-radius: 12px;
                  padding: 28px; margin-bottom: 28px; text-align: center; }
    #score-num { font-size: 5rem; font-weight: 700; transition: all 0.5s; }
    .meter-bar-bg { background: #21262d; border-radius: 99px; height: 18px; margin: 12px auto; max-width: 500px; }
    #meter-bar { height: 18px; border-radius: 99px; width: 0%; transition: all 0.6s; background: #3fb950; }
    #verdict-badge { display: inline-block; margin-top: 14px; padding: 6px 22px;
                     border-radius: 99px; font-weight: 700; font-size: 1rem; }
    #risk-message { margin-top: 10px; color: #8b949e; font-size: 0.92rem; }

    /* Scenarios */
    .scenarios { display: flex; gap: 14px; margin-bottom: 28px; flex-wrap: wrap; }
    .scenario-btn { flex: 1; min-width: 200px; padding: 16px; border-radius: 10px; border: none;
                    cursor: pointer; font-size: 0.95rem; font-weight: 600; transition: transform 0.1s; }
    .scenario-btn:active { transform: scale(0.97); }
    .btn-normal  { background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb; }
    .btn-scam    { background: #9e6a0333; color: #d29922; border: 1px solid #9e6a03; }
    .btn-screen  { background: #6e101033; color: #f85149; border: 1px solid #6e1010; }

    /* Reasons list */
    #reasons-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; }
    #reasons-list { list-style: none; margin-top: 10px; }
    #reasons-list li { padding: 7px 0; border-bottom: 1px solid #21262d; font-size: 0.88rem; color: #8b949e; }
    #reasons-list li::before { content: "⚡ "; }

    /* Stats bar */
    #stats-bar { display: flex; gap: 18px; margin-bottom: 28px; flex-wrap: wrap; }
    .stat-card { flex: 1; min-width: 130px; background: #161b22; border: 1px solid #30363d;
                 border-radius: 10px; padding: 16px; text-align: center; }
    .stat-card .val { font-size: 2rem; font-weight: 700; color: #58a6ff; }
    .stat-card .lbl { font-size: 0.75rem; color: #8b949e; margin-top: 4px; }
  </style>
</head>
<body>
<header>
  <div>
    <h1>🛡️ BehaviorShield</h1>
    <span>Real-Time Behavioural Fraud Detection — Live Demo</span>
  </div>
</header>

<div class="container">

  <!-- Stats -->
  <div id="stats-bar">
    <div class="stat-card"><div class="val" id="s-total">0</div><div class="lbl">Total Checks</div></div>
    <div class="stat-card"><div class="val" id="s-blocked" style="color:#f85149">0</div><div class="lbl">Blocked</div></div>
    <div class="stat-card"><div class="val" id="s-warned" style="color:#d29922">0</div><div class="lbl">Warned</div></div>
    <div class="stat-card"><div class="val" id="s-allowed" style="color:#3fb950">0</div><div class="lbl">Allowed</div></div>
    <div class="stat-card"><div class="val" id="s-fraud">0%</div><div class="lbl">Fraud Rate</div></div>
  </div>

  <!-- Meter -->
  <div class="meter-wrap">
    <div id="score-num" style="color:#3fb950">0</div>
    <div style="color:#8b949e; font-size:0.85rem; margin-top:4px;">Risk Score (0–100)</div>
    <div class="meter-bar-bg"><div id="meter-bar"></div></div>
    <div id="verdict-badge" style="background:#1a3a1a; color:#3fb950;">WAITING</div>
    <div id="risk-message">Press a scenario button below to run the engine.</div>
  </div>

  <!-- Scenario buttons -->
  <h2>🎯 Judge Demo Scenarios</h2>
  <div class="scenarios">
    <button class="scenario-btn btn-normal"  onclick="runScenario('normal')">✅ Normal Transaction<br><small style="font-weight:400">₹500 · known beneficiary</small></button>
    <button class="scenario-btn btn-scam"    onclick="runScenario('scam')">📞 Scam Call Fraud<br><small style="font-weight:400">₹75,000 · copy-paste · OTP retry</small></button>
    <button class="scenario-btn btn-screen"  onclick="runScenario('screen')">🖥️ Screen-Share Attack<br><small style="font-weight:400">₹2,00,000 · screen sharing · new beneficiary</small></button>
  </div>

  <!-- Reasons -->
  <div id="reasons-box">
    <h2>🔍 Risk Signals Detected</h2>
    <ul id="reasons-list"><li>No signals yet — run a scenario above.</li></ul>
  </div>

</div>

<script>
const SCENARIOS = {
  normal: { amount:500, new_beneficiary:false, copy_paste:false, otp_retry:false,
            screen_sharing:false, app_switching:false, typing_speed_wpm:42 },
  scam:   { amount:75000, new_beneficiary:true, copy_paste:true, otp_retry:true,
            screen_sharing:false, app_switching:true, typing_speed_wpm:130 },
  screen: { amount:200000, new_beneficiary:true, copy_paste:true, otp_retry:false,
            screen_sharing:true, app_switching:true, typing_speed_wpm:95 }
};

async function runScenario(key) {
  const payload = SCENARIOS[key];
  const res  = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  updateUI(data);
  fetchStats();
}

function updateUI(data) {
  const score = data.score;
  document.getElementById('score-num').textContent = score;
  document.getElementById('meter-bar').style.width = score + '%';
  document.getElementById('risk-message').textContent = data.message;

  const badge  = document.getElementById('verdict-badge');
  const num    = document.getElementById('score-num');
  const bar    = document.getElementById('meter-bar');

  if (data.verdict === 'blocked') {
    badge.style.cssText = 'background:#3a0f0f; color:#f85149;';
    badge.textContent   = '🚫 BLOCKED';
    num.style.color     = '#f85149';
    bar.style.background= '#f85149';
  } else if (data.verdict === 'warned') {
    badge.style.cssText = 'background:#3a2a0f; color:#d29922;';
    badge.textContent   = '⚠️ WARNING';
    num.style.color     = '#d29922';
    bar.style.background= '#d29922';
  } else {
    badge.style.cssText = 'background:#0f3a1a; color:#3fb950;';
    badge.textContent   = '✅ ALLOWED';
    num.style.color     = '#3fb950';
    bar.style.background= '#3fb950';
  }

  const list = document.getElementById('reasons-list');
  if (data.reasons && data.reasons.length) {
    list.innerHTML = data.reasons.map(r => `<li>${r}</li>`).join('');
  } else {
    list.innerHTML = '<li>No risk signals found — transaction looks normal.</li>';
  }
}

async function fetchStats() {
  const res  = await fetch('/api/stats');
  const data = await res.json();
  document.getElementById('s-total').textContent   = data.total;
  document.getElementById('s-blocked').textContent = data.blocked;
  document.getElementById('s-warned').textContent  = data.warned;
  document.getElementById('s-allowed').textContent = data.allowed;
  document.getElementById('s-fraud').textContent   = data.fraud_rate_pct + '%';
}

fetchStats();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DEMO_HTML)


if __name__ == "__main__":
    print("\n✅ BehaviorShield is running!")
    print("   Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)