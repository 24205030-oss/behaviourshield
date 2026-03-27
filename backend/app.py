from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from datetime import datetime
import json
import os

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────
#  SIGNAL WEIGHTS  (tweak these to adjust sensitivity)
# ─────────────────────────────────────────────────────────────
SIGNAL_WEIGHTS = {
    "new_beneficiary":    30,
    "large_amount":       20,   # > 50,000
    "very_large_amount":  10,   # > 1,00,000 (extra on top)
    "fast_typing":        15,
    "copy_paste":         20,
    "app_switching":      20,
    "otp_retry":          15,
    "late_night":         10,   # auto-detected 1am–5am
    "screen_sharing":     25,
}

LOG_FILE = "transactions.json"


# ─────────────────────────────────────────────────────────────
#  CORE RISK ENGINE
# ─────────────────────────────────────────────────────────────
def compute_risk(data: dict) -> dict:
    score     = 0
    triggered = []
    amount    = data.get("amount", 0)
    hour      = datetime.now().hour

    # — Transaction signals —
    if data.get("new_beneficiary"):
        score += SIGNAL_WEIGHTS["new_beneficiary"]
        triggered.append("new_beneficiary")

    if amount > 50_000:
        score += SIGNAL_WEIGHTS["large_amount"]
        triggered.append("large_amount")

    if amount > 1_00_000:
        score += SIGNAL_WEIGHTS["very_large_amount"]
        triggered.append("very_large_amount")

    # — Behavioral signals —
    if data.get("fast_typing"):
        score += SIGNAL_WEIGHTS["fast_typing"]
        triggered.append("fast_typing")

    if data.get("copy_paste"):
        score += SIGNAL_WEIGHTS["copy_paste"]
        triggered.append("copy_paste")

    if data.get("app_switching"):
        score += SIGNAL_WEIGHTS["app_switching"]
        triggered.append("app_switching")

    if data.get("otp_retry"):
        score += SIGNAL_WEIGHTS["otp_retry"]
        triggered.append("otp_retry")

    if data.get("screen_sharing"):
        score += SIGNAL_WEIGHTS["screen_sharing"]
        triggered.append("screen_sharing")

    # — Context signals (auto-detected) —
    if 1 <= hour <= 5:
        score += SIGNAL_WEIGHTS["late_night"]
        triggered.append("late_night")

    score = min(score, 100)

    # — Verdict —
    if score < 30:
        verdict = "safe"
        action  = "ALLOW"
        message = "Transaction approved. No suspicious signals detected."
        cooldown_seconds = 0
    elif score < 65:
        verdict = "warning"
        action  = "WARN"
        message = ("Warning: Are you on a call with someone asking you "
                   "to transfer money? Please verify before continuing.")
        cooldown_seconds = 0
    else:
        verdict = "blocked"
        action  = "BLOCK"
        message = ("Transaction blocked. High manipulation risk detected. "
                   "A 30-second cooldown has been applied. "
                   "Did someone ask you to do this urgently?")
        cooldown_seconds = 30

    return {
        "score":            score,
        "verdict":          verdict,
        "action":           action,
        "message":          message,
        "triggered":        triggered,
        "cooldown_seconds": cooldown_seconds,
        "timestamp":        datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────
#  LOGGING HELPER
# ─────────────────────────────────────────────────────────────
def save_log(data: dict, result: dict):
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
    logs.append({"input": data, "result": result})
    with open(LOG_FILE, "w") as f:
        json.dump(logs[-100:], f, indent=2)   # keep last 100


# ─────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_DEMO)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    POST /api/analyze
    {
        "amount":          75000,
        "new_beneficiary": true,
        "fast_typing":     false,
        "copy_paste":      true,
        "app_switching":   false,
        "otp_retry":       true,
        "screen_sharing":  false
    }
    """
    data = request.get_json(force=True)

    if not data:
        return jsonify({"error": "No JSON body provided"}), 400
    if "amount" not in data:
        return jsonify({"error": "'amount' field is required"}), 422

    result = compute_risk(data)
    save_log(data, result)
    return jsonify(result), 200


@app.route("/api/history", methods=["GET"])
def history():
    """Returns last 20 flagged transactions."""
    if not os.path.exists(LOG_FILE):
        return jsonify([]), 200
    with open(LOG_FILE, "r") as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            return jsonify([]), 200
    flagged = [l for l in logs if l["result"]["verdict"] != "safe"]
    return jsonify(flagged[-20:]), 200


@app.route("/api/signals", methods=["GET"])
def signals():
    """Returns all signal names and their weights."""
    return jsonify(SIGNAL_WEIGHTS), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "BehaviorShield"}), 200


# ─────────────────────────────────────────────────────────────
#  BUILT-IN DEMO UI
# ─────────────────────────────────────────────────────────────
HTML_DEMO = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BehaviorShield</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, sans-serif; background: #f5f5f0;
       display: flex; justify-content: center; padding: 2rem 1rem; color: #222; }
.wrap { width: 100%; max-width: 480px; }
h1   { font-size: 20px; font-weight: 700; margin-bottom: 2px; }
.sub { font-size: 13px; color: #888; margin-bottom: 1.5rem; }
.card { background: #fff; border: 1px solid #e0e0d8; border-radius: 14px;
        padding: 1.25rem; margin-bottom: 1rem; }
label { font-size: 12px; color: #666; display: block; margin-bottom: 4px; }
input[type=number], select { width: 100%; padding: 9px 11px; border: 1px solid #ddd;
  border-radius: 8px; font-size: 14px; margin-bottom: 12px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.checks { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin: 4px 0 14px; }
.chk { display: flex; align-items: center; gap: 7px; font-size: 13px;
       cursor: pointer; padding: 6px 8px; border-radius: 8px;
       border: 1px solid #eee; user-select: none; }
.chk:hover { background: #f8f8f4; }
.chk input { width: 14px; height: 14px; cursor: pointer; }
.sc-row { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
.sc { padding: 5px 12px; border-radius: 20px; font-size: 12px; cursor: pointer;
      border: 1px solid #ddd; background: #fff; color: #555; }
.sc.on { border-color: #378add; color: #185fa5; background: #e6f1fb; }
.btn { width: 100%; padding: 12px; border-radius: 10px; font-size: 15px;
       font-weight: 600; border: none; cursor: pointer; background: #1a1a1a;
       color: #fff; letter-spacing: .01em; }
.btn:hover { background: #333; }
.bar-bg { height: 10px; background: #eee; border-radius: 5px; overflow: hidden; margin: 6px 0 14px; }
.bar-fill { height: 100%; border-radius: 5px; width: 0%;
            transition: width .45s ease, background .45s ease; }
.verdict { padding: 12px 14px; border-radius: 10px; font-size: 13px;
           line-height: 1.5; margin-bottom: 10px; }
.v-safe    { background: #eaf3de; color: #2a5009; border: 1px solid #97c459; }
.v-warning { background: #faeeda; color: #5a3200; border: 1px solid #ef9f27; }
.v-blocked { background: #fcebeb; color: #4a1010; border: 1px solid #e24b4a; }
.tag { display: inline-block; font-size: 11px; padding: 2px 9px; border-radius: 20px;
       background: #f0f0ea; color: #555; margin: 2px; }
.meta { font-size: 11px; color: #aaa; margin-top: 8px; }
.score-big { font-size: 32px; font-weight: 700; }
#result { display: none; }
.timer { font-size: 28px; font-weight: 700; color: #e24b4a; text-align: center;
         padding: 8px 0; }
</style>
</head>
<body>
<div class="wrap">
  <h1>BehaviorShield</h1>
  <p class="sub">Real-time scam manipulation detector</p>

  <div class="card">
    <div class="sc-row">
      <button class="sc on" onclick="scene('normal',this)">Normal transfer</button>
      <button class="sc"    onclick="scene('scam',this)">Scam call</button>
      <button class="sc"    onclick="scene('screen',this)">Screen-share fraud</button>
    </div>

    <div class="grid2">
      <div>
        <label>Amount (INR)</label>
        <input type="number" id="amount" value="500" min="0">
      </div>
      <div>
        <label>Beneficiary</label>
        <select id="benef">
          <option value="0">Known contact</option>
          <option value="1">New / unknown</option>
        </select>
      </div>
    </div>

    <label>Behavioral signals observed</label>
    <div class="checks">
      <label class="chk"><input type="checkbox" id="fast_typing"> Fast typing</label>
      <label class="chk"><input type="checkbox" id="copy_paste"> Copy-paste</label>
      <label class="chk"><input type="checkbox" id="app_switching"> App switching</label>
      <label class="chk"><input type="checkbox" id="otp_retry"> OTP retry</label>
      <label class="chk"><input type="checkbox" id="screen_sharing"> Screen sharing</label>
    </div>

    <button class="btn" onclick="analyze()">Analyze transaction</button>
  </div>

  <div class="card" id="result">
    <label>Risk score</label>
    <div class="score-big" id="score-num">0</div>
    <div class="bar-bg"><div class="bar-fill" id="bar"></div></div>
    <div class="verdict" id="verdict-box"></div>
    <div id="timer-wrap" style="display:none">
      <div class="timer" id="timer">30</div>
      <p style="text-align:center;font-size:12px;color:#aaa;margin-bottom:8px">
        seconds cooldown remaining
      </p>
    </div>
    <div id="tags"></div>
    <div class="meta" id="ts"></div>
  </div>
</div>

<script>
function scene(name, btn) {
  document.querySelectorAll('.sc').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  ['fast_typing','copy_paste','app_switching','otp_retry','screen_sharing']
    .forEach(id => document.getElementById(id).checked = false);

  if (name === 'normal') {
    document.getElementById('amount').value = 500;
    document.getElementById('benef').value  = '0';
  } else if (name === 'scam') {
    document.getElementById('amount').value = 75000;
    document.getElementById('benef').value  = '1';
    ['fast_typing','copy_paste','otp_retry'].forEach(id =>
      document.getElementById(id).checked = true);
  } else {
    document.getElementById('amount').value = 200000;
    document.getElementById('benef').value  = '1';
    ['copy_paste','app_switching','screen_sharing'].forEach(id =>
      document.getElementById(id).checked = true);
  }
}

let timerInterval = null;

async function analyze() {
  const body = {
    amount:          parseInt(document.getElementById('amount').value) || 0,
    new_beneficiary: document.getElementById('benef').value === '1',
    fast_typing:     document.getElementById('fast_typing').checked,
    copy_paste:      document.getElementById('copy_paste').checked,
    app_switching:   document.getElementById('app_switching').checked,
    otp_retry:       document.getElementById('otp_retry').checked,
    screen_sharing:  document.getElementById('screen_sharing').checked,
  };

  const res  = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await res.json();

  document.getElementById('result').style.display = 'block';
  document.getElementById('score-num').textContent = data.score;

  const bar = document.getElementById('bar');
  bar.style.width      = data.score + '%';
  bar.style.background = data.score < 30 ? '#639922'
                       : data.score < 65 ? '#BA7517' : '#E24B4A';

  const vbox = document.getElementById('verdict-box');
  vbox.className = 'verdict v-' + data.verdict;
  vbox.textContent = data.message;

  document.getElementById('tags').innerHTML =
    data.triggered.map(t =>
      `<span class="tag">${t.replace(/_/g,' ')}</span>`
    ).join('');

  document.getElementById('ts').textContent =
    'Analyzed at ' + new Date(data.timestamp).toLocaleTimeString();

  // Cooldown timer
  clearInterval(timerInterval);
  const twrap = document.getElementById('timer-wrap');
  if (data.cooldown_seconds > 0) {
    twrap.style.display = 'block';
    let t = data.cooldown_seconds;
    document.getElementById('timer').textContent = t;
    timerInterval = setInterval(() => {
      t--;
      document.getElementById('timer').textContent = t;
      if (t <= 0) { clearInterval(timerInterval); twrap.style.display = 'none'; }
    }, 1000);
  } else {
    twrap.style.display = 'none';
  }
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n  BehaviorShield is running!")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)