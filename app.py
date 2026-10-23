"""
CyberShield — Flask Application
Run: python app.py
"""

from flask import Flask, render_template, request, jsonify
from phishing_detector import analyze_url, analyze_email, check_password

app = Flask(__name__)
app.secret_key = "cybershield-secret-2024"

# ---------------------------------------------------------------------------
# Page Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/url-scanner")
def url_scanner():
    return render_template("url_scanner.html")


@app.route("/email-analyzer")
def email_analyzer():
    return render_template("email_analyzer.html")


@app.route("/password-checker")
def password_checker():
    return render_template("password_checker.html")


@app.route("/awareness")
def awareness():
    return render_template("awareness.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    result = analyze_url(url)
    return jsonify(result)


@app.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    data = request.get_json(silent=True) or {}
    subject = (data.get("subject") or "").strip()
    sender  = (data.get("sender") or "").strip()
    body    = (data.get("body") or "").strip()
    if not (subject or sender or body):
        return jsonify({"error": "Please provide at least one email field."}), 400
    result = analyze_email(subject, sender, body)
    return jsonify(result)


@app.route("/api/check-password", methods=["POST"])
def api_check_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "No password provided."}), 400
    result = check_password(password)
    return jsonify(result)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  CyberShield — Phishing Detection & Cybersecurity")
    print("  Server running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
