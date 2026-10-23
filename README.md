# 🛡️ CyberShield — Phishing Detection & Cybersecurity Awareness System

> A complete, professional cybersecurity web application built with **Python & Flask**.  
> No Node.js · No Docker · No API keys · No cloud · No data stored · 100% local.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation & Setup](#installation--setup)
- [Running the Application](#running-the-application)
- [Pages & Tools](#pages--tools)
- [Detection Engine](#detection-engine)
- [API Reference](#api-reference)
- [Technology Stack](#technology-stack)
- [Privacy Policy](#privacy-policy)
- [Screenshots](#screenshots)

---

## Overview

**CyberShield** is a locally-hosted cybersecurity awareness platform that provides:

- Real-time **phishing URL detection** using 13+ heuristic checks
- **Email phishing analysis** for spoofed senders, urgency language, and brand impersonation
- **Password strength evaluation** with entropy scoring and common-password blocking
- An interactive **cybersecurity awareness module** with tips, examples, a checklist, and a quiz

Everything runs on your own machine. No internet connection is required after setup. No data you enter is ever stored, logged, or sent anywhere.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **URL Scanner** | Analyzes any URL for phishing indicators with a 0–100 risk score |
| 📧 **Email Analyzer** | Detects phishing in email sender, subject, and body text |
| 🔐 **Password Checker** | Live strength meter, entropy analysis, and password generation |
| 📚 **Awareness Hub** | Tips, red-flag guide, interactive checklist, 5-question quiz |
| ℹ️ **About Page** | Engine internals, tech stack, privacy policy, quick-start guide |
| 🌙 **Dark UI** | Professional dark-theme interface — responsive on all screen sizes |

---

## Project Structure

```
CYBERSHIELD/
│
├── app.py                      # Flask application — routes & API endpoints
├── phishing_detector.py        # Python detection engine (pure stdlib, no API keys)
├── README.md                   # This file
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Shared layout: navbar, footer, meta
│   ├── index.html              # Home page
│   ├── url_scanner.html        # Phishing URL Scanner page
│   ├── email_analyzer.html     # Email Phishing Analyzer page
│   ├── password_checker.html   # Password Strength Checker page
│   ├── awareness.html          # Cybersecurity Awareness + Quiz page
│   └── about.html              # About / Tech details page
│
└── static/
    ├── css/
    │   └── style.css           # Full dark-theme design system
    └── js/
        ├── url_scanner.js      # URL scanner frontend logic
        ├── email_analyzer.js   # Email analyzer frontend logic
        ├── password_checker.js # Password checker + live meter + generator
        └── awareness.js        # Checklist + quiz interactive logic
```

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.8 or higher |
| Flask | 2.x or 3.x |

**No other dependencies.** The detection engine uses only Python's standard library (`re`, `math`, `urllib.parse`, `datetime`).

---

## Installation & Setup

### Step 1 — Clone or download the project

Place the `CYBERSHIELD` folder anywhere on your machine.

### Step 2 — Install Flask

Open a terminal (PowerShell, CMD, or bash) and run:

```bash
python -m pip install flask
```

> If you already have Flask installed (`flask` appears in `python -m pip list`), skip this step.

### Step 3 — Verify your setup

```bash
python -c "import flask; print('Flask', flask.__version__, '— ready')"
```

Expected output: `Flask 3.x.x — ready`

---

## Running the Application

```bash
# Navigate to the project folder
cd path/to/CYBERSHIELD

# Start the Flask server
python app.py
```

You will see:

```
============================================================
  CyberShield — Phishing Detection & Cybersecurity
  Server running at: http://127.0.0.1:5000
============================================================
 * Running on http://127.0.0.1:5000
```

Open your browser and go to:

```
http://127.0.0.1:5000
```

Press `Ctrl+C` in the terminal to stop the server.

---

## Pages & Tools

### 🏠 Home — `/`
- Hero section with call-to-action buttons
- Live cybercrime statistics (3.4B phishing emails/day, $17.7K lost/minute)
- Feature cards linking to all tools
- How It Works (3-step flow)
- Common threat type overview

### 🔍 URL Scanner — `/url-scanner`
- Paste any URL and click **Scan URL** (or press Enter)
- Returns an animated SVG score ring (0–100), risk level badge, and a detailed findings list
- Three built-in example URLs to try instantly
- Explains all 13 checks performed

### 📧 Email Analyzer — `/email-analyzer`
- Enter the sender address, subject line, and body text
- One-click **Load Example** button populates a realistic phishing email
- Returns risk level, score, and itemized findings
- Includes a red-flags guide and "What to do" action list

### 🔐 Password Checker — `/password-checker`
- Live strength meter updates as you type (debounced)
- Show/hide password toggle
- **Generate Strong** button creates a cryptographically random 16-character password
- Full analysis on demand: findings + improvement suggestions
- Guides on how attackers crack passwords (brute force, dictionary, credential stuffing)

### 📚 Awareness — `/awareness`
- How to spot phishing (URLs, senders, urgency, HTTPS myths)
- Real vs Fake email comparison table
- Interactive 10-item security checklist with progress bar
- 5-question phishing awareness quiz with explanations
- Further learning resources (CISA, NCSC, FBI IC3, free tools)

### ℹ️ About — `/about`
- Mission statement
- Full breakdown of all detection checks
- Risk scoring table (Safe / Low / Moderate / High / Critical)
- Zero data collection privacy policy
- Technology stack details
- Quick-start instructions

---

## Detection Engine

### `phishing_detector.py` — Three functions

#### `analyze_url(url: str) → dict`

Runs 13 heuristic checks against any URL:

| Check | Points if triggered |
|---|---|
| HTTP (not HTTPS) | +15 |
| IP address instead of domain | +30 |
| High-risk TLD (.tk, .ml, .xyz, 30+ others) | +20 |
| Excessive subdomain depth (>4 levels) | +15 |
| Brand impersonation pattern (paypa1, g00gle…) | +35 |
| Known brand in non-official domain | +25 |
| URL length > 100 characters | +10 |
| @ character redirect trick | +20 |
| Double-slash redirect | +15 |
| 3+ phishing keywords in URL | +20 |
| High Shannon entropy domain | +15 |
| 3+ hyphens in domain | +15 |
| Suspicious redirect query parameter | +10 |

Returns: `{ url, score (0–100), risk_level, risk_color, findings[], scanned_at }`

#### `analyze_email(subject, sender, body: str) → dict`

Runs 8 checks:

| Check | Points if triggered |
|---|---|
| 3+ urgency phrases (18-phrase library) | +30 |
| Sender on high-risk TLD | +25 |
| Numeric-heavy sender domain | +15 |
| Display name / actual domain mismatch (spoofing) | +35 |
| Clickable links in body | +5 |
| Request for sensitive info (password, SSN, CVV…) | +20 |
| Generic salutation ("Dear Customer") | +10 |
| Misspelled brand in body | +25 |

Returns: `{ score (0–100), risk_level, risk_color, findings[], scanned_at }`

#### `check_password(password: str) → dict`

| Check | Effect |
|---|---|
| In 35-entry common-password list | Score = 0 immediately |
| Length 16+ / 12+ / 8+ | +30 / +20 / +10 |
| Uppercase, lowercase, digits, special chars | +12 each |
| Shannon entropy > 4.0 | +15 |
| Repeated characters (aaa…) | −10 |
| Sequential keyboard patterns | −10 |

Returns: `{ score (0–100), strength, strength_color, findings[], suggestions[], percentage }`

### Risk Level Thresholds

| Score | Risk Level |
|---|---|
| 0–20 | ✅ Safe |
| 21–45 | 🔵 Low Risk |
| 46–65 | 🟡 Moderate Risk |
| 66–80 | 🔴 High Risk |
| 81–100 | 🚨 Critical — Likely Phishing |

---

## API Reference

All endpoints accept and return `application/json`.

### `POST /api/scan-url`

**Request:**
```json
{ "url": "http://paypal-secure-login.tk/verify" }
```

**Response:**
```json
{
  "url": "http://paypal-secure-login.tk/verify",
  "score": 85,
  "risk_level": "Critical — Likely Phishing",
  "risk_color": "darkred",
  "findings": [
    "Uses HTTP (not HTTPS) — data is transmitted unencrypted.",
    "Uses a high-risk TLD: '.tk' — frequently abused for phishing.",
    "Domain spoofs a known brand ('paypal') but is not the official site.",
    "URL contains suspicious keyword(s): verify, secure, login."
  ],
  "scanned_at": "2026-10-23 20:15:00"
}
```

---

### `POST /api/analyze-email`

**Request:**
```json
{
  "subject": "URGENT: Your account suspended",
  "sender": "PayPal Support <billing@paypa1.ml>",
  "body": "Dear Customer, verify your password immediately..."
}
```

**Response:**
```json
{
  "score": 100,
  "risk_level": "Critical — Almost Certainly Phishing",
  "risk_color": "darkred",
  "findings": ["..."],
  "scanned_at": "2026-10-23 20:15:00"
}
```

---

### `POST /api/check-password`

**Request:**
```json
{ "password": "correctHorseBatteryStaple99!" }
```

**Response:**
```json
{
  "score": 86,
  "strength": "Very Strong",
  "strength_color": "green",
  "findings": ["Excellent password strength!"],
  "suggestions": ["Consider using a passphrase (multiple random words joined together)."],
  "percentage": 86
}
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ |
| Web Framework | Flask 3.x |
| Templating | Jinja2 |
| WSGI | Werkzeug |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Async Requests | Fetch API |
| Password Generation | Web Crypto API (`window.crypto.getRandomValues`) |
| Detection Logic | Python standard library only (`re`, `math`, `urllib.parse`) |

---

## Privacy Policy

**CyberShield collects zero data.**

- All processing happens in memory on your local machine.
- No database is used. No files are written. Nothing is logged.
- URLs, email content, and passwords you enter are discarded immediately after the response is sent.
- The only network traffic is between your browser and `127.0.0.1:5000` — it never leaves your computer.

---

## License

This project is free to use for educational and personal purposes.

---

*Built with Python & Flask — no external services, no API keys, no data collection.*
