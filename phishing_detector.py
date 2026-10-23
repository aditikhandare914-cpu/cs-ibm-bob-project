"""
CyberShield — Phishing Detection Engine
Pure Python heuristics — no API keys or external services required.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# ---------------------------------------------------------------------------
# Suspicious keyword lists
# ---------------------------------------------------------------------------

PHISHING_KEYWORDS = [
    "verify", "account", "secure", "update", "login", "signin", "bank",
    "paypal", "ebay", "amazon", "apple", "microsoft", "google", "netflix",
    "confirm", "password", "credential", "suspended", "unusual", "activity",
    "click", "here", "free", "winner", "prize", "urgent", "immediate",
    "limited", "offer", "expire", "billing", "invoice", "payment", "refund",
    "alert", "warning", "notification", "validate", "reactivate", "unlock",
    "webscr", "cmd=", "dispatch", "checkout", "support", "helpdesk",
    "customer-service", "recover", "reset", "auth", "oauth", "sso",
]

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "github.com", "wikipedia.org", "reddit.com",
    "paypal.com", "ebay.com", "yahoo.com", "bing.com", "adobe.com",
    "zoom.us", "dropbox.com", "wordpress.com", "shopify.com",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".site", ".online", ".tech", ".live", ".icu", ".bid", ".loan", ".win",
    ".click", ".download", ".stream", ".gdn", ".racing", ".review",
    ".accountant", ".science", ".trade", ".date", ".faith", ".party",
    ".cricket", ".men", ".webcam", ".kim", ".country", ".realtor",
}

BRAND_IMPERSONATION = {
    "paypa1", "paypai", "payp4l", "g00gle", "g0ogle", "go0gle",
    "amaz0n", "amаzon", "micrsoft", "microsft", "micros0ft",
    "app1e", "faceb00k", "facebok", "linkedln", "twitterr",
    "netfl1x", "netfl1x", "ebay1", "1ebay",
}

# ---------------------------------------------------------------------------
# URL Analysis
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for phishing indicators.
    Returns a dict with score (0-100), risk_level, findings, and details.
    """
    findings = []
    score = 0  # higher = more suspicious

    # Normalise
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return _build_result(100, ["Invalid URL — could not parse"], url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme

    full_domain = hostname.lower()
    # Strip www.
    domain = re.sub(r"^www\.", "", full_domain)

    # ------------------------------------------------------------------
    # 1. HTTPS check
    if scheme != "https":
        score += 15
        findings.append("Uses HTTP (not HTTPS) — data is transmitted unencrypted.")

    # ------------------------------------------------------------------
    # 2. IP address instead of domain name
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ip_pattern.match(hostname):
        score += 30
        findings.append("URL uses an IP address instead of a domain name — common phishing tactic.")

    # ------------------------------------------------------------------
    # 3. Trusted domain shortcut
    root = _root_domain(domain)
    if root in TRUSTED_DOMAINS:
        return _build_result(0, ["Domain is a well-known trusted website."], url, safe=True)

    # ------------------------------------------------------------------
    # 4. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            findings.append(f"Uses a high-risk TLD: '{tld}' — frequently abused for phishing.")
            break

    # ------------------------------------------------------------------
    # 5. Excessive subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        score += 15
        findings.append(f"Excessive subdomains ({len(parts) - 2} levels) — may be disguising true destination.")

    # ------------------------------------------------------------------
    # 6. Brand name impersonation in domain
    for brand in BRAND_IMPERSONATION:
        if brand in domain:
            score += 35
            findings.append(f"Domain contains a brand impersonation pattern: '{brand}'.")
            break

    # ------------------------------------------------------------------
    # 7. Known brand name + extra words (e.g., paypal-secure-login.com)
    for brand in ["paypal", "google", "amazon", "apple", "microsoft", "netflix",
                  "ebay", "facebook", "instagram", "twitter", "linkedin"]:
        if brand in domain and root != brand + ".com":
            score += 25
            findings.append(f"Domain spoofs a known brand ('{brand}') but is not the official site.")
            break

    # ------------------------------------------------------------------
    # 8. Long URL
    if len(url) > 100:
        score += 10
        findings.append(f"URL is unusually long ({len(url)} characters) — often used to hide destination.")

    # ------------------------------------------------------------------
    # 9. Multiple redirects / '@' in URL
    if "@" in url:
        score += 20
        findings.append("URL contains '@' character — browser ignores everything before it (redirect trick).")

    # ------------------------------------------------------------------
    # 10. Double slash redirect
    if re.search(r"(https?:\/\/.+)(\/\/)", url):
        score += 15
        findings.append("URL contains double-slash redirect pattern.")

    # ------------------------------------------------------------------
    # 11. Phishing keywords in URL
    url_lower = url.lower()
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if len(matched_kw) >= 3:
        score += 20
        findings.append(f"URL contains multiple suspicious keywords: {', '.join(matched_kw[:5])}.")
    elif matched_kw:
        score += 8
        findings.append(f"URL contains suspicious keyword(s): {', '.join(matched_kw[:3])}.")

    # ------------------------------------------------------------------
    # 12. High entropy domain (random-looking)
    domain_entropy = _entropy(domain.split(".")[0])
    if domain_entropy > 4.0:
        score += 15
        findings.append(f"Domain name appears randomly generated (entropy={domain_entropy:.2f}) — characteristic of phishing.")

    # ------------------------------------------------------------------
    # 13. Hyphens in domain
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        score += 15
        findings.append(f"Domain contains {hyphen_count} hyphens — common pattern in phishing domains.")
    elif hyphen_count >= 1:
        score += 5

    # ------------------------------------------------------------------
    # 14. Numeric characters in domain
    nums = sum(c.isdigit() for c in domain.split(".")[0])
    if nums >= 3:
        score += 10
        findings.append("Domain contains multiple numeric characters — suspicious pattern.")

    # ------------------------------------------------------------------
    # 15. Suspicious query parameters
    if query:
        q_lower = query.lower()
        suspicious_params = ["redirect", "url=", "return=", "redir=", "next=", "goto="]
        for p in suspicious_params:
            if p in q_lower:
                score += 10
                findings.append(f"URL contains suspicious redirect parameter: '{p}'.")
                break

    score = min(score, 100)

    if not findings:
        findings.append("No obvious phishing indicators detected.")

    return _build_result(score, findings, url)


def _root_domain(domain: str) -> str:
    """Extract root domain (last two parts)."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _build_result(score: int, findings: list, url: str, safe: bool = False) -> dict:
    if safe or score <= 20:
        risk_level = "Safe"
        risk_color = "green"
    elif score <= 45:
        risk_level = "Low Risk"
        risk_color = "blue"
    elif score <= 65:
        risk_level = "Moderate Risk"
        risk_color = "orange"
    elif score <= 80:
        risk_level = "High Risk"
        risk_color = "red"
    else:
        risk_level = "Critical — Likely Phishing"
        risk_color = "darkred"

    return {
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "findings": findings,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Email Analysis
# ---------------------------------------------------------------------------

URGENT_WORDS = [
    "urgent", "immediate", "act now", "limited time", "expires",
    "verify now", "confirm now", "click here", "winner", "congratulations",
    "you have been selected", "free gift", "claim your", "last chance",
    "account suspended", "unusual activity", "verify your account",
    "update your information", "security alert",
]

def analyze_email(subject: str, sender: str, body: str) -> dict:
    """Analyze email for phishing/spam indicators."""
    findings = []
    score = 0

    subject_lower = subject.lower()
    sender_lower = sender.lower()
    body_lower = body.lower()
    combined = subject_lower + " " + body_lower

    # 1. Urgent language
    matched_urgent = [w for w in URGENT_WORDS if w in combined]
    if len(matched_urgent) >= 3:
        score += 30
        findings.append(f"Contains multiple urgency triggers: {', '.join(matched_urgent[:4])}.")
    elif matched_urgent:
        score += 12
        findings.append(f"Contains urgency language: '{matched_urgent[0]}'.")

    # 2. Suspicious sender domain
    sender_match = re.search(r"@([\w.\-]+)", sender_lower)
    if sender_match:
        s_domain = sender_match.group(1)
        for tld in SUSPICIOUS_TLDS:
            if s_domain.endswith(tld.lstrip(".")):
                score += 25
                findings.append(f"Sender uses a high-risk domain: '{s_domain}'.")
                break
        # Numeric-heavy sender
        if sum(c.isdigit() for c in s_domain) >= 3:
            score += 15
            findings.append("Sender email domain contains many numbers — suspicious.")

    # 3. Display name vs actual email mismatch pattern
    if "<" in sender and ">" in sender:
        display = sender[:sender.index("<")].strip().lower()
        for brand in ["paypal", "amazon", "apple", "google", "microsoft", "netflix", "ebay"]:
            if brand in display:
                actual_match = re.search(r"<(.+?)>", sender)
                if actual_match:
                    actual_domain = actual_match.group(1).split("@")[-1].lower()
                    if brand not in actual_domain:
                        score += 35
                        findings.append(
                            f"Sender display name claims to be '{brand.title()}' but email is from '{actual_domain}' — spoofing."
                        )

    # 4. Links in body
    urls_in_body = re.findall(r"https?://[^\s<>\"']+", body)
    if urls_in_body:
        score += 5
        findings.append(f"Email contains {len(urls_in_body)} clickable link(s) — inspect carefully.")

    # 5. Requests for sensitive info
    sensitive_patterns = [
        r"password", r"social security", r"ssn", r"credit card",
        r"bank account", r"pin\b", r"cvv", r"mother'?s maiden",
    ]
    for pat in sensitive_patterns:
        if re.search(pat, combined):
            score += 20
            findings.append(f"Email requests sensitive information ('{pat.strip(chr(92)+'b')}').")
            break

    # 6. Generic salutation
    if re.search(r"dear (customer|user|member|account holder|valued customer)", combined):
        score += 10
        findings.append("Uses generic salutation ('Dear Customer') instead of your name — mass phishing indicator.")

    # 7. Misspellings of brands
    for brand in BRAND_IMPERSONATION:
        if brand in combined:
            score += 25
            findings.append(f"Contains misspelled brand name '{brand}' — impersonation attempt.")
            break

    score = min(score, 100)

    if not findings:
        findings.append("No obvious phishing indicators detected in this email.")

    if score <= 20:
        risk_level, risk_color = "Likely Safe", "green"
    elif score <= 45:
        risk_level, risk_color = "Suspicious", "orange"
    elif score <= 70:
        risk_level, risk_color = "High Risk — Probable Phishing", "red"
    else:
        risk_level, risk_color = "Critical — Almost Certainly Phishing", "darkred"

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "findings": findings,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Password Strength
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "admin", "welcome", "login", "hello",
    "charlie", "donald", "password2", "qwerty123", "admin123",
}

def check_password(password: str) -> dict:
    """Evaluate password strength."""
    findings = []
    score = 0
    suggestions = []

    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "strength": "Critically Weak",
            "strength_color": "darkred",
            "findings": ["This is one of the most commonly used passwords — immediately change it!"],
            "suggestions": ["Use a random passphrase of 4+ words.", "Use a password manager to generate strong passwords."],
            "percentage": 5,
        }

    length = len(password)

    # Length
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        score += 0
        findings.append(f"Password is too short ({length} characters). Use at least 12.")
        suggestions.append("Increase length to at least 12 characters.")

    # Character variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_lower, has_upper, has_digit, has_special])
    score += variety * 12

    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_digit:
        suggestions.append("Add numbers.")
    if not has_special:
        suggestions.append("Add special characters (!, @, #, $, etc.).")

    # Entropy bonus
    ent = _entropy(password)
    if ent > 4.0:
        score += 15
    elif ent > 3.0:
        score += 8

    # Repeated characters
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        findings.append("Contains repeated characters (e.g., 'aaa') — weakens the password.")
        suggestions.append("Avoid repeating characters.")

    # Sequential patterns
    for seq in ["abcdef", "qwerty", "123456", "654321", "abcabc"]:
        if seq in password.lower():
            score -= 10
            findings.append(f"Contains predictable sequence '{seq}'.")
            suggestions.append("Avoid keyboard patterns and sequential strings.")
            break

    score = max(0, min(score, 100))

    if score >= 80:
        strength, color = "Very Strong", "green"
        findings.append("Excellent password strength!")
    elif score >= 60:
        strength, color = "Strong", "#2d8a2d"
        findings.append("Good password strength.")
    elif score >= 40:
        strength, color = "Moderate", "orange"
        findings.append("Password could be stronger.")
    elif score >= 20:
        strength, color = "Weak", "red"
        findings.append("Password is weak and easy to crack.")
    else:
        strength, color = "Very Weak", "darkred"
        findings.append("Password is very weak — do not use it.")

    if not suggestions:
        suggestions.append("Consider using a passphrase (multiple random words joined together).")

    return {
        "score": score,
        "strength": strength,
        "strength_color": color,
        "findings": findings,
        "suggestions": suggestions,
        "percentage": score,
    }
