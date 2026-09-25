"""
Tool C: Heuristic URL & Phishing Threat Detection Module.
Evaluates input URLs for suspicious mechanics, typosquatting, homoglyphs,
IP-based hostnames, excessive subdomains, and obfuscation heuristics.
"""

import math
import re
import urllib.parse
from typing import Dict, Any, List

SUSPICIOUS_TLDS = {
    "tk", "xyz", "top", "zip", "gq", "cf", "ml", "cc", "buzz", "fit", "pw",
    "work", "cam", "live", "mov", "su", "icu", "rest", "bar", "monster", "click"
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "banking", "secure", "update",
    "wallet", "account", "authenticate", "webscr", "ebayisapi", "security",
    "confirm", "recovery", "billing", "invoice", "free-gift", "claim", "paypal",
    "appleid", "netflix", "microsoft", "google-security", "chase-bank"
]

IP_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for domain string to detect randomized DGA names."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 2)

def analyze_url(url: str) -> Dict[str, Any]:
    """Perform heuristic phishing inspection across multiple risk vectors."""
    cleaned_url = url.strip()
    if not cleaned_url:
        return {"error": "URL cannot be empty."}

    # Normalize protocol if missing
    if not cleaned_url.startswith(("http://", "https://")):
        full_url = f"http://{cleaned_url}"
    else:
        full_url = cleaned_url

    parsed = urllib.parse.urlparse(full_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path
    query = parsed.query
    netloc = parsed.netloc

    risk_score = 0
    flagged_factors = []

    # 1. IP Address as Hostname
    if re.match(IP_REGEX, hostname):
        risk_score += 30
        flagged_factors.append({
            "code": "IP_HOSTNAME",
            "name": "Raw IP Hostname",
            "risk_weight": 30,
            "status": "CRITICAL",
            "detail": f"Target uses raw IP address '{hostname}' instead of a legitimate domain name."
        })

    # 2. Embedded '@' Symbol in URL
    if "@" in netloc or "@" in cleaned_url:
        risk_score += 25
        flagged_factors.append({
            "code": "AT_SYMBOL",
            "name": "Embedded '@' Obfuscation Symbol",
            "risk_weight": 25,
            "status": "CRITICAL",
            "detail": "URL contains '@', which leads browsers to ignore preceding text and authenticate to the host after '@'."
        })

    # 3. Excessive Subdomains
    domain_parts = hostname.split(".")
    if len(domain_parts) > 3:
        excess = len(domain_parts) - 3
        points = min(25, 10 + (excess * 5))
        risk_score += points
        flagged_factors.append({
            "code": "EXCESSIVE_SUBDOMAINS",
            "name": "Excessive Subdomains Count",
            "risk_weight": points,
            "status": "HIGH",
            "detail": f"Hostname has {len(domain_parts)} domain segments. Attackers frequently nest brand names in subdomains."
        })

    # 4. Punycode / Homoglyph Attack (IDN spoofing)
    if "xn--" in hostname or any(ord(char) > 127 for char in hostname):
        risk_score += 25
        flagged_factors.append({
            "code": "HOMOGLYPH_PUNYCODE",
            "name": "Homoglyph / Punycode Internationalized Domain",
            "risk_weight": 25,
            "status": "HIGH",
            "detail": "Domain utilizes Punycode ('xn--') or non-ASCII characters to visually mimic reputable brands."
        })

    # 5. Suspicious / High-Abuse TLD Check
    tld = domain_parts[-1] if domain_parts else ""
    if tld in SUSPICIOUS_TLDS:
        risk_score += 20
        flagged_factors.append({
            "code": "HIGH_RISK_TLD",
            "name": f"High-Risk Top-Level Domain (.{tld})",
            "risk_weight": 20,
            "status": "MEDIUM",
            "detail": f"The '.{tld}' TLD has a statistically high correlation with disposable phishing kits and free domains."
        })

    # 6. Typosquatting / Hyphenation in Domain
    if "-" in hostname:
        hyphen_count = hostname.count("-")
        points = min(20, hyphen_count * 8)
        risk_score += points
        flagged_factors.append({
            "code": "HYPHENATED_DOMAIN",
            "name": "Hyphenated / Brand Spoofing Mechanics",
            "risk_weight": points,
            "status": "MEDIUM",
            "detail": f"Hostname contains {hyphen_count} hyphen(s). Legitimate commercial domains rarely combine brand names with hyphens."
        })

    # 7. Abnormal URL Length
    url_len = len(cleaned_url)
    if url_len > 75:
        risk_score += 15
        flagged_factors.append({
            "code": "EXCESSIVE_LENGTH",
            "name": f"Abnormal URL Length ({url_len} chars)",
            "risk_weight": 15,
            "status": "MEDIUM",
            "detail": "URL exceeds 75 characters. Excessively long URLs are often used to hide real destination domains on mobile screens."
        })
    elif url_len > 54:
        risk_score += 8
        flagged_factors.append({
            "code": "MODERATE_LENGTH",
            "name": f"Elevated URL Length ({url_len} chars)",
            "risk_weight": 8,
            "status": "LOW",
            "detail": "URL is relatively long (>54 chars), often seen in tracking redirects or phishing obfuscation."
        })

    # 8. Double Slash Redirection in Path
    if "//" in path:
        risk_score += 15
        flagged_factors.append({
            "code": "DOUBLE_SLASH",
            "name": "Redirection Trick with Double Slash ('//')",
            "risk_weight": 15,
            "status": "MEDIUM",
            "detail": "Path contains '//' which can be exploited for open redirect bypasses."
        })

    # 9. High-Risk Phishing Keywords
    lower_full = cleaned_url.lower()
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in lower_full]
    # Check if keyword is in subdomain or path while main domain is not the legitimate brand
    if matched_keywords:
        points = min(25, len(matched_keywords) * 10)
        risk_score += points
        flagged_factors.append({
            "code": "PHISHING_KEYWORDS",
            "name": "Sensitive Credential Keywords Present",
            "risk_weight": points,
            "status": "HIGH",
            "detail": f"Contains security/credential keywords: {', '.join(matched_keywords[:4])}."
        })

    # 10. Shannon Domain Entropy (DGA Detection)
    domain_entropy = calculate_shannon_entropy(hostname.replace(".", ""))
    if domain_entropy > 4.2 and len(hostname) > 10:
        risk_score += 15
        flagged_factors.append({
            "code": "HIGH_ENTROPY",
            "name": f"High Domain Entropy ({domain_entropy})",
            "risk_weight": 15,
            "status": "MEDIUM",
            "detail": "Domain characters exhibit high mathematical randomness indicative of Domain Generation Algorithms (DGA)."
        })

    # 11. HTTPS / SSL Presence
    is_https = cleaned_url.startswith("https://")
    if not is_https:
        risk_score += 10
        flagged_factors.append({
            "code": "NO_HTTPS",
            "name": "Unencrypted HTTP Protocol",
            "risk_weight": 10,
            "status": "LOW",
            "detail": "URL does not enforce TLS encryption, allowing cleartext eavesdropping and credential sniffing."
        })

    # Clamp risk score 0 to 100
    risk_score = min(100, max(0, risk_score))

    # Category classification
    if risk_score >= 75:
        classification = "MALICIOUS PHISHING DETECTED (HIGH RISK)"
        verdict = "MALICIOUS"
        color = "#ff0055"
    elif risk_score >= 45:
        classification = "SUSPICIOUS (ELEVATED RISK)"
        verdict = "SUSPICIOUS"
        color = "#ffb703"
    elif risk_score >= 20:
        classification = "LOW RISK / MINOR ANOMALIES"
        verdict = "LOW_RISK"
        color = "#00f2fe"
    else:
        classification = "LEGITIMATE / SAFE (LOW RISK)"
        verdict = "SAFE"
        color = "#00f5a0"

    return {
        "url": cleaned_url,
        "hostname": hostname,
        "risk_score": risk_score,
        "classification": classification,
        "verdict": verdict,
        "color": color,
        "is_https": is_https,
        "domain_entropy": domain_entropy,
        "factors_flagged": flagged_factors,
        "total_factors": len(flagged_factors)
    }
