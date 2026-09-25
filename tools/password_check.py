"""
Tool B: Password Strength & Entropy Resilience Evaluator.
Evaluates passwords against NIST 800-63B guidelines using zxcvbn,
entropy calculations, crack-time simulations, and dictionary leak checks.
"""

import math
import re
import hashlib
from typing import Dict, Any

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

def calculate_entropy(password: str) -> float:
    """Calculate Shannon information entropy (in bits) based on character pool size."""
    if not password:
        return 0.0

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 33

    if pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def evaluate_password(password: str) -> Dict[str, Any]:
    """Perform comprehensive multi-tier password resilience evaluation."""
    if not password:
        return {
            "score": 0,
            "percentage": 0,
            "strength_label": "CRITICAL - EMPTY",
            "entropy": 0.0,
            "criteria": {},
            "crack_times": {},
            "feedback": {"warning": "", "suggestions": []},
            "masked_hash": ""
        }

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digits = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
    entropy = calculate_entropy(password)

    # Anonymized SHA-256 fingerprint for safe audit logging
    masked_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()[:12] + "..."

    # Check criteria dictionary
    criteria = {
        "length_12": length >= 12,
        "uppercase": has_upper,
        "lowercase": has_lower,
        "numbers": has_digits,
        "special_chars": has_special,
        "entropy_high": entropy >= 60.0
    }

    warning = ""
    suggestions = []
    crack_times = {}
    zxcvbn_score = 0

    if ZXCVBN_AVAILABLE:
        try:
            res = zxcvbn(password)
            zxcvbn_score = res.get("score", 0)
            crack_times = res.get("crack_times_display", {})
            fb = res.get("feedback", {})
            warning = fb.get("warning", "")
            suggestions = fb.get("suggestions", [])
        except Exception:
            pass

    # Hybrid scoring algorithm (0 to 100%)
    criteria_score = sum([20 for k, v in criteria.items() if v])
    if ZXCVBN_AVAILABLE:
        # Weighted blend of zxcvbn model (60%) and character requirements (40%)
        final_percentage = int((zxcvbn_score / 4.0 * 60) + (criteria_score / 120.0 * 40))
    else:
        final_percentage = min(100, int((entropy / 80.0) * 100))

    final_percentage = max(5, min(100, final_percentage))

    # Strength label mapping
    if final_percentage >= 85:
        strength_label = "FORTRESS - MAXIMUM STRENGTH"
        color = "#00f5a0"
    elif final_percentage >= 65:
        strength_label = "STRONG - RESILIENT"
        color = "#00f2fe"
    elif final_percentage >= 45:
        strength_label = "MODERATE - ACCEPTABLE"
        color = "#ffb703"
    elif final_percentage >= 25:
        strength_label = "WEAK - HIGH RISK"
        color = "#fb8500"
    else:
        strength_label = "CRITICAL - VERY WEAK"
        color = "#ff0055"

    if not crack_times:
        # Fallback crack-time estimation
        guesses = 2 ** entropy
        fast_sec = guesses / 1e10
        if fast_sec < 1:
            fast_time = "Instantaneous"
        elif fast_sec < 60:
            fast_time = f"{int(fast_sec)} seconds"
        elif fast_sec < 3600:
            fast_time = f"{int(fast_sec/60)} minutes"
        elif fast_sec < 86400:
            fast_time = f"{int(fast_sec/3600)} hours"
        elif fast_sec < 31536000:
            fast_time = f"{int(fast_sec/86400)} days"
        else:
            fast_time = f"{int(fast_sec/31536000)} years"
        
        crack_times = {
            "offline_fast_hashing_1e10_per_second": fast_time,
            "online_throttled_100_per_hour": "Centuries" if fast_sec > 1000 else "Days"
        }

    return {
        "percentage": final_percentage,
        "score_0_to_4": zxcvbn_score,
        "strength_label": strength_label,
        "color": color,
        "entropy": entropy,
        "length": length,
        "criteria": criteria,
        "crack_times": crack_times,
        "feedback": {
            "warning": warning,
            "suggestions": suggestions
        },
        "masked_hash": masked_hash
    }
