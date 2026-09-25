"""
Comprehensive Verification Test Suite for CyberSOC Dashboard.
Tests Database, Authentication, Multilingual Translations, and Security Tools.
"""

import os
import sys

# Reconfigure stdout for UTF-8 to cleanly print Devanagari script on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure current directory is in path
sys.path.insert(0, os.path.dirname(__file__))

import database as db
import auth
from translations import t, TRANSLATIONS
from tools.scanner import scan_target
from tools.password_check import evaluate_password
from tools.phishing_detector import analyze_url

def test_multilingual():
    print("--- 1. Testing Multilingual Translation Mapping ---")
    langs = ["en", "hi", "mr"]
    sample_keys = [
        "app_title", "nav_dashboard", "nav_scanner", "nav_password",
        "nav_phishing", "btn_scan", "strength_strong", "risk_malicious"
    ]
    for l in langs:
        assert l in TRANSLATIONS, f"Language '{l}' missing from TRANSLATIONS"
        for k in sample_keys:
            val = t(k, l)
            assert val and val != k, f"Key '{k}' translation failed for '{l}'"
            print(f"  [{l}] {k} -> {val[:30]}")
    print("  [SUCCESS] Multilingual mapping validated for English, Hindi, and Marathi.\n")

def test_database_and_auth():
    print("--- 2. Testing Database Architecture & Authentication ---")
    ok, db_type = db.init_db()
    assert ok, f"Database init failed: {db_type}"
    print(f"  Database initialized on: {db_type}")

    # Test User Registration
    test_user = "sec_test_user"
    test_email = "sec_test@soc.local"
    test_pwd = "P@ssw0rdSecure!2026"

    # Clean existing if rerun
    existing = db.get_user_by_username(test_user)
    if not existing:
        reg_ok, msg = auth.register_user(test_user, test_email, test_pwd, "hi")
        assert reg_ok, f"Registration failed: {msg}"
        print(f"  User registration successful: {msg}")
    else:
        print(f"  User {test_user} already present from previous run.")

    # Duplicate rejection test
    dup_ok, dup_msg = auth.register_user(test_user, "another@soc.local", test_pwd, "en")
    assert not dup_ok, "Duplicate username was incorrectly allowed!"
    print(f"  Duplicate username correctly blocked: {dup_msg}")

    # Authentication test
    user = db.get_user_by_username(test_user)
    assert user is not None, "User could not be retrieved by username"
    assert auth.verify_password(test_pwd, user["password_hash"]), "Password verification failed"
    assert not auth.verify_password("WrongPassword123", user["password_hash"]), "Invalid password incorrectly verified!"
    print(f"  Password bcrypt verification passed.")

    # Test Scan History Persistence
    mock_scan_res = {"score": 95, "status": "TEST_OK"}
    save_ok = db.save_scan(user["id"], "Test Scanner", "https://test.example.com", mock_scan_res)
    assert save_ok, "Failed to save scan history record"

    scans = db.get_user_scans(user["id"], limit=5)
    assert len(scans) > 0, "No scans retrieved for user"
    assert scans[0]["tool_name"] == "Test Scanner", "Scan tool_name mismatch"
    print(f"  Scan history saved and retrieved successfully: {scans[0]['target_input']}")

    # Test Metrics
    metrics = db.get_dashboard_metrics()
    assert metrics["total_scans"] > 0, "Total scans metric is 0"
    print(f"  Aggregated dashboard metrics: {metrics}")
    print("  [SUCCESS] Database & Auth flows validated.\n")

def test_vulnerability_scanner():
    print("--- 3. Testing Tool A: Vulnerability Scanner ---")
    target = "https://example.com"
    res = scan_target(target)
    assert "security_score" in res, "Scanner missing security_score"
    assert "headers_found" in res or "headers_missing" in res, "Scanner missing headers report"
    assert "rating" in res, "Scanner missing rating"
    print(f"  Target: {res['target']}")
    print(f"  Security Score: {res['security_score']}/100 ({res['rating']})")
    print(f"  Headers Found: {list(res['headers_found'].keys())}")
    print(f"  Headers Missing: {list(res['headers_missing'].keys())}")
    print("  [SUCCESS] Tool A (Vulnerability Scanner) validated.\n")

def test_password_evaluator():
    print("--- 4. Testing Tool B: Password Strength Evaluator ---")
    weak_res = evaluate_password("123456")
    strong_res = evaluate_password("Cyber#SecOps$2026!FortressKey")

    assert weak_res["percentage"] < 35, f"Weak password scored too high: {weak_res['percentage']}"
    assert strong_res["percentage"] >= 75, f"Strong password scored too low: {strong_res['percentage']}"
    assert strong_res["entropy"] > 60, f"Entropy too low for strong password: {strong_res['entropy']}"
    assert strong_res["criteria"]["special_chars"] is True, "Special chars check failed"

    print(f"  Weak Password ('123456'): {weak_res['percentage']}% ({weak_res['strength_label']})")
    print(f"  Strong Password: {strong_res['percentage']}% ({strong_res['strength_label']}) | Entropy: {strong_res['entropy']} bits")
    print(f"  Estimated Crack Time: {strong_res['crack_times'].get('offline_fast_hashing_1e10_per_second')}")
    print("  [SUCCESS] Tool B (Password Strength Evaluator) validated.\n")

def test_phishing_detector():
    print("--- 5. Testing Tool C: URL Phishing Detector ---")
    safe_url = "https://google.com"
    malicious_url = "http://192.168.1.1/paypal-account-update@malicious-phish.tk/login.php"

    safe_res = analyze_url(safe_url)
    mal_res = analyze_url(malicious_url)

    assert safe_res["risk_score"] < 30, f"Safe URL flagged as too risky: {safe_res['risk_score']}"
    assert mal_res["risk_score"] >= 65, f"Malicious URL not flagged as high risk: {mal_res['risk_score']}"
    assert mal_res["verdict"] in ["SUSPICIOUS", "MALICIOUS"], f"Unexpected verdict: {mal_res['verdict']}"

    print(f"  Safe URL ('{safe_url}'): Risk Score = {safe_res['risk_score']}% ({safe_res['verdict']})")
    print(f"  Malicious URL ('{malicious_url}'): Risk Score = {mal_res['risk_score']}% ({mal_res['verdict']})")
    print(f"  Flagged factors count: {mal_res['total_factors']}")
    for f in mal_res["factors_flagged"]:
        print(f"    - [{f['status']}] {f['name']} (+{f['risk_weight']} pts)")
    print("  [SUCCESS] Tool C (Phishing Detector) validated.\n")

if __name__ == "__main__":
    print("==================================================")
    print("CYBERSOC TEST SUITE EXECUTION")
    print("==================================================\n")
    test_multilingual()
    test_database_and_auth()
    test_vulnerability_scanner()
    test_password_evaluator()
    test_phishing_detector()
    print("==================================================")
    print("ALL TESTS COMPLETED SUCCESSFULLY (5/5 PASSED)!")
    print("==================================================")
