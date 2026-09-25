"""
Multilingual Translation Mapping System for CyberSOC Dashboard.
Supports English (en), Hindi (hi - हिन्दी), and Marathi (mr - मराठी).
"""

TRANSLATIONS = {
    # -------------------------------------------------------------
    # English (Default)
    # -------------------------------------------------------------
    "en": {
        # App Info & Brand
        "app_title": "CYBER-SOC // THREAT MONITOR",
        "app_tagline": "Next-Gen Autonomous Multilingual Cybersecurity Intelligence Platform",
        "lang_name": "English",
        
        # Navigation
        "nav_dashboard": "Threat Dashboard",
        "nav_scanner": "Vulnerability Scanner",
        "nav_password": "Password Resilience",
        "nav_phishing": "Phishing Detector",
        "nav_history": "Audit History",
        "nav_account": "Account",
        "nav_login": "Authentication",
        "nav_logout": "Sign Out",
        
        # Common Actions & Labels
        "btn_scan": "Execute Security Scan",
        "btn_analyze": "Analyze Target",
        "btn_evaluate": "Evaluate Resilience",
        "btn_clear": "Clear",
        "btn_export_csv": "Export CSV Report",
        "btn_export_json": "Export JSON",
        "status_scanning": "Running deep heuristic analysis...",
        "target_label": "Target Hostname / URL / IP:",
        "target_placeholder": "e.g. https://example.com or 192.168.1.1",
        "risk_score": "Risk Assessment Score",
        "severity": "Severity",
        "status": "Status",
        "timestamp": "Timestamp",
        "details": "Details",
        "remediation": "Remediation & Hardening",
        "connected_to": "Connected to",
        
        # Dashboard
        "metric_threat_level": "DEFCON Threat Level",
        "threat_elevated": "ELEVATED (LEVEL 3)",
        "threat_guarded": "GUARDED (LEVEL 2)",
        "metric_total_scans": "Total Audits Completed",
        "metric_vulns_found": "Critical Vulnerabilities",
        "metric_phish_blocked": "Phishing Sites Flagged",
        "metric_soc_readiness": "SOC Readiness Score",
        "chart_vector_title": "Active Threat Vectors (Global Telemetry)",
        "chart_timeline_title": "24-Hour Intrusion Attempt Timeline",
        "chart_severity_title": "Historical Findings by Severity",
        "recent_activity": "Real-Time Intelligence & Audit Feed",
        
        # Tool A: Vulnerability Scanner
        "scanner_title": "Target Vulnerability & HTTP Header Audit",
        "scanner_desc": "Probes target endpoints for missing security headers, sensitive banner disclosures, cookie flags, and exposed ports.",
        "header_hsts": "Strict-Transport-Security (HSTS)",
        "header_csp": "Content-Security-Policy (CSP)",
        "header_xframe": "X-Frame-Options (Anti-Clickjacking)",
        "header_xcontent": "X-Content-Type-Options (MIME Sniffing)",
        "header_referrer": "Referrer-Policy",
        "header_permissions": "Permissions-Policy",
        "open_ports_detected": "Open Exposed Ports Detected",
        "info_disclosure": "Server Banner Disclosure",
        "cookie_security": "Cookie Flags Verification",
        "scan_summary_title": "Executive Audit Summary",
        "vuln_score_label": "Security Posture Rating",
        
        # Tool B: Password Checker
        "password_title": "Password Strength & Entropy Analyzer",
        "password_desc": "Evaluates password entropy, brute-force resistance, dictionary vulnerabilities, and estimated crack times.",
        "password_input_label": "Enter Password to Audit:",
        "strength_very_weak": "CRITICAL - VERY WEAK",
        "strength_weak": "WEAK - HIGH RISK",
        "strength_fair": "MODERATE - ACCEPTABLE",
        "strength_strong": "STRONG - RESILIENT",
        "strength_very_strong": "FORTRESS - MAXIMUM STRENGTH",
        "entropy_bits": "Entropy Score",
        "crack_time_fast": "Offline Fast Attack Crack Time",
        "crack_time_online": "Online Throttled Attack Crack Time",
        "crit_length": "Length >= 12 Characters",
        "crit_upper": "Uppercase Letters (A-Z)",
        "crit_lower": "Lowercase Letters (a-z)",
        "crit_digits": "Numerical Digits (0-9)",
        "crit_special": "Special Symbols (!@#$%)",
        "crit_dictionary": "Free of Dictionary / Leaked Patterns",
        "password_warning": "Warning",
        "password_suggestion": "Security Recommendations",
        
        # Tool C: Phishing Detector
        "phishing_title": "Heuristic URL & Domain Phishing Detector",
        "phishing_desc": "Scrutinizes suspicious domain mechanics, IP hosts, homoglyphs, brand typosquatting, and obfuscation heuristics.",
        "url_input_label": "Target URL to Inspect:",
        "risk_safe": "LEGITIMATE / SAFE (LOW RISK)",
        "risk_suspicious": "SUSPICIOUS (ELEVATED RISK)",
        "risk_malicious": "MALICIOUS PHISHING DETECTED (HIGH RISK)",
        "factor_ip_host": "Raw IP Address as Hostname",
        "factor_subdomains": "Excessive Subdomain Count (>3)",
        "factor_at_symbol": "Embedded '@' Obfuscation Symbol",
        "factor_suspicious_tld": "High-Risk Top-Level Domain (TLD)",
        "factor_typosquatting": "Hyphenated / Brand Typosquatting Signatures",
        "factor_length": "Abnormal URL Length (>75 chars)",
        "factor_double_slash": "Deep Path Redirection (//)",
        "factor_homoglyph": "Punycode / Non-ASCII Homoglyph Spoofing",
        "factor_keywords": "High-Risk Phishing Keywords Present",
        "factor_ssl": "Missing HTTPS Encryption",
        
        # Auth & Users
        "login_title": "Security Operations Center Access",
        "tab_login": "Sign In",
        "tab_register": "New Operative Registration",
        "username": "Username",
        "email": "Official Email Address",
        "password": "Password",
        "confirm_password": "Confirm Password",
        "language_pref": "Preferred Language Interface",
        "btn_submit_login": "Authorize Access",
        "btn_submit_register": "Create Credentials",
        "demo_login": "Quick Access (Demo Operative)",
        "welcome_user": "Welcome, Operative",
        "err_invalid_creds": "Authentication failed. Invalid username/email or password.",
        "msg_registered": "Account created successfully! You can now log in.",
        
        # Scan History
        "history_title": "Security Audit & Telemetry Logs",
        "history_empty": "No security scans logged yet. Initiate an audit using the security tools above.",
        "col_id": "Audit ID",
        "col_tool": "Security Tool",
        "col_target": "Target",
        "col_result": "Key Findings",
        "col_time": "Timestamp (UTC)",
    },

    # -------------------------------------------------------------
    # Hindi (हिन्दी)
    # -------------------------------------------------------------
    "hi": {
        # App Info & Brand
        "app_title": "साइबर-एसओसी // खतरा निगरानी केंद्र",
        "app_tagline": "अगली पीढ़ी का स्वायत्त बहुभाषी साइबर सुरक्षा इंटेलिजेंस प्लेटफॉर्म",
        "lang_name": "हिन्दी",
        
        # Navigation
        "nav_dashboard": "थ्रेट डैशबोर्ड",
        "nav_scanner": "कमजोरी स्कैनर (Vulnerability)",
        "nav_password": "पासवर्ड मजबूती विश्लेषक",
        "nav_phishing": "फ़िशिंग डिटेक्टर",
        "nav_history": "ऑडिट इतिहास",
        "nav_account": "खाता",
        "nav_login": "प्रमाणीकरण (Login)",
        "nav_logout": "लॉग आउट",
        
        # Common Actions & Labels
        "btn_scan": "सुरक्षा स्कैन प्रारंभ करें",
        "btn_analyze": "लक्ष्य का विश्लेषण करें",
        "btn_evaluate": "दृढ़ता का मूल्यांकन करें",
        "btn_clear": "हटाएं",
        "btn_export_csv": "CSV रिपोर्ट निर्यात करें",
        "btn_export_json": "JSON निर्यात करें",
        "status_scanning": "गहन अनुमानी विश्लेषण चल रहा है...",
        "target_label": "लक्ष्य होस्टनेम / URL / IP:",
        "target_placeholder": "उदा. https://example.com या 192.168.1.1",
        "risk_score": "जोखिम मूल्यांकन स्कोर",
        "severity": "गंभीरता",
        "status": "स्थिति",
        "timestamp": "समय मोहर",
        "details": "विवरण",
        "remediation": "उपचार और सुरक्षा सुदृढ़ीकरण",
        "connected_to": "जुड़ा हुआ है",
        
        # Dashboard
        "metric_threat_level": "DEFCON खतरा स्तर",
        "threat_elevated": "उन्नत खतरा (स्तर 3)",
        "threat_guarded": "सुरक्षित (स्तर 2)",
        "metric_total_scans": "कुल पूर्ण ऑडिट",
        "metric_vulns_found": "गंभीर कमजोरियां",
        "metric_phish_blocked": "पहचानी गई फ़िशिंग साइट्स",
        "metric_soc_readiness": "SOC तत्परता स्कोर",
        "chart_vector_title": "सक्रिय साइबर खतरे (वैश्विक टेलीमेट्री)",
        "chart_timeline_title": "24 घंटे के घुसपैठ के प्रयास",
        "chart_severity_title": "गंभीरता के आधार पर निष्कर्ष",
        "recent_activity": "वास्तविक समय ऑडिट और टेलीमेट्री फीड",
        
        # Tool A: Vulnerability Scanner
        "scanner_title": "लक्ष्य भेद्यता और HTTP हेडर ऑडिट",
        "scanner_desc": "लापता सुरक्षा हेडर, संवेदनशील सर्वर जानकारी, कुकी सुरक्षा और खुले पोर्ट की जांच करता है।",
        "header_hsts": "Strict-Transport-Security (HSTS)",
        "header_csp": "Content-Security-Policy (CSP)",
        "header_xframe": "X-Frame-Options (क्लिकजैकिंग रोकथाम)",
        "header_xcontent": "X-Content-Type-Options (MIME स्निफिंग)",
        "header_referrer": "Referrer-Policy",
        "header_permissions": "Permissions-Policy",
        "open_ports_detected": "पहचाने गए खुले पोर्ट्स",
        "info_disclosure": "सर्वर बैनर प्रकटीकरण",
        "cookie_security": "कुकी सुरक्षा सत्यापन",
        "scan_summary_title": "कार्यकारी ऑडिट सारांश",
        "vuln_score_label": "सुरक्षा स्थिति रेटिंग",
        
        # Tool B: Password Checker
        "password_title": "पासवर्ड मजबूती और एन्ट्रॉपी विश्लेषक",
        "password_desc": "पासवर्ड एन्ट्रॉपी, ब्रूट-फोर्स प्रतिरोध, शब्दकोश कमजोरियों और क्रैक समय का मूल्यांकन करता है।",
        "password_input_label": "जांच के लिए पासवर्ड दर्ज करें:",
        "strength_very_weak": "अति संवेदनशील - बहुत कमजोर",
        "strength_weak": "कमजोर - उच्च जोखिम",
        "strength_fair": "मध्यम - स्वीकार्य",
        "strength_strong": "मजबूत - प्रतिरोधी",
        "strength_very_strong": "अभेद्य - अधिकतम सुरक्षा",
        "entropy_bits": "एन्ट्रॉपी स्कोर",
        "crack_time_fast": "ऑफ़लाइन फास्ट अटैक क्रैक समय",
        "crack_time_online": "ऑनलाइन थ्रॉटल्ड अटैक क्रैक समय",
        "crit_length": "लंबाई >= 12 वर्ण",
        "crit_upper": "बड़े अक्षर (A-Z)",
        "crit_lower": "छोटे अक्षर (a-z)",
        "crit_digits": "अंक (0-9)",
        "crit_special": "विशेष प्रतीक (!@#$%)",
        "crit_dictionary": "सामान्य शब्दकोश पैटर्न से मुक्त",
        "password_warning": "चेतावनी",
        "password_suggestion": "सुरक्षा सिफारिशें",
        
        # Tool C: Phishing Detector
        "phishing_title": "अनुमानी URL और डोमेन फ़िशिंग डिटेक्टर",
        "phishing_desc": "संदेहास्पद डोमेन बनावट, आईपी होस्ट, होमोग्लिफ़, ब्रांड स्पूफिंग और भ्रामक यूआरएल की जांच करता है।",
        "url_input_label": "निरीक्षण के लिए URL दर्ज करें:",
        "risk_safe": "वैध / सुरक्षित (कम जोखिम)",
        "risk_suspicious": "संदेहास्पद (बढ़ा हुआ जोखिम)",
        "risk_malicious": "दुर्भावनापूर्ण फ़िशिंग पहचानी गई (उच्च जोखिम)",
        "factor_ip_host": "होस्टनेम के रूप में कच्चा IP पता",
        "factor_subdomains": "अत्यधिक सबडोमेन संख्या (>3)",
        "factor_at_symbol": "एंबेडेड '@' भ्रमित करने वाला प्रतीक",
        "factor_suspicious_tld": "उच्च जोखिम वाला टॉप-लेवल डोमेन (TLD)",
        "factor_typosquatting": "हाइफ़न / ब्रांड टाइपोस्क्वैटिंग संकेत",
        "factor_length": "असामान्य URL लंबाई (>75 वर्ण)",
        "factor_double_slash": "गहन पथ पुनर्निर्देशन (//)",
        "factor_homoglyph": "यूनिकोड / होमोग्लिफ़ स्पूफिंग",
        "factor_keywords": "उच्च जोखिम वाले फ़िशिंग कीवर्ड उपस्थित",
        "factor_ssl": "अनुपस्थित HTTPS एन्क्रिप्शन",
        
        # Auth & Users
        "login_title": "सुरक्षा संचालन केंद्र में प्रवेश",
        "tab_login": "लॉग इन करें",
        "tab_register": "नया ऑपरेटर पंजीकरण",
        "username": "उपयोगकर्ता नाम (Username)",
        "email": "आधिकारिक ईमेल पता",
        "password": "पासवर्ड",
        "confirm_password": "पासवर्ड की पुष्टि करें",
        "language_pref": "पसंदीदा इंटरफ़ेस भाषा",
        "btn_submit_login": "प्रवेश अधिकृत करें",
        "btn_submit_register": "खाता बनाएं",
        "demo_login": "त्वरित डेमो लॉगिन",
        "welcome_user": "स्वागत है, ऑपरेटर",
        "err_invalid_creds": "प्रमाणीकरण विफल। अमान्य उपयोगकर्ता नाम/ईमेल या पासवर्ड।",
        "msg_registered": "खाता सफलतापूर्वक बन गया! अब आप लॉग इन कर सकते हैं।",
        
        # Scan History
        "history_title": "सुरक्षा ऑडिट और टेलीमेट्री लॉग",
        "history_empty": "अभी तक कोई सुरक्षा स्कैन दर्ज नहीं हुआ है। ऊपर दिए गए सुरक्षा टूल से ऑडिट शुरू करें।",
        "col_id": "ऑडिट आईडी",
        "col_tool": "सुरक्षा उपकरण",
        "col_target": "लक्ष्य",
        "col_result": "मुख्य निष्कर्ष",
        "col_time": "समय (UTC)",
    },

    # -------------------------------------------------------------
    # Marathi (मराठी)
    # -------------------------------------------------------------
    "mr": {
        # App Info & Brand
        "app_title": "सायबर-एसओसी // धोका देखरेख केंद्र",
        "app_tagline": "पुढील पिढीचे स्वायत्त बहुभाषिक सायबर सुरक्षा इंटेलिजेंस व्यासपीठ",
        "lang_name": "मराठी",
        
        # Navigation
        "nav_dashboard": "धोका डॅशबोर्ड",
        "nav_scanner": "सुरक्षा त्रुटी स्कॅनर (Vulnerability)",
        "nav_password": "पासवर्ड सामर्थ्य विश्लेषक",
        "nav_phishing": "फिशिंग शोधक",
        "nav_history": "ऑडिट इतिहास",
        "nav_account": "खाते",
        "nav_login": "प्रमाणीकरण (Login)",
        "nav_logout": "लॉग आउट",
        
        # Common Actions & Labels
        "btn_scan": "सुरक्षा स्कॅन सुरू करा",
        "btn_analyze": "लक्ष्याचे विश्लेषण करा",
        "btn_evaluate": "सामर्थ्य तपासा",
        "btn_clear": "साफ करा",
        "btn_export_csv": "CSV अहवाल निर्यात करा",
        "btn_export_json": "JSON निर्यात करा",
        "status_scanning": "खोलवर अनुमानी विश्लेषण सुरू आहे...",
        "target_label": "लक्ष्य होस्टनेम / URL / IP:",
        "target_placeholder": "उदा. https://example.com किंवा 192.168.1.1",
        "risk_score": "धोका मूल्यांकन गुण",
        "severity": "तीव्रता",
        "status": "स्थिती",
        "timestamp": "वेळ",
        "details": "तपशील",
        "remediation": "उपाययोजना आणि सुरक्षा सक्षमीकरण",
        "connected_to": "जोडलेले आहे",
        
        # Dashboard
        "metric_threat_level": "DEFCON धोका पातळी",
        "threat_elevated": "वाढलेला धोका (पातळी ३)",
        "threat_guarded": "सुरक्षित (पातळी २)",
        "metric_total_scans": "एकूण पूर्ण झालेले ऑडिट",
        "metric_vulns_found": "गंभीर त्रुटी सापडल्या",
        "metric_phish_blocked": "अडकवलेल्या फिशिंग साइट्स",
        "metric_soc_readiness": "SOC सज्जता गुण",
        "chart_vector_title": "सक्रिय सायबर हल्ले (जागतिक टेलीमेट्री)",
        "chart_timeline_title": "२४ तासांतील घुसखोरीचे प्रयत्न",
        "chart_severity_title": "तीव्रतेनुसार निष्कर्ष",
        "recent_activity": "थेट सुरक्षा ऑडिट आणि टेलीमेट्री फीड",
        
        # Tool A: Vulnerability Scanner
        "scanner_title": "लक्ष्य त्रुटी आणि HTTP हेडर ऑडिट",
        "scanner_desc": "गहाळ सुरक्षा हेडर, उघड झालेली सर्व्हर माहिती, कुकी सुरक्षा आणि उघडे पोर्ट्स शोधतो.",
        "header_hsts": "Strict-Transport-Security (HSTS)",
        "header_csp": "Content-Security-Policy (CSP)",
        "header_xframe": "X-Frame-Options (क्लिकजॅकिंग प्रतिबंध)",
        "header_xcontent": "X-Content-Type-Options (MIME स्निफिंग)",
        "header_referrer": "Referrer-Policy",
        "header_permissions": "Permissions-Policy",
        "open_ports_detected": "सापडलेले उघडे पोर्ट्स",
        "info_disclosure": "सर्व्हर बॅनर प्रकटीकरण",
        "cookie_security": "कुकी सुरक्षा पडताळणी",
        "scan_summary_title": "कार्यकारी ऑडिट सारांश",
        "vuln_score_label": "सुरक्षा स्थिती मानांकन",
        
        # Tool B: Password Checker
        "password_title": "पासवर्ड सामर्थ्य आणि एन्ट्रॉपी विश्लेषक",
        "password_desc": "पासवर्ड एन्ट्रॉपी, ब्रूट-फोर्स प्रतिकार, शब्दकोश त्रुटी आणि क्रॅक करण्यासाठी लागणारा वेळ तपासतो.",
        "password_input_label": "तपासणीसाठी पासवर्ड टाका:",
        "strength_very_weak": "अतिसंवेदनशील - अत्यंत कमकुवत",
        "strength_weak": "कमकुवत - उच्च धोका",
        "strength_fair": "मध्यम - स्वीकारार्ह",
        "strength_strong": "मजबूत - प्रतिरोधी",
        "strength_very_strong": "अभेद्य - सर्वोच्च सुरक्षा",
        "entropy_bits": "एन्ट्रॉपी गुण",
        "crack_time_fast": "ऑफलाइन फास्ट अटॅक क्रॅक वेळ",
        "crack_time_online": "ऑनलाइन थ्रॉटल्ड अटॅक क्रॅक वेळ",
        "crit_length": "लांबी >= १२ अक्षरे",
        "crit_upper": "मोठी अक्षरे (A-Z)",
        "crit_lower": "लहान अक्षरे (a-z)",
        "crit_digits": "अंक (0-9)",
        "crit_special": "विशेष चिन्हे (!@#$%)",
        "crit_dictionary": "सामान्य शब्दकोश रचनेपासून मुक्त",
        "password_warning": "चेतावणी",
        "password_suggestion": "सुरक्षा शिफारसी",
        
        # Tool C: Phishing Detector
        "phishing_title": "अनुमानी URL आणि डोमेन फिशिंग शोधक",
        "phishing_desc": "संशयास्पद डोमेन रचना, आयपी होस्ट, होमोग्लिफ, ब्रँड स्पूफिंग आणि भ्रामक यूआरएलची तपासणी करतो.",
        "url_input_label": "तपासणीसाठी URL प्रविष्ट करा:",
        "risk_safe": "वैध / सुरक्षित (कमी धोका)",
        "risk_suspicious": "संशयास्पद (वाढलेला धोका)",
        "risk_malicious": "घातक फिशिंग आढळले (उच्च धोका)",
        "factor_ip_host": "होस्टनेम म्हणून थेट IP पत्ता",
        "factor_subdomains": "अतिरिक्त सबडोमेन संख्या (>३)",
        "factor_at_symbol": "एंबेडेड '@' दिशाभूल करणारे चिन्ह",
        "factor_suspicious_tld": "उच्च धोक्याचे टॉप-लेव्हल डोमेन (TLD)",
        "factor_typosquatting": "हायफन / ब्रँड टायपोस्क्वॅटिंग लक्षणे",
        "factor_length": "असामान्य URL लांबी (>७५ अक्षरे)",
        "factor_double_slash": "मार्ग पुनर्निर्देशन (//)",
        "factor_homoglyph": "युनिकोड / होमोग्लिफ स्पूफिंग",
        "factor_keywords": "उच्च धोक्याचे फिशिंग शब्द उपस्थित",
        "factor_ssl": "अनुपस्थित HTTPS एन्क्रिप्शन",
        
        # Auth & Users
        "login_title": "सुरक्षा संचालन केंद्र प्रवेश",
        "tab_login": "लॉग इन करा",
        "tab_register": "नवीन ऑपरेटर नोंदणी",
        "username": "वापरकर्ता नाव (Username)",
        "email": "अधिकृत ईमेल पत्ता",
        "password": "पासवर्ड",
        "confirm_password": "पासवर्डची पुष्टी करा",
        "language_pref": "पसंतीची भाषा",
        "btn_submit_login": "प्रवेश अधिकृत करा",
        "btn_submit_register": "खाते तयार करा",
        "demo_login": "त्वरित डेमो लॉगिन",
        "welcome_user": "स्वागत आहे, ऑपरेटर",
        "err_invalid_creds": "प्रमाणीकरण अयशस्वी. अवैध वापरकर्तानाव/ईमेल किंवा पासवर्ड.",
        "msg_registered": "खाते यशस्वीरित्या तयार झाले! आता आपण लॉग इन करू शकता.",
        
        # Scan History
        "history_title": "सुरक्षा ऑडिट आणि टेलीमेट्री नोंदी",
        "history_empty": "अद्याप कोणतेही सुरक्षा स्कॅन नोंदवलेले नाहीत. वरील सुरक्षा साधनांचा वापर करून ऑडिट सुरू करा.",
        "col_id": "ऑडिट आयडी",
        "col_tool": "सुरक्षा साधन",
        "col_target": "लक्ष्य",
        "col_result": "मुख्य निष्कर्ष",
        "col_time": "वेळ (UTC)",
    }
}

def t(key: str, lang: str = "en") -> str:
    """Retrieve translated text string with English fallback."""
    if not lang or lang not in TRANSLATIONS:
        lang = "en"
    lang_dict = TRANSLATIONS.get(lang, TRANSLATIONS["en"])
    return lang_dict.get(key, TRANSLATIONS["en"].get(key, key))
