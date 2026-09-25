# 🛡️ CyberSOC: Multilingual Cybersecurity Intelligence Dashboard

A production-grade, animated, multilingual Cybersecurity Operations Center (SOC) dashboard built with **Streamlit**, **Python**, and **MySQL**.

![CyberSOC Dashboard](https://img.shields.io/badge/Security-SOC%20Level%203-00f2fe?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?style=for-the-badge&logo=streamlit)
![MySQL](https://img.shields.io/badge/MySQL-8.0%2B-00758F?style=for-the-badge&logo=mysql)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 🌟 Key Features

1. **Cyberpunk Glassmorphism UI**:
   - Translucent glassmorphic cards (`backdrop-filter: blur(14px)`).
   - Dynamic CSS keyframe animations (`@keyframes pulseGlow`, radar scanlines, glowing metric boxes).
   - High-contrast dark SOC theme optimized for threat visualization.

2. **Multilingual Support (3 Languages)**:
   - Full translation support for **English (`en`)**, **Hindi (`hi` - हिन्दी)**, and **Marathi (`mr` - मराठी)**.
   - Dynamic language switcher in the sidebar that instantly switches UI text and persists user language preference in the database.

3. **Production Database & Security Architecture**:
   - Parameterized SQL execution using SQLAlchemy and PyMySQL (`sqlalchemy.text` with parameter binding) to eliminate SQL Injection.
   - Secure password hashing with `bcrypt` (12 salt rounds).
   - Resilient database engine: automatically connects to MySQL (via `.streamlit/secrets.toml`), with an automatic fallback to local SQLite for offline development or instant testability.

4. **Security Toolset**:
   - **Tool A: Vulnerability & Header Scanner**: Inspects target endpoints for essential HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), flags server banner disclosures, inspects cookie security attributes (`Secure`, `HttpOnly`), performs fast non-blocking port probing (`80`, `443`, `8080`, `8443`, `21`, `22`, `3306`), and produces remediation code for Nginx and Apache.
   - **Tool B: Password Strength Evaluator**: Evaluates password entropy (bits), resistance against fast offline attacks (10B guesses/sec) and online throttled attacks using `zxcvbn`, checks NIST 800-63B criteria, and presents an animated glowing strength bar with remediation recommendations.
   - **Tool C: URL Phishing Detector**: Evaluates heuristic risk factors (raw IP hostnames, embedded `@` obfuscation, subdomain nesting depth > 3, homoglyphs / Punycode `xn--`, suspicious TLDs, typosquatting hyphens, double-slash paths, credential keywords, and Shannon domain entropy) to compute a 0-100% risk score.
   - **Audit History & Telemetry Logs**: Persistent audit trail for authenticated operatives with CSV and JSON export capabilities.

---

## 📁 Repository Structure

```
cybersecurity_dashboard/
├── .streamlit/
│   ├── config.toml           # Obsidian Cyberpunk theme & server settings
│   └── secrets.toml          # MySQL credentials and application secrets
├── tools/
│   ├── __init__.py
│   ├── scanner.py            # Tool A: Vulnerability & HTTP Header/Port Scanner
│   ├── password_check.py     # Tool B: Password Strength & Entropy Evaluator
│   └── phishing_detector.py  # Tool C: Heuristic Phishing Detector
├── schema.sql                # Production MySQL DDL schema
├── database.py               # SQLAlchemy engine, connection pooling, and parameterized queries
├── auth.py                   # User authentication, bcrypt hashing, session control
├── translations.py           # Multilingual mapping for English, Hindi, and Marathi
├── app.py                    # Main Streamlit application
├── requirements.txt          # Production dependencies for Streamlit Cloud & local
└── README.md                 # Setup and deployment documentation
```

---

## 🚀 Quickstart Guide

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/your-username/cybersecurity-dashboard.git
cd cybersecurity-dashboard

# Create virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate
# Or on Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure MySQL Database

#### Option A: Cloud MySQL (Aiven / Clever Cloud / AWS RDS)
1. Provision a free MySQL database on [Aiven](https://aiven.io/) or [Clever Cloud](https://www.clever-cloud.com/).
2. Open `.streamlit/secrets.toml` and configure your credentials:

```toml
[mysql]
host = "mysql-instance.aivencloud.com"
port = 12345
database = "defaultdb"
user = "avnadmin"
password = "your_secure_password"
ssl_mode = "REQUIRED"
```

#### Option B: Local MySQL
1. Log into your local MySQL server:
   ```bash
   mysql -u root -p < schema.sql
   ```
2. Update `.streamlit/secrets.toml`:
   ```toml
   [mysql]
   host = "localhost"
   port = 3306
   database = "cyber_security_db"
   user = "root"
   password = "your_local_password"
   ```

#### Option C: Out-of-the-box Fallback Mode
If `.streamlit/secrets.toml` contains default placeholder values or MySQL is unreachable, the dashboard automatically activates **Local SQLite Fallback (`cyber_soc.db`)** so you can test all features immediately without any manual database setup.

---

### 3. Launch the Dashboard

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## ☁️ Deployment to Streamlit Community Cloud

1. Push your repository to **GitHub**:
   ```bash
   git init
   git add .
   git commit -m "feat: initial release of CyberSOC dashboard"
   git branch -M main
   git remote add origin https://github.com/your-username/cybersecurity-dashboard.git
   git push -u origin main
   ```
2. Sign in to [share.streamlit.io](https://share.streamlit.io).
3. Click **New App**, select your GitHub repository, branch `main`, and main file `app.py`.
4. Under **Advanced settings** -> **Secrets**, paste your `.streamlit/secrets.toml` configuration:
   ```toml
   [mysql]
   host = "your-mysql-host.aivencloud.com"
   port = 3306
   database = "cyber_security_db"
   user = "your_user"
   password = "your_password"
   ssl_mode = "REQUIRED"
   ```
5. Click **Deploy!**

---

## 🔒 Security & Defensive Guarantees

- **No SQL Injection**: All queries use SQLAlchemy parameterized expressions (`text("... :param")`).
- **No Password Leakage**: Passwords evaluated in the Password Checker are never stored in plaintext in the scan history; only an anonymized SHA-256 fingerprint is recorded.
- **Defensive Auditing**: The vulnerability scanner performs non-invasive HTTP header and standard port evaluations strictly for defensive posture assessments.
