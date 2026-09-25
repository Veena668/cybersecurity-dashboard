"""
CyberSOC: Production-Ready Animated Multilingual Cybersecurity Dashboard.
Built with Streamlit, Python, MySQL, SQLAlchemy, Bcrypt, Plotly, and Custom Glassmorphism UI.
"""

import json
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Custom modules
import database as db
import auth
from translations import t, TRANSLATIONS
from tools.scanner import scan_target
from tools.password_check import evaluate_password
from tools.phishing_detector import analyze_url

# Optional streamlit-option-menu import with graceful fallback
try:
    from streamlit_option_menu import option_menu
    OPTION_MENU_AVAILABLE = True
except ImportError:
    OPTION_MENU_AVAILABLE = False

# Page Configuration
st.set_page_config(
    page_title="CyberSOC // Threat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database
db_ok, db_engine_type = db.init_db()

# Initialize Session State
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None
if "username" not in st.session_state:
    st.session_state["username"] = None
if "email" not in st.session_state:
    st.session_state["email"] = None
if "lang" not in st.session_state:
    st.session_state["lang"] = "en"

lang = st.session_state["lang"]

# Inject Custom Glassmorphism & Keyframe Animation Styles
CSS_STYLES = """
<style>
/* Import Cyberpunk / Modern Tech Fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Outfit', sans-serif;
    color: #e2e8f0;
}

code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Background & Main App Canvas */
.stApp {
    background: radial-gradient(circle at 10% 20%, #0d1527 0%, #070a12 90%);
    background-attachment: fixed;
}

/* Glassmorphism Cards */
.glass-card {
    background: rgba(17, 26, 46, 0.65);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid rgba(0, 242, 254, 0.18);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px 0 rgba(0, 0, 0, 0.45);
    transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
}

.glass-card:hover {
    border-color: rgba(0, 242, 254, 0.45);
    box-shadow: 0 14px 40px 0 rgba(0, 242, 254, 0.12);
    transform: translateY(-2px);
}

/* Glowing Keyframe Pulse for Threat Badges */
@keyframes pulseGlow {
    0% {
        box-shadow: 0 0 5px rgba(255, 0, 85, 0.4), 0 0 15px rgba(255, 0, 85, 0.2);
    }
    50% {
        box-shadow: 0 0 20px rgba(255, 0, 85, 0.9), 0 0 35px rgba(255, 0, 85, 0.5);
    }
    100% {
        box-shadow: 0 0 5px rgba(255, 0, 85, 0.4), 0 0 15px rgba(255, 0, 85, 0.2);
    }
}

@keyframes pulseCyan {
    0% { box-shadow: 0 0 5px rgba(0, 242, 254, 0.3); }
    50% { box-shadow: 0 0 20px rgba(0, 242, 254, 0.8); }
    100% { box-shadow: 0 0 5px rgba(0, 242, 254, 0.3); }
}

@keyframes scanlineAnim {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(1000%); }
}

.threat-badge-pulse {
    display: inline-block;
    padding: 8px 16px;
    border-radius: 30px;
    background: linear-gradient(135deg, #ff0055 0%, #790025 100%);
    color: #ffffff;
    font-weight: 700;
    font-size: 0.88rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    animation: pulseGlow 2.2s infinite;
    border: 1px solid #ff4d88;
}

.status-badge-cyan {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: rgba(0, 242, 254, 0.15);
    color: #00f2fe;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid rgba(0, 242, 254, 0.4);
    animation: pulseCyan 3s infinite;
}

.status-badge-green {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: rgba(0, 245, 160, 0.15);
    color: #00f5a0;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid rgba(0, 245, 160, 0.4);
}

.status-badge-amber {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: rgba(255, 183, 3, 0.15);
    color: #ffb703;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid rgba(255, 183, 3, 0.4);
}

.status-badge-red {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: rgba(255, 0, 85, 0.15);
    color: #ff0055;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid rgba(255, 0, 85, 0.4);
}

/* Metrics Cards */
.soc-metric-box {
    background: rgba(14, 23, 42, 0.85);
    border: 1px solid rgba(0, 242, 254, 0.2);
    border-radius: 12px;
    padding: 16px 20px;
    text-align: left;
    position: relative;
    overflow: hidden;
}

.soc-metric-box::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 4px;
    height: 100%;
    background: linear-gradient(180deg, #00f2fe 0%, #4facfe 100%);
}

.soc-metric-value {
    font-size: 2rem;
    font-weight: 800;
    color: #ffffff;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 4px;
}

.soc-metric-title {
    font-size: 0.82rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* Strength Progress Bar */
.strength-bar-bg {
    width: 100%;
    height: 14px;
    background: #1e293b;
    border-radius: 8px;
    overflow: hidden;
    margin: 10px 0 15px 0;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.strength-bar-fill {
    height: 100%;
    transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 0 12px currentColor;
}

/* Custom Buttons */
.stButton>button {
    background: linear-gradient(135deg, #00f2fe 0%, #0072ff 100%);
    color: #050b14 !important;
    font-weight: 700;
    border: none;
    border-radius: 8px;
    padding: 10px 24px;
    transition: all 0.3s ease;
    letter-spacing: 0.5px;
}

.stButton>button:hover {
    box-shadow: 0 0 20px rgba(0, 242, 254, 0.6);
    transform: scale(1.02);
}

/* Form Inputs Styling */
.stTextInput>div>div>input {
    background-color: rgba(15, 23, 42, 0.75) !important;
    border: 1px solid rgba(0, 242, 254, 0.25) !important;
    color: #f1f5f9 !important;
    border-radius: 8px !important;
}

.stTextInput>div>div>input:focus {
    border-color: #00f2fe !important;
    box-shadow: 0 0 10px rgba(0, 242, 254, 0.3) !important;
}
</style>
"""
st.markdown(CSS_STYLES, unsafe_allow_html=True)


# =========================================================
# Sidebar: Language Selection, Status & Navigation
# =========================================================

with st.sidebar:
    st.markdown(
        f"""
        <div style="padding: 10px 0 15px 0; border-bottom: 1px solid rgba(0, 242, 254, 0.2);">
            <div style="font-size: 1.4rem; font-weight: 800; color: #00f2fe; letter-spacing: 1px;">
                🛡️ CYBER-SOC
            </div>
            <div style="font-size: 0.76rem; color: #94a3b8; margin-top: 2px;">
                {t('app_tagline', lang)}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 1. Multilingual Language Selector
    lang_options = {
        "en": "🇬🇧 English",
        "hi": "🇮🇳 हिन्दी (Hindi)",
        "mr": "🇮🇳 मराठी (Marathi)"
    }
    
    current_idx = list(lang_options.keys()).index(lang) if lang in lang_options else 0
    selected_lang = st.selectbox(
        "🌐 " + t("language_pref", lang),
        options=list(lang_options.keys()),
        index=current_idx,
        format_func=lambda x: lang_options[x],
        key="lang_selector"
    )

    if selected_lang != lang:
        st.session_state["lang"] = selected_lang
        if st.session_state.get("user_id"):
            db.update_user_language(st.session_state["user_id"], selected_lang)
        st.rerun()

    lang = st.session_state["lang"]

    # 2. Database Connection Badge
    db_badge_color = "#00f5a0" if "MySQL" in db_engine_type else "#ffb703"
    st.markdown(
        f"""
        <div style="margin: 12px 0; padding: 8px 12px; background: rgba(15, 23, 42, 0.6); border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.08); font-size: 0.78rem;">
            <span style="color: #94a3b8;">{t('connected_to', lang)}:</span> 
            <strong style="color: {db_badge_color};">● {db_engine_type}</strong>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Informative guide if in fallback mode
    if "SQLite" in db_engine_type:
        with st.expander("ℹ️ MySQL Setup Guide", expanded=False):
            st.caption(
                "Running in **Local SQLite Fallback**. To link your live MySQL (Aiven, Clever Cloud, or Local), update `.streamlit/secrets.toml`:\n"
                "```toml\n[mysql]\nhost = 'your-host'\nport = 3306\ndatabase = 'db_name'\nuser = 'user'\npassword = 'password'\n```"
            )

    # 3. User Session Info & Navigation
    if auth.is_authenticated():
        current_user = auth.get_current_user()
        st.markdown(
            f"""
            <div style="padding: 10px; background: rgba(0, 242, 254, 0.08); border-radius: 8px; border: 1px solid rgba(0, 242, 254, 0.2); margin-bottom: 15px;">
                <span style="font-size: 0.78rem; color: #94a3b8;">{t('welcome_user', lang)}:</span><br/>
                <strong style="color: #ffffff; font-size: 0.95rem;">⚡ {current_user['username']}</strong>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Main Navigation Menu
        menu_items = [
            t("nav_dashboard", lang),
            t("nav_scanner", lang),
            t("nav_password", lang),
            t("nav_phishing", lang),
            t("nav_history", lang),
        ]

        if OPTION_MENU_AVAILABLE:
            selected_nav = option_menu(
                menu_title=None,
                options=menu_items,
                icons=["speedometer2", "shield-check", "key", "link-45deg", "clock-history"],
                menu_icon="cast",
                default_index=0,
                styles={
                    "container": {"padding": "0!important", "background-color": "transparent"},
                    "icon": {"color": "#00f2fe", "font-size": "16px"},
                    "nav-link": {
                        "font-size": "14px",
                        "text-align": "left",
                        "margin": "4px 0",
                        "border-radius": "8px",
                        "color": "#94a3b8",
                        "padding": "10px 14px",
                    },
                    "nav-link-selected": {
                        "background-color": "rgba(0, 242, 254, 0.15)",
                        "color": "#00f2fe",
                        "font-weight": "700",
                        "border": "1px solid rgba(0, 242, 254, 0.4)",
                    },
                }
            )
        else:
            selected_nav = st.radio("Navigation", menu_items, label_visibility="collapsed")

        st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
        if st.button("🚪 " + t("nav_logout", lang), use_container_width=True):
            auth.logout_user()

    else:
        selected_nav = t("nav_login", lang)


# =========================================================
# View 0: Authentication View (Login / Registration)
# =========================================================

if not auth.is_authenticated():
    st.markdown(
        f"""
        <div style="text-align: center; margin: 30px 0 20px 0;">
            <div style="font-size: 2.4rem; font-weight: 800; color: #ffffff; letter-spacing: 1px;">
                🛡️ {t('app_title', lang)}
            </div>
            <div style="color: #00f2fe; font-size: 1rem; margin-top: 6px;">
                {t('app_tagline', lang)}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns([1, 2.2, 1])
    with col2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        tab_login, tab_reg = st.tabs([f"🔑 {t('tab_login', lang)}", f"📝 {t('tab_register', lang)}"])

        with tab_login:
            st.markdown(f"#### {t('login_title', lang)}")
            with st.form("form_login"):
                login_user = st.text_input(t("username", lang) + " / " + t("email", lang), placeholder="admin / operative@soc.local")
                login_pass = st.text_input(t("password", lang), type="password")
                submit_login = st.form_submit_button(t("btn_submit_login", lang), use_container_width=True)

                if submit_login:
                    ok, msg = auth.authenticate_user(login_user, login_pass)
                    if ok:
                        st.success("Authorization Granted. Initializing SOC Dashboard...")
                        time.sleep(0.6)
                        st.rerun()
                    else:
                        st.error(t("err_invalid_creds", lang))

            # Demo Mode Access Button
            st.markdown("<div style='text-align: center; margin: 15px 0 5px 0; color: #64748b;'>— OR —</div>", unsafe_allow_html=True)
            if st.button("⚡ " + t("demo_login", lang), use_container_width=True):
                # Check if demo user exists, create if not
                demo_user = db.get_user_by_username("demo_operative")
                if not demo_user:
                    db.create_user("demo_operative", "demo@soc.local", auth.hash_password("Demo@123456"), lang)
                    demo_user = db.get_user_by_username("demo_operative")
                auth.set_user_session(demo_user)
                st.rerun()

        with tab_reg:
            st.markdown(f"#### {t('tab_register', lang)}")
            with st.form("form_register"):
                reg_user = st.text_input(t("username", lang), placeholder="e.g. cyber_analyst_01")
                reg_email = st.text_input(t("email", lang), placeholder="analyst@domain.com")
                reg_pass = st.text_input(t("password", lang), type="password", placeholder="Minimum 8 characters")
                reg_confirm = st.text_input(t("confirm_password", lang), type="password")
                submit_reg = st.form_submit_button(t("btn_submit_register", lang), use_container_width=True)

                if submit_reg:
                    if reg_pass != reg_confirm:
                        st.error("Passwords do not match.")
                    else:
                        ok, msg = auth.register_user(reg_user, reg_email, reg_pass, lang)
                        if ok:
                            st.success(t("msg_registered", lang))
                        else:
                            st.error(msg)

        st.markdown('</div>', unsafe_allow_html=True)

    st.stop()


# =========================================================
# View 1: Main Dashboard (Overview & SOC Threat Telemetry)
# =========================================================

if selected_nav == t("nav_dashboard", lang):
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px;">
            <div>
                <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: #ffffff;">
                    🛡️ {t('nav_dashboard', lang)}
                </h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                    {t('app_tagline', lang)}
                </p>
            </div>
            <div>
                <span class="threat-badge-pulse">🚨 {t('metric_threat_level', lang)}: {t('threat_elevated', lang)}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 1. Top Threat Metric Cards
    metrics_data = db.get_dashboard_metrics()
    total_scans = metrics_data.get("total_scans", 0)
    vuln_scans = metrics_data.get("vuln_scans", 0)
    phish_scans = metrics_data.get("phish_scans", 0)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(
            f"""
            <div class="soc-metric-box">
                <div class="soc-metric-title">{t('metric_threat_level', lang)}</div>
                <div class="soc-metric-value" style="color: #ff0055; font-size: 1.6rem;">DEFCON 3</div>
                <div style="font-size: 0.74rem; color: #94a3b8; margin-top: 4px;">ACTIVE MONITORING</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m2:
        st.markdown(
            f"""
            <div class="soc-metric-box">
                <div class="soc-metric-title">{t('metric_total_scans', lang)}</div>
                <div class="soc-metric-value">{total_scans}</div>
                <div style="font-size: 0.74rem; color: #00f2fe; margin-top: 4px;">↑ TELEMETRY AGGREGATED</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m3:
        st.markdown(
            f"""
            <div class="soc-metric-box">
                <div class="soc-metric-title">{t('metric_vulns_found', lang)}</div>
                <div class="soc-metric-value" style="color: #ffb703;">{vuln_scans}</div>
                <div style="font-size: 0.74rem; color: #94a3b8; margin-top: 4px;">AUDITED ENDPOINTS</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m4:
        st.markdown(
            f"""
            <div class="soc-metric-box">
                <div class="soc-metric-title">{t('metric_phish_blocked', lang)}</div>
                <div class="soc-metric-value" style="color: #00f5a0;">{phish_scans}</div>
                <div style="font-size: 0.74rem; color: #00f5a0; margin-top: 4px;">HEURISTICALLY INTERCEPTED</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 25px;'></div>", unsafe_allow_html=True)

    # 2. Interactive Plotly Charts
    chart_col1, chart_col2 = st.columns([1.2, 1.8])

    with chart_col1:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown(f"#### 🌐 {t('chart_vector_title', lang)}")
        
        # Donut Chart: Threat Vectors
        vector_df = pd.DataFrame({
            "Vector": ["Phishing / Social Eng", "Web Exploit / Injection", "Credential Stuffing", "DDoS / Flooding", "Malware Delivery"],
            "Incidents": [38, 27, 21, 14, 12]
        })
        fig_donut = px.pie(
            vector_df,
            values="Incidents",
            names="Vector",
            hole=0.55,
            color_discrete_sequence=["#ff0055", "#00f2fe", "#ffb703", "#7928ca", "#00f5a0"]
        )
        fig_donut.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_donut, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with chart_col2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown(f"#### 📈 {t('chart_timeline_title', lang)}")
        
        # 24-Hour Intrusion Attempts Timeline
        timeline_df = pd.DataFrame({
            "Hour": [f"{h:02d}:00" for h in range(0, 24, 2)],
            "Blocked Attacks": [12, 19, 14, 26, 42, 65, 88, 74, 56, 48, 35, 22],
            "Port Scans": [45, 52, 60, 85, 110, 140, 195, 160, 125, 95, 80, 50]
        })
        fig_timeline = go.Figure()
        fig_timeline.add_trace(go.Scatter(
            x=timeline_df["Hour"], y=timeline_df["Port Scans"],
            mode="lines+markers",
            name="Probes & Scans",
            line=dict(color="#00f2fe", width=2),
            fill="tozeroy",
            fillcolor="rgba(0, 242, 254, 0.08)"
        ))
        fig_timeline.add_trace(go.Scatter(
            x=timeline_df["Hour"], y=timeline_df["Blocked Attacks"],
            mode="lines+markers",
            name="Intrusions Blocked",
            line=dict(color="#ff0055", width=3),
            fill="tozeroy",
            fillcolor="rgba(255, 0, 85, 0.15)"
        ))
        fig_timeline.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zerolinecolor="rgba(255,255,255,0.1)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zerolinecolor="rgba(255,255,255,0.1)"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # 3. Recent Scans Table
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown(f"#### 📋 {t('recent_activity', lang)}")
    recent_scans = db.get_user_scans(st.session_state["user_id"], limit=5)

    if recent_scans:
        data_rows = []
        for s in recent_scans:
            data_rows.append({
                t("col_id", lang): s["id"],
                t("col_tool", lang): s["tool_name"],
                t("col_target", lang): s["target_input"][:45] + ("..." if len(s["target_input"]) > 45 else ""),
                t("col_time", lang): s["scanned_at"],
            })
        st.dataframe(pd.DataFrame(data_rows), use_container_width=True, hide_index=True)
    else:
        st.info(t("history_empty", lang))
    st.markdown('</div>', unsafe_allow_html=True)


# =========================================================
# View 2: Tool A - Vulnerability Scanner
# =========================================================

elif selected_nav == t("nav_scanner", lang):
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: #ffffff;">
                🔍 {t('scanner_title', lang)}
            </h1>
            <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                {t('scanner_desc', lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    target_in = st.text_input(
        t("target_label", lang),
        value="https://example.com",
        placeholder=t("target_placeholder", lang)
    )

    col_btn, col_hint = st.columns([1, 3])
    with col_btn:
        start_scan = st.button("🚀 " + t("btn_scan", lang), use_container_width=True)
    with col_hint:
        st.caption("Quick Audits: `https://example.com` • `https://google.com` • `127.0.0.1`")

    st.markdown('</div>', unsafe_allow_html=True)

    if start_scan and target_in:
        with st.spinner(t("status_scanning", lang)):
            scan_progress = st.progress(15)
            time.sleep(0.3)
            scan_progress.progress(50)
            res = scan_target(target_in)
            scan_progress.progress(100)
            time.sleep(0.2)
            scan_progress.empty()

        # Save scan to database
        db.save_scan(st.session_state["user_id"], "Vulnerability Scanner", target_in, res)

        # Render Scan Results
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        col_res1, col_res2 = st.columns([1.2, 2.8])

        score = res.get("security_score", 0)
        badge_color = res.get("badge_color", "#00f5a0")

        with col_res1:
            st.markdown(f"### {t('vuln_score_label', lang)}")
            # Circular Gauge Chart
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": res.get("rating", ""), "font": {"size": 14, "color": badge_color}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                    "bar": {"color": badge_color},
                    "bgcolor": "rgba(255,255,255,0.05)",
                    "steps": [
                        {"range": [0, 45], "color": "rgba(255, 0, 85, 0.2)"},
                        {"range": [45, 75], "color": "rgba(255, 183, 3, 0.2)"},
                        {"range": [75, 100], "color": "rgba(0, 245, 160, 0.2)"},
                    ],
                }
            ))
            fig_gauge.update_layout(
                margin=dict(t=30, b=10, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#ffffff")
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        with col_res2:
            st.markdown(f"### {t('scan_summary_title', lang)}")
            st.write(f"**Target Host:** `{res.get('hostname')}` | **IP:** `{res.get('resolved_ip', 'N/A')}`")
            st.write(f"**HTTPS Enabled:** {'✅ Yes' if res.get('is_https') else '❌ No (Unencrypted)'}")
            
            if res.get("server_banner"):
                st.warning(f"⚠️ {t('info_disclosure', lang)}: `{res.get('server_banner')}`")
            if res.get("x_powered_by"):
                st.warning(f"⚠️ X-Powered-By Header: `{res.get('x_powered_by')}`")

            # Exposed Ports
            open_ports = res.get("open_ports", [])
            if open_ports:
                st.markdown(f"**{t('open_ports_detected', lang)}:**")
                port_pills = " ".join([f"`Port {p['port']} ({p['service']})`" for p in open_ports])
                st.markdown(port_pills)
            else:
                st.info("No standard open ports exposed directly on target.")

        st.markdown('</div>', unsafe_allow_html=True)

        # Tabbed Findings & Hardening Recommendations
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        tab_headers, tab_issues, tab_remed = st.tabs(["🛡️ Security Headers", "⚠️ Detected Issues", "🔧 Remediation Code"])

        with tab_headers:
            st.markdown("##### Header Audit Breakdown:")
            header_col1, header_col2 = st.columns(2)
            with header_col1:
                st.markdown("**Active Security Headers:**")
                if res.get("headers_found"):
                    for h, v in res["headers_found"].items():
                        st.success(f"✅ **{h}**\n\n`{v[:60]}`")
                else:
                    st.caption("No recommended security headers configured.")

            with header_col2:
                st.markdown("**Missing Security Headers:**")
                if res.get("headers_missing"):
                    for h, meta in res["headers_missing"].items():
                        st.error(f"❌ **{h}** ({meta['severity']})\n\n{meta['description']}")
                else:
                    st.success("All recommended defense headers present!")

        with tab_issues:
            issues = res.get("issues", [])
            if issues:
                for issue in issues:
                    badge_cls = "status-badge-red" if issue["severity"] in ["CRITICAL", "HIGH"] else "status-badge-amber"
                    st.markdown(
                        f"""
                        <div style="padding: 12px; border-left: 3px solid #ff0055; background: rgba(255,0,85,0.06); border-radius: 6px; margin-bottom: 10px;">
                            <span class="{badge_cls}">{issue['severity']}</span>
                            <strong style="margin-left: 8px; color: #ffffff;">{issue['item']}</strong>
                            <p style="margin: 6px 0 0 0; color: #cbd5e1; font-size: 0.88rem;">{issue['description']}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.success("Zero critical security defects identified!")

        with tab_remed:
            st.markdown("##### Web Server Hardening Directives:")
            st.markdown("**Nginx Configuration (`/etc/nginx/nginx.conf`):**")
            st.code("""
# Add Security Headers to Server Block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self';" always;
server_tokens off;
            """, language="nginx")

            st.markdown("**Apache Configuration (`.htaccess`):**")
            st.code("""
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
ServerSignature Off
ServerTokens Prod
            """, language="apache")

        st.markdown('</div>', unsafe_allow_html=True)


# =========================================================
# View 3: Tool B - Password Strength Checker
# =========================================================

elif selected_nav == t("nav_password", lang):
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: #ffffff;">
                🔐 {t('password_title', lang)}
            </h1>
            <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                {t('password_desc', lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    col_input, col_opt = st.columns([3, 1])
    with col_input:
        test_pwd = st.text_input(
            t("password_input_label", lang),
            type="password",
            placeholder="Type a password to audit (e.g. CorrectHorseBatteryStaple!2026)"
        )
    with col_opt:
        st.markdown("<div style='height: 27px;'></div>", unsafe_allow_html=True)
        eval_btn = st.button("⚡ " + t("btn_evaluate", lang), use_container_width=True)

    st.markdown('</div>', unsafe_allow_html=True)

    if test_pwd:
        res_pwd = evaluate_password(test_pwd)

        # Log audit safely (fingerprint hash only)
        if eval_btn:
            db.save_scan(
                st.session_state["user_id"],
                "Password Checker",
                f"Password Audit (Fingerprint: {res_pwd['masked_hash']})",
                res_pwd
            )

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        
        # Animated Glowing Strength Meter
        pct = res_pwd["percentage"]
        color = res_pwd["color"]
        label = res_pwd["strength_label"]

        st.markdown(
            f"""
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-weight: 700; color: {color}; font-size: 1.15rem; letter-spacing: 0.5px;">
                    {label}
                </span>
                <span style="font-weight: 800; color: #ffffff; font-family: 'JetBrains Mono'; font-size: 1.2rem;">
                    {pct}%
                </span>
            </div>
            <div class="strength-bar-bg">
                <div class="strength-bar-fill" style="width: {pct}%; background: {color};"></div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Password Metrics
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.metric(t("entropy_bits", lang), f"{res_pwd['entropy']} bits")
        with p2:
            st.metric("Character Length", f"{res_pwd['length']} chars")
        with p3:
            st.metric(t("crack_time_fast", lang), res_pwd["crack_times"].get("offline_fast_hashing_1e10_per_second", "N/A"))
        with p4:
            st.metric(t("crack_time_online", lang), res_pwd["crack_times"].get("online_throttled_100_per_hour", "N/A"))

        st.markdown("<hr style='border-color: rgba(255,255,255,0.08); margin: 20px 0;'>", unsafe_allow_html=True)

        # Criteria Checklist & Recommendations
        col_crit, col_sugg = st.columns(2)
        with col_crit:
            st.markdown("##### 📋 NIST 800-63B Resilience Criteria:")
            crit = res_pwd["criteria"]
            st.write(f"{'✅' if crit.get('length_12') else '❌'} {t('crit_length', lang)}")
            st.write(f"{'✅' if crit.get('uppercase') else '❌'} {t('crit_upper', lang)}")
            st.write(f"{'✅' if crit.get('lowercase') else '❌'} {t('crit_lower', lang)}")
            st.write(f"{'✅' if crit.get('numbers') else '❌'} {t('crit_digits', lang)}")
            st.write(f"{'✅' if crit.get('special_chars') else '❌'} {t('crit_special', lang)}")
            st.write(f"{'✅' if crit.get('entropy_high') else '❌'} {t('crit_dictionary', lang)}")

        with col_sugg:
            st.markdown(f"##### 💡 {t('password_suggestion', lang)}:")
            warning = res_pwd["feedback"].get("warning")
            suggestions = res_pwd["feedback"].get("suggestions", [])

            if warning:
                st.warning(f"⚠️ **{t('password_warning', lang)}:** {warning}")
            if suggestions:
                for s in suggestions:
                    st.info(f"👉 {s}")
            if not warning and not suggestions:
                st.success("🌟 Outstanding entropy and unpredictability. Excellent resilience against dictionary attacks.")

        st.markdown('</div>', unsafe_allow_html=True)


# =========================================================
# View 4: Tool C - URL Phishing Detection
# =========================================================

elif selected_nav == t("nav_phishing", lang):
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: #ffffff;">
                🎣 {t('phishing_title', lang)}
            </h1>
            <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                {t('phishing_desc', lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    target_url = st.text_input(
        t("url_input_label", lang),
        value="http://192.168.1.1/paypal.com/login-verify.php@account-update.tk",
        placeholder="Enter suspected phishing link..."
    )

    col_btn_p, col_samples = st.columns([1, 3])
    with col_btn_p:
        analyze_btn = st.button("🔎 " + t("btn_analyze", lang), use_container_width=True)
    with col_samples:
        st.caption("Try Samples: `https://paypal.com` • `http://192.168.1.1/update` • `http://chase-security-login.xyz`")

    st.markdown('</div>', unsafe_allow_html=True)

    if target_url:
        res_phish = analyze_url(target_url)

        if analyze_btn:
            db.save_scan(st.session_state["user_id"], "Phishing Detector", target_url, res_phish)

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        col_gauge, col_verdict = st.columns([1.2, 2.8])

        score = res_phish["risk_score"]
        color = res_phish["color"]
        classification = res_phish["classification"]

        with col_gauge:
            st.markdown(f"### {t('risk_score', lang)}")
            # Gauge chart for Phishing Risk
            fig_phish = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                number={"suffix": "%", "font": {"color": color, "size": 36}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                    "bar": {"color": color},
                    "bgcolor": "rgba(255,255,255,0.05)",
                    "steps": [
                        {"range": [0, 25], "color": "rgba(0, 245, 160, 0.2)"},
                        {"range": [25, 50], "color": "rgba(0, 242, 254, 0.2)"},
                        {"range": [50, 75], "color": "rgba(255, 183, 3, 0.2)"},
                        {"range": [75, 100], "color": "rgba(255, 0, 85, 0.2)"},
                    ],
                }
            ))
            fig_phish.update_layout(
                margin=dict(t=20, b=10, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#ffffff")
            )
            st.plotly_chart(fig_phish, use_container_width=True)

        with col_verdict:
            st.markdown("### Threat Classification")
            badge_type = "threat-badge-pulse" if score >= 75 else ("status-badge-amber" if score >= 45 else "status-badge-green")
            st.markdown(f'<span class="{badge_type}">{classification}</span>', unsafe_allow_html=True)

            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            st.write(f"**Hostname:** `{res_phish['hostname']}`")
            st.write(f"**Domain Entropy:** `{res_phish['domain_entropy']}` (Measure of algorithmic randomness)")
            st.write(f"**HTTPS Encryption:** {'🔒 Active' if res_phish['is_https'] else '⚠️ Unencrypted HTTP'}")
            st.write(f"**Total Heuristic Anomalies Flagged:** `{res_phish['total_factors']}`")

        st.markdown('</div>', unsafe_allow_html=True)

        # Flagged Factors Breakdown
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown("#### 🚨 Flagged Risk Factors & Signatures:")

        factors = res_phish.get("factors_flagged", [])
        if factors:
            for f in factors:
                severity_cls = "status-badge-red" if f["status"] == "CRITICAL" else ("status-badge-amber" if f["status"] == "HIGH" else "status-badge-cyan")
                st.markdown(
                    f"""
                    <div style="padding: 12px; background: rgba(15, 23, 42, 0.7); border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.08); margin-bottom: 10px;">
                        <span class="{severity_cls}">{f['status']} (+{f['risk_weight']} pts)</span>
                        <strong style="margin-left: 10px; color: #ffffff;">{f['name']}</strong>
                        <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.88rem;">{f['detail']}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.success("✅ No suspicious phishing patterns, domain obfuscations, or typosquatting techniques detected.")

        st.markdown('</div>', unsafe_allow_html=True)


# =========================================================
# View 5: Audit History View
# =========================================================

elif selected_nav == t("nav_history", lang):
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 10px;">
            <div>
                <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: #ffffff;">
                    📜 {t('history_title', lang)}
                </h1>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                    Archived security scans stored in parameterized MySQL database.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    scans = db.get_user_scans(st.session_state["user_id"], limit=50)

    if scans:
        # Export buttons
        df_export = pd.DataFrame(scans)
        csv_data = df_export.to_csv(index=False).encode("utf-8")
        json_data = json.dumps(scans, indent=2, default=str).encode("utf-8")

        col_c, col_j, _ = st.columns([1, 1, 2])
        with col_c:
            st.download_button(
                "📥 " + t("btn_export_csv", lang),
                data=csv_data,
                file_name=f"cybersoc_audit_{int(time.time())}.csv",
                mime="text/csv",
                use_container_width=True
            )
        with col_j:
            st.download_button(
                "📦 " + t("btn_export_json", lang),
                data=json_data,
                file_name=f"cybersoc_audit_{int(time.time())}.json",
                mime="application/json",
                use_container_width=True
            )

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        for s in scans:
            with st.expander(f"📌 [{s['tool_name']}] {s['target_input']} — {s['scanned_at']}"):
                st.write(f"**Audit ID:** `{s['id']}` | **Timestamp:** `{s['scanned_at']}`")
                st.json(s["result_json"])
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.info(t("history_empty", lang))
        st.markdown('</div>', unsafe_allow_html=True)
