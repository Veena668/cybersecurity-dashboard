"""
CyberSOC: Production-Ready Animated Multilingual Cybersecurity Dashboard.
Built with Streamlit, Python, MySQL, SQLAlchemy, Bcrypt, Plotly, and Dual-Theme Glassmorphism UI.
Supports Dark Mode (default) and Light Mode, with Quick Tool Shortcuts and Multilingual Navigation.
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
if "nav_target_index" not in st.session_state:
    st.session_state["nav_target_index"] = 0

lang = st.session_state["lang"]
is_dark = True


theme_css = """
    :root {
        --bg-main: radial-gradient(circle at 10% 20%, #0d1527 0%, #070a12 90%);
        --bg-card: rgba(17, 26, 46, 0.75);
        --border-card: rgba(0, 242, 254, 0.22);
        --border-card-hover: rgba(0, 242, 254, 0.55);
        --text-primary: #e2e8f0;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        --accent-cyan: #00f2fe;
        --accent-blue: #0072ff;
        --sidebar-bg: #0b1326;
        --sidebar-border: rgba(0, 242, 254, 0.2);
        --input-bg: rgba(15, 23, 42, 0.85);
        --input-border: rgba(0, 242, 254, 0.25);
        --input-text: #f1f5f9;
        --btn-bg: linear-gradient(135deg, #00f2fe 0%, #0072ff 100%);
        --btn-text: #050b14;
        --btn-shadow-hover: 0 0 20px rgba(0, 242, 254, 0.6);
        --card-shadow: 0 10px 30px 0 rgba(0, 0, 0, 0.45);
        --card-shadow-hover: 0 14px 40px 0 rgba(0, 242, 254, 0.15);
        --badge-cyan-bg: rgba(0, 242, 254, 0.15);
        --badge-cyan-text: #00f2fe;
        --badge-cyan-border: rgba(0, 242, 254, 0.4);
        --badge-green-bg: rgba(0, 245, 160, 0.15);
        --badge-green-text: #00f5a0;
        --badge-green-border: rgba(0, 245, 160, 0.4);
        --badge-amber-bg: rgba(255, 183, 3, 0.15);
        --badge-amber-text: #ffb703;
        --badge-amber-border: rgba(255, 183, 3, 0.4);
        --badge-red-bg: rgba(255, 0, 85, 0.15);
        --badge-red-text: #ff0055;
        --badge-red-border: rgba(255, 0, 85, 0.4);
        --pulse-shadow-1: rgba(255, 0, 85, 0.4);
        --pulse-shadow-2: rgba(255, 0, 85, 0.9);
        --table-bg: rgba(15, 23, 42, 0.6);
    }
    """
chart_paper_bg = "rgba(0,0,0,0)"
chart_plot_bg = "rgba(0,0,0,0)"
chart_font_color = "#e2e8f0"
chart_grid_color = "rgba(255,255,255,0.06)"



COMMON_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Outfit:wght@300;400;600;700&display=swap');

""" + theme_css + """

html, body, [class*="css"] {
    font-family: 'Outfit', sans-serif;
    color: var(--text-primary);
}

code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Background & Canvas */
.stApp {
    background: var(--bg-main);
    background-attachment: fixed;
}

/* Sidebar Styling */
[data-testid="stSidebar"] {
    background-color: var(--sidebar-bg) !important;
    border-right: 1px solid var(--sidebar-border) !important;
}

[data-testid="stSidebar"] * {
    color: var(--text-primary);
}

/* Streamlit Container Borders (Zero Empty Boxes) */
[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--bg-card) !important;
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid var(--border-card) !important;
    border-radius: 14px !important;
    padding: 16px !important;
    margin-bottom: 18px !important;
    box-shadow: var(--card-shadow) !important;
    transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1) !important;
}

[data-testid="stVerticalBlockBorderWrapper"]:hover {
    border-color: var(--border-card-hover) !important;
    box-shadow: var(--card-shadow-hover) !important;
}

/* Shortcut Box Styling */
.shortcut-box {
    padding: 6px 2px 10px 2px;
    text-align: left;
}

.shortcut-icon {
    font-size: 2rem;
    margin-bottom: 8px;
}

.shortcut-title {
    font-size: 1.08rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 4px;
    letter-spacing: 0.3px;
}

.shortcut-desc {
    font-size: 0.84rem;
    color: var(--text-secondary);
    min-height: 40px;
    line-height: 1.35;
    margin-bottom: 8px;
}

/* Keyframe Animations */
@keyframes pulseGlow {
    0% { box-shadow: 0 0 5px var(--pulse-shadow-1); }
    50% { box-shadow: 0 0 20px var(--pulse-shadow-2); }
    100% { box-shadow: 0 0 5px var(--pulse-shadow-1); }
}

@keyframes pulseCyan {
    0% { box-shadow: 0 0 4px rgba(0, 242, 254, 0.3); }
    50% { box-shadow: 0 0 16px rgba(0, 242, 254, 0.7); }
    100% { box-shadow: 0 0 4px rgba(0, 242, 254, 0.3); }
}

.threat-badge-pulse {
    display: inline-block;
    padding: 8px 16px;
    border-radius: 30px;
    background: linear-gradient(135deg, #ff0055 0%, #790025 100%);
    color: #ffffff !important;
    font-weight: 700;
    font-size: 0.88rem;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    animation: pulseGlow 2.2s infinite;
    border: 1px solid #ff4d88;
}

.status-badge-cyan {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: var(--badge-cyan-bg);
    color: var(--badge-cyan-text) !important;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid var(--badge-cyan-border);
}

.status-badge-green {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: var(--badge-green-bg);
    color: var(--badge-green-text) !important;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid var(--badge-green-border);
}

.status-badge-amber {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: var(--badge-amber-bg);
    color: var(--badge-amber-text) !important;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid var(--badge-amber-border);
}

.status-badge-red {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 20px;
    background: var(--badge-red-bg);
    color: var(--badge-red-text) !important;
    font-weight: 600;
    font-size: 0.82rem;
    border: 1px solid var(--badge-red-border);
}

/* Strength Progress Bar */
.strength-bar-bg {
    width: 100%;
    height: 14px;
    background: var(--input-bg);
    border-radius: 8px;
    overflow: hidden;
    margin: 10px 0 15px 0;
    border: 1px solid var(--border-card);
}

.strength-bar-fill {
    height: 100%;
    transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    box-shadow: 0 0 12px currentColor;
}

/* Buttons */
.stButton>button {
    background: var(--btn-bg) !important;
    color: var(--btn-text) !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 9px 20px !important;
    transition: all 0.3s ease !important;
    letter-spacing: 0.5px !important;
}

.stButton>button:hover {
    box-shadow: var(--btn-shadow-hover) !important;
    transform: scale(1.02);
}

/* Form Inputs & Select Boxes */
.stTextInput>div>div>input, .stSelectbox>div>div {
    background-color: var(--input-bg) !important;
    border: 1px solid var(--input-border) !important;
    color: var(--input-text) !important;
    border-radius: 8px !important;
}

.stTextInput>div>div>input:focus {
    border-color: var(--accent-cyan) !important;
    box-shadow: 0 0 10px rgba(0, 242, 254, 0.25) !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
}
.stTabs [data-baseweb="tab"] {
    color: var(--text-secondary) !important;
    border-radius: 6px !important;
    padding: 8px 16px !important;
}
.stTabs [aria-selected="true"] {
    background-color: var(--input-bg) !important;
    color: var(--accent-cyan) !important;
    border-bottom: 2px solid var(--accent-cyan) !important;
}

/* Tables */
[data-testid="stDataFrame"] {
    background: var(--table-bg) !important;
    border-radius: 8px;
}
</style>
"""

st.markdown(COMMON_CSS, unsafe_allow_html=True)


# =========================================================
# Sidebar: Language, Theme, Status & Navigation
# =========================================================

with st.sidebar:
    st.markdown(
        f"""
        <div style="padding: 10px 0 15px 0; border-bottom: 1px solid var(--sidebar-border);">
            <div style="font-size: 1.4rem; font-weight: 800; color: var(--accent-cyan); letter-spacing: 1px;">
                🛡️ CYBER-SOC
            </div>
            <div style="font-size: 0.76rem; color: var(--text-secondary); margin-top: 2px;">
                {t('app_tagline', lang)}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # 1. Multilingual Selector
    lang_options = {
        "en": "🇬🇧 English",
        "hi": "🇮🇳 हिन्दी (Hindi)",
        "mr": "🇮🇳 मराठी (Marathi)"
    }
    current_lang_idx = list(lang_options.keys()).index(lang) if lang in lang_options else 0
    selected_lang = st.selectbox(
        "🌐 " + t("language_pref", lang),
        options=list(lang_options.keys()),
        index=current_lang_idx,
        format_func=lambda x: lang_options[x],
        key="lang_selector"
    )

    if selected_lang != lang:
        st.session_state["lang"] = selected_lang
        if st.session_state.get("user_id"):
            db.update_user_language(st.session_state["user_id"], selected_lang)
        st.rerun()

    lang = st.session_state["lang"]

    # 3. Database Connection Badge
    db_badge_color = "#00f5a0" if "MySQL" in db_engine_type else "#ffb703"
    st.markdown(
        f"""
        <div style="margin: 12px 0; padding: 8px 12px; background: var(--input-bg); border-radius: 8px; border: 1px solid var(--border-card); font-size: 0.78rem;">
            <span style="color: var(--text-secondary);">{t('connected_to', lang)}:</span> 
            <strong style="color: {db_badge_color};">● {db_engine_type}</strong>
        </div>
        """,
        unsafe_allow_html=True
    )

    if "SQLite" in db_engine_type:
        with st.expander("ℹ️ MySQL Setup Guide", expanded=False):
            st.caption(
                "Running in **Local SQLite Fallback**. To link your live MySQL (Aiven, Clever Cloud, or Local), update `.streamlit/secrets.toml`:\n"
                "```toml\n[mysql]\nhost = 'localhost'\nport = 3306\ndatabase = 'cyber_security_db'\nuser = 'root'\npassword = 'root'\n```"
            )

    # 4. User Session Info & Navigation Menu
    if auth.is_authenticated():
        current_user = auth.get_current_user()
        st.markdown(
            f"""
            <div style="padding: 10px; background: var(--input-bg); border-radius: 8px; border: 1px solid var(--border-card); margin-bottom: 15px;">
                <span style="font-size: 0.78rem; color: var(--text-secondary);">{t('welcome_user', lang)}:</span><br/>
                <strong style="color: var(--text-primary); font-size: 0.95rem;">⚡ {current_user['username']}</strong>
            </div>
            """,
            unsafe_allow_html=True
        )

        menu_items = [
            t("nav_dashboard", lang),
            t("nav_scanner", lang),
            t("nav_password", lang),
            t("nav_phishing", lang),
            t("nav_history", lang),
        ]

        current_target_idx = st.session_state.get("nav_target_index", 0)
        if current_target_idx < 0 or current_target_idx >= len(menu_items):
            current_target_idx = 0

        # Styles for option_menu depending on active theme
        if is_dark:
            opt_styles = {
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
        else:
            opt_styles = {
                "container": {"padding": "0!important", "background-color": "transparent"},
                "icon": {"color": "#0284c7", "font-size": "16px"},
                "nav-link": {
                    "font-size": "14px",
                    "text-align": "left",
                    "margin": "4px 0",
                    "border-radius": "8px",
                    "color": "#334155",
                    "padding": "10px 14px",
                },
                "nav-link-selected": {
                    "background-color": "#e0f2fe",
                    "color": "#0284c7",
                    "font-weight": "700",
                    "border": "1px solid #7dd3fc",
                },
            }

        if OPTION_MENU_AVAILABLE:
            selected_nav = option_menu(
                menu_title=None,
                options=menu_items,
                icons=["speedometer2", "shield-check", "key", "link-45deg", "clock-history"],
                menu_icon="cast",
                default_index=current_target_idx,
                key=f"sidebar_option_menu_{current_target_idx}",
                styles=opt_styles
            )
        else:
            selected_nav = st.radio("Navigation", menu_items, index=current_target_idx, label_visibility="collapsed")

        # Synchronize sidebar selection back to nav_target_index
        if selected_nav in menu_items:
            chosen_idx = menu_items.index(selected_nav)
            if chosen_idx != st.session_state.get("nav_target_index", 0):
                st.session_state["nav_target_index"] = chosen_idx
                st.rerun()

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
            <div style="font-size: 2.4rem; font-weight: 800; color: var(--text-primary); letter-spacing: 1px;">
                🛡️ {t('app_title', lang)}
            </div>
            <div style="color: var(--accent-cyan); font-size: 1rem; margin-top: 6px;">
                {t('app_tagline', lang)}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns([1, 2.2, 1])
    with col2:
        with st.container(border=True):
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
                            st.session_state["nav_target_index"] = 0
                            time.sleep(0.5)
                            st.rerun()
                        else:
                            st.error(t("err_invalid_creds", lang))

                st.markdown("<div style='text-align: center; margin: 15px 0 5px 0; color: var(--text-muted);'>— OR —</div>", unsafe_allow_html=True)
                if st.button("⚡ " + t("demo_login", lang), use_container_width=True):
                    demo_user = db.get_user_by_username("demo_operative")
                    if not demo_user:
                        db.create_user("demo_operative", "demo@soc.local", auth.hash_password("Demo@123456"), lang)
                        demo_user = db.get_user_by_username("demo_operative")
                    auth.set_user_session(demo_user)
                    st.session_state["nav_target_index"] = 0
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

    st.stop()


# =========================================================
# Determine Active View from nav_target_index
# (0=Dashboard, 1=Scanner, 2=Password, 3=Phishing, 4=History)
# =========================================================

active_view_idx = st.session_state.get("nav_target_index", 0)


# =========================================================
# View 1: Main Dashboard (Threat Dashboard)
# =========================================================

if active_view_idx == 0:
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 15px;">
            <div>
                <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: var(--text-primary);">
                    🛡️ {t('nav_dashboard', lang)}
                </h1>
                <p style="margin: 4px 0 0 0; color: var(--text-secondary); font-size: 0.95rem;">
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

    # 1. Four Clickable Quick Security Tool Shortcuts (Replacing static cards completely)
    sc1, sc2, sc3, sc4 = st.columns(4)

    with sc1:
        with st.container(border=True):
            st.markdown(
                f"""
                <div class="shortcut-box">
                    <div class="shortcut-icon">🛡️</div>
                    <div class="shortcut-title">{t('nav_scanner', lang)}</div>
                    <div class="shortcut-desc">Scan ports and security headers</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("Open Scanner →", key="sc_btn_scanner", use_container_width=True):
                st.session_state["nav_target_index"] = 1
                st.rerun()

    with sc2:
        with st.container(border=True):
            st.markdown(
                f"""
                <div class="shortcut-box">
                    <div class="shortcut-icon">🔐</div>
                    <div class="shortcut-title">{t('nav_password', lang)}</div>
                    <div class="shortcut-desc">Check password strength</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("Check Password →", key="sc_btn_password", use_container_width=True):
                st.session_state["nav_target_index"] = 2
                st.rerun()

    with sc3:
        with st.container(border=True):
            st.markdown(
                f"""
                <div class="shortcut-box">
                    <div class="shortcut-icon">🔗</div>
                    <div class="shortcut-title">{t('nav_phishing', lang)}</div>
                    <div class="shortcut-desc">Check suspicious URLs</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("Check URL →", key="sc_btn_phishing", use_container_width=True):
                st.session_state["nav_target_index"] = 3
                st.rerun()

    with sc4:
        with st.container(border=True):
            st.markdown(
                f"""
                <div class="shortcut-box">
                    <div class="shortcut-icon">🕐</div>
                    <div class="shortcut-title">{t('nav_history', lang)}</div>
                    <div class="shortcut-desc">View previous security scans</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("View History →", key="sc_btn_history", use_container_width=True):
                st.session_state["nav_target_index"] = 4
                st.rerun()

    st.markdown("<div style='height: 15px;'></div>", unsafe_allow_html=True)

    # 2. Interactive Theme-Adaptive Plotly Charts
    chart_col1, chart_col2 = st.columns([1.2, 1.8])

    with chart_col1:
        with st.container(border=True):
            st.markdown(f"#### 🌐 {t('chart_vector_title', lang)}")
            
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
                paper_bgcolor=chart_paper_bg,
                plot_bgcolor=chart_plot_bg,
                font=dict(color=chart_font_color),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_donut, use_container_width=True)

    with chart_col2:
        with st.container(border=True):
            st.markdown(f"#### 📈 {t('chart_timeline_title', lang)}")
            
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
                line=dict(color="#00f2fe" if is_dark else "#0284c7", width=2),
                fill="tozeroy",
                fillcolor="rgba(0, 242, 254, 0.08)" if is_dark else "rgba(2, 132, 199, 0.08)"
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
                paper_bgcolor=chart_paper_bg,
                plot_bgcolor=chart_plot_bg,
                font=dict(color=chart_font_color),
                xaxis=dict(gridcolor=chart_grid_color, zerolinecolor=chart_grid_color),
                yaxis=dict(gridcolor=chart_grid_color, zerolinecolor=chart_grid_color),
                legend=dict(orientation="h", yanchor="bottom", y=-0.25, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_timeline, use_container_width=True)

    # 3. Recent Activity Feed
    with st.container(border=True):
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


# =========================================================
# View 2: Tool A - Vulnerability Scanner (Index 1)
# =========================================================

elif active_view_idx == 1:
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: var(--text-primary);">
                🔍 {t('scanner_title', lang)}
            </h1>
            <p style="margin: 6px 0 0 0; color: var(--text-secondary); font-size: 0.95rem;">
                {t('scanner_desc', lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.container(border=True):
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
        with st.container(border=True):
            col_res1, col_res2 = st.columns([1.2, 2.8])

            score = res.get("security_score", 0)
            badge_color = res.get("badge_color", "#00f5a0")

            with col_res1:
                st.markdown(f"### {t('vuln_score_label', lang)}")
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    title={"text": res.get("rating", ""), "font": {"size": 14, "color": badge_color}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": chart_font_color},
                        "bar": {"color": badge_color},
                        "bgcolor": "rgba(255,255,255,0.05)" if is_dark else "#f1f5f9",
                        "steps": [
                            {"range": [0, 45], "color": "rgba(255, 0, 85, 0.2)"},
                            {"range": [45, 75], "color": "rgba(255, 183, 3, 0.2)"},
                            {"range": [75, 100], "color": "rgba(0, 245, 160, 0.2)"},
                        ],
                    }
                ))
                fig_gauge.update_layout(
                    margin=dict(t=30, b=10, l=20, r=20),
                    paper_bgcolor=chart_paper_bg,
                    plot_bgcolor=chart_plot_bg,
                    font=dict(color=chart_font_color)
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

                open_ports = res.get("open_ports", [])
                if open_ports:
                    st.markdown(f"**{t('open_ports_detected', lang)}:**")
                    port_pills = " ".join([f"`Port {p['port']} ({p['service']})`" for p in open_ports])
                    st.markdown(port_pills)
                else:
                    st.info("No standard open ports exposed directly on target.")

        # Tabbed Findings & Hardening Recommendations
        with st.container(border=True):
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
                            <div style="padding: 12px; border-left: 3px solid #ff0055; background: var(--input-bg); border-radius: 6px; margin-bottom: 10px;">
                                <span class="{badge_cls}">{issue['severity']}</span>
                                <strong style="margin-left: 8px; color: var(--text-primary);">{issue['item']}</strong>
                                <p style="margin: 6px 0 0 0; color: var(--text-secondary); font-size: 0.88rem;">{issue['description']}</p>
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


# =========================================================
# View 3: Tool B - Password Strength Checker (Index 2)
# =========================================================

elif active_view_idx == 2:
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: var(--text-primary);">
                🔐 {t('password_title', lang)}
            </h1>
            <p style="margin: 6px 0 0 0; color: var(--text-secondary); font-size: 0.95rem;">
                {t('password_desc', lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.container(border=True):
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

    if test_pwd:
        res_pwd = evaluate_password(test_pwd)

        if eval_btn:
            db.save_scan(
                st.session_state["user_id"],
                "Password Checker",
                f"Password Audit (Fingerprint: {res_pwd['masked_hash']})",
                res_pwd
            )

        with st.container(border=True):
            pct = res_pwd["percentage"]
            color = res_pwd["color"]
            label = res_pwd["strength_label"]

            st.markdown(
                f"""
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-weight: 700; color: {color}; font-size: 1.15rem; letter-spacing: 0.5px;">
                        {label}
                    </span>
                    <span style="font-weight: 800; color: var(--text-primary); font-family: 'JetBrains Mono'; font-size: 1.2rem;">
                        {pct}%
                    </span>
                </div>
                <div class="strength-bar-bg">
                    <div class="strength-bar-fill" style="width: {pct}%; background: {color};"></div>
                </div>
                """,
                unsafe_allow_html=True
            )

            p1, p2, p3, p4 = st.columns(4)
            with p1:
                st.metric(t("entropy_bits", lang), f"{res_pwd['entropy']} bits")
            with p2:
                st.metric("Character Length", f"{res_pwd['length']} chars")
            with p3:
                st.metric(t("crack_time_fast", lang), res_pwd["crack_times"].get("offline_fast_hashing_1e10_per_second", "N/A"))
            with p4:
                st.metric(t("crack_time_online", lang), res_pwd["crack_times"].get("online_throttled_100_per_hour", "N/A"))

            st.markdown("<hr style='border-color: var(--border-card); margin: 20px 0;'>", unsafe_allow_html=True)

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


# =========================================================
# View 4: Tool C - URL Phishing Detection (Index 3)
# =========================================================

elif active_view_idx == 3:
    st.markdown(
        f"""
        <div style="margin-bottom: 20px;">
            <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: var(--text-primary);">
                🎣 {t('phishing_title', lang)}
            </h1>
            <p style="margin: 6px 0 0 0; color: var(--text-secondary); font-size: 0.95rem;">
                {t('phishing_desc', lang)}
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.container(border=True):
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

    if target_url:
        res_phish = analyze_url(target_url)

        if analyze_btn:
            db.save_scan(st.session_state["user_id"], "Phishing Detector", target_url, res_phish)

        with st.container(border=True):
            col_gauge, col_verdict = st.columns([1.2, 2.8])

            score = res_phish["risk_score"]
            color = res_phish["color"]
            classification = res_phish["classification"]

            with col_gauge:
                st.markdown(f"### {t('risk_score', lang)}")
                fig_phish = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={"suffix": "%", "font": {"color": color, "size": 36}},
                    gauge={
                        "axis": {"range": [0, 100], "tickcolor": chart_font_color},
                        "bar": {"color": color},
                        "bgcolor": "rgba(255,255,255,0.05)" if is_dark else "#f1f5f9",
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
                    paper_bgcolor=chart_paper_bg,
                    plot_bgcolor=chart_plot_bg,
                    font=dict(color=chart_font_color)
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

        # Flagged Factors Breakdown
        with st.container(border=True):
            st.markdown("#### 🚨 Flagged Risk Factors & Signatures:")

            factors = res_phish.get("factors_flagged", [])
            if factors:
                for f in factors:
                    severity_cls = "status-badge-red" if f["status"] == "CRITICAL" else ("status-badge-amber" if f["status"] == "HIGH" else "status-badge-cyan")
                    st.markdown(
                        f"""
                        <div style="padding: 12px; background: var(--input-bg); border-radius: 8px; border: 1px solid var(--border-card); margin-bottom: 10px;">
                            <span class="{severity_cls}">{f['status']} (+{f['risk_weight']} pts)</span>
                            <strong style="margin-left: 10px; color: var(--text-primary);">{f['name']}</strong>
                            <p style="margin: 6px 0 0 0; color: var(--text-secondary); font-size: 0.88rem;">{f['detail']}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.success("✅ No suspicious phishing patterns, domain obfuscations, or typosquatting techniques detected.")


# =========================================================
# View 5: Audit History View (Index 4)
# =========================================================

elif active_view_idx == 4:
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 10px;">
            <div>
                <h1 style="margin: 0; font-size: 2rem; font-weight: 800; color: var(--text-primary);">
                    📜 {t('history_title', lang)}
                </h1>
                <p style="margin: 4px 0 0 0; color: var(--text-secondary); font-size: 0.95rem;">
                    Archived security scans stored in parameterized MySQL database.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    scans = db.get_user_scans(st.session_state["user_id"], limit=50)

    if scans:
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

        with st.container(border=True):
            for s in scans:
                with st.expander(f"📌 [{s['tool_name']}] {s['target_input']} — {s['scanned_at']}"):
                    st.write(f"**Audit ID:** `{s['id']}` | **Timestamp:** `{s['scanned_at']}`")
                    st.json(s["result_json"])
    else:
        with st.container(border=True):
            st.info(t("history_empty", lang))
