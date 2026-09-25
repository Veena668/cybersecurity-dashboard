"""
Authentication and User Session Management Module.
Handles registration, login, bcrypt password hashing, input sanitization,
and session state control for CyberSOC.
"""

import re
import bcrypt
import streamlit as st
import database as db

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
USERNAME_REGEX = r"^[a-zA-Z0-9_]{3,30}$"

def validate_email(email: str) -> bool:
    """Validate email format with regex."""
    if not email:
        return False
    return bool(re.match(EMAIL_REGEX, email.strip()))

def validate_username(username: str) -> bool:
    """Validate username (3-30 chars, alphanumeric and underscore)."""
    if not username:
        return False
    return bool(re.match(USERNAME_REGEX, username.strip()))

def hash_password(password: str) -> str:
    """Hash password using bcrypt with 12 salt rounds."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def register_user(username: str, email: str, password: str, language_pref: str = "en"):
    """Register a new user with validation and bcrypt hashing."""
    username = username.strip()
    email = email.strip().lower()

    if not validate_username(username):
        return False, "Username must be 3-30 characters (letters, numbers, underscores only)."

    if not validate_email(email):
        return False, "Invalid email address format."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    # Check if username or email already exists
    if db.get_user_by_username(username):
        return False, "Username already exists. Please choose a different one."

    if db.get_user_by_email(email):
        return False, "Email is already registered. Please login instead."

    pwd_hash = hash_password(password)
    success, msg = db.create_user(username, email, pwd_hash, language_pref)
    return success, msg

def authenticate_user(username_or_email: str, password: str):
    """Authenticate user credentials and initialize session."""
    target = username_or_email.strip()
    if not target or not password:
        return False, "Please enter both credentials."

    user = None
    if "@" in target:
        user = db.get_user_by_email(target)
    else:
        user = db.get_user_by_username(target)

    if not user:
        return False, "Invalid username/email or password."

    if not verify_password(password, user["password_hash"]):
        return False, "Invalid username/email or password."

    # Initialize session state
    set_user_session(user)
    return True, "Login successful."

def set_user_session(user: dict):
    """Set authenticated session state."""
    st.session_state["authenticated"] = True
    st.session_state["user_id"] = user["id"]
    st.session_state["username"] = user["username"]
    st.session_state["email"] = user.get("email", "")
    st.session_state["lang"] = user.get("language_pref", "en") or "en"

def logout_user():
    """Clear session state and log out."""
    st.session_state["authenticated"] = False
    st.session_state["user_id"] = None
    st.session_state["username"] = None
    st.session_state["email"] = None
    st.rerun()

def is_authenticated() -> bool:
    """Check if current session is authenticated."""
    return st.session_state.get("authenticated", False)

def get_current_user():
    """Retrieve current logged-in user dictionary."""
    if not is_authenticated():
        return None
    return {
        "id": st.session_state.get("user_id"),
        "username": st.session_state.get("username"),
        "email": st.session_state.get("email"),
        "lang": st.session_state.get("lang", "en"),
    }
