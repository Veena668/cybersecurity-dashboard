"""
Database Architecture and Management Module for CyberSOC.
Handles MySQL connections via SQLAlchemy/PyMySQL using Streamlit secrets,
with parameterized queries, connection pooling, and automatic fallback.
"""

import json
import logging
import os
import streamlit as st
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import QueuePool

# Setup logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberSOC.DB")

_ENGINE = None
_DB_TYPE = "UNKNOWN"

def get_db_credentials():
    """Retrieve database credentials from st.secrets or environment variables."""
    try:
        if "mysql" in st.secrets:
            cfg = st.secrets["mysql"]
            return {
                "host": cfg.get("host", "localhost"),
                "port": int(cfg.get("port", 3306)),
                "database": cfg.get("database", "cyber_security_db"),
                "user": cfg.get("user", "root"),
                "password": cfg.get("password", ""),
                "ssl_mode": cfg.get("ssl_mode", None),
                "ssl_ca": cfg.get("ssl_ca", None),
            }
    except Exception as e:
        logger.warning(f"Could not read st.secrets['mysql']: {e}")
    
    # Fallback to environment variables
    if os.getenv("MYSQL_HOST"):
        return {
            "host": os.getenv("MYSQL_HOST", "localhost"),
            "port": int(os.getenv("MYSQL_PORT", 3306)),
            "database": os.getenv("MYSQL_DATABASE", "cyber_security_db"),
            "user": os.getenv("MYSQL_USER", "root"),
            "password": os.getenv("MYSQL_PASSWORD", ""),
            "ssl_mode": os.getenv("MYSQL_SSL_MODE", None),
            "ssl_ca": os.getenv("MYSQL_SSL_CA", None),
        }
    return None

def get_engine():
    """Get or create singleton SQLAlchemy Engine."""
    global _ENGINE, _DB_TYPE
    if _ENGINE is not None:
        return _ENGINE, _DB_TYPE

    creds = get_db_credentials()
    if creds and creds["password"] and creds["password"] != "your_mysql_password_here":
        try:
            # Build MySQL connection string with PyMySQL
            user = creds["user"]
            pwd = creds["password"]
            host = creds["host"]
            port = creds["port"]
            dbname = creds["database"]
            
            conn_url = f"mysql+pymysql://{user}:{pwd}@{host}:{port}/{dbname}?charset=utf8mb4"
            connect_args = {"connect_timeout": 5}
            
            if creds.get("ssl_ca") and os.path.exists(creds["ssl_ca"]):
                connect_args["ssl"] = {"ca": creds["ssl_ca"]}
            elif creds.get("ssl_mode") == "REQUIRED":
                connect_args["ssl"] = {"check_hostname": False}

            engine = create_engine(
                conn_url,
                connect_args=connect_args,
                poolclass=QueuePool,
                pool_size=10,
                max_overflow=20,
                pool_recycle=300,
                pool_pre_ping=True
            )
            # Test connectivity
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            _ENGINE = engine
            _DB_TYPE = "MySQL"
            logger.info(f"Successfully connected to MySQL database: {dbname}@{host}")
            return _ENGINE, _DB_TYPE
        except Exception as e:
            logger.error(f"Failed to connect to MySQL ({e}). Falling back to local SQLite.")

    # Graceful fallback to local SQLite for seamless testing and offline reliability
    sqlite_path = os.path.join(os.path.dirname(__file__), "cyber_soc.db")
    engine = create_engine(
        f"sqlite:///{sqlite_path}",
        connect_args={"check_same_thread": False},
        pool_pre_ping=True
    )
    _ENGINE = engine
    _DB_TYPE = "SQLite (Local Fallback)"
    logger.info(f"Activated fallback SQLite engine at: {sqlite_path}")
    return _ENGINE, _DB_TYPE

def init_db():
    """Initialize database tables automatically if they do not exist."""
    engine, db_type = get_engine()
    
    # DDL tailored for either MySQL or SQLite
    if "MySQL" in db_type:
        users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            language_pref VARCHAR(10) DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        scan_table = """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            tool_name VARCHAR(50) NOT NULL,
            target_input TEXT NOT NULL,
            result_json LONGTEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user_id (user_id),
            INDEX idx_tool_name (tool_name),
            CONSTRAINT fk_scan_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
    else:
        users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            language_pref TEXT DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        scan_table = """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            target_input TEXT NOT NULL,
            result_json TEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """

    try:
        with engine.begin() as conn:
            conn.execute(text(users_table))
            conn.execute(text(scan_table))
        logger.info(f"Database schema initialized successfully on {db_type}.")
        return True, db_type
    except Exception as e:
        logger.error(f"Error during schema initialization: {e}")
        return False, str(e)

# Parameterized Query Functions

def create_user(username: str, email: str, password_hash: str, language_pref: str = "en"):
    """Insert a new user using parameterized SQL."""
    engine, _ = get_engine()
    query = text("""
        INSERT INTO users (username, email, password_hash, language_pref)
        VALUES (:username, :email, :password_hash, :language_pref)
    """)
    try:
        with engine.begin() as conn:
            result = conn.execute(query, {
                "username": username.strip(),
                "email": email.strip().lower(),
                "password_hash": password_hash,
                "language_pref": language_pref
            })
            return True, "User registered successfully."
    except SQLAlchemyError as e:
        err_msg = str(e).lower()
        if "unique constraint" in err_msg or "duplicate entry" in err_msg:
            if "email" in err_msg:
                return False, "Email address is already registered."
            return False, "Username is already taken."
        return False, f"Database error: {e}"

def get_user_by_username(username: str):
    """Retrieve user record by username using parameterized SQL."""
    engine, _ = get_engine()
    query = text("SELECT id, username, email, password_hash, language_pref, created_at FROM users WHERE username = :username LIMIT 1")
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {"username": username.strip()}).mappings().first()
            if row:
                return dict(row)
            return None
    except Exception as e:
        logger.error(f"Error fetching user by username: {e}")
        return None

def get_user_by_email(email: str):
    """Retrieve user record by email using parameterized SQL."""
    engine, _ = get_engine()
    query = text("SELECT id, username, email, password_hash, language_pref, created_at FROM users WHERE email = :email LIMIT 1")
    try:
        with engine.connect() as conn:
            row = conn.execute(query, {"email": email.strip().lower()}).mappings().first()
            if row:
                return dict(row)
            return None
    except Exception as e:
        logger.error(f"Error fetching user by email: {e}")
        return None

def update_user_language(user_id: int, language_pref: str):
    """Update language preference for a specific user."""
    engine, _ = get_engine()
    query = text("UPDATE users SET language_pref = :lang WHERE id = :uid")
    try:
        with engine.begin() as conn:
            conn.execute(query, {"lang": language_pref, "uid": user_id})
            return True
    except Exception as e:
        logger.error(f"Error updating user language preference: {e}")
        return False

def save_scan(user_id: int, tool_name: str, target_input: str, result_data: dict):
    """Save a completed security scan result in JSON format."""
    engine, _ = get_engine()
    query = text("""
        INSERT INTO scan_history (user_id, tool_name, target_input, result_json)
        VALUES (:user_id, :tool_name, :target_input, :result_json)
    """)
    try:
        with engine.begin() as conn:
            conn.execute(query, {
                "user_id": user_id,
                "tool_name": tool_name,
                "target_input": target_input,
                "result_json": json.dumps(result_data, default=str)
            })
            return True
    except Exception as e:
        logger.error(f"Error saving scan history: {e}")
        return False

def get_user_scans(user_id: int, limit: int = 50):
    """Fetch scan history records for a specific user."""
    engine, _ = get_engine()
    query = text("""
        SELECT id, tool_name, target_input, result_json, scanned_at 
        FROM scan_history 
        WHERE user_id = :user_id 
        ORDER BY scanned_at DESC 
        LIMIT :limit
    """)
    try:
        with engine.connect() as conn:
            rows = conn.execute(query, {"user_id": user_id, "limit": limit}).mappings().all()
            scans = []
            for row in rows:
                item = dict(row)
                try:
                    item["result_json"] = json.loads(item["result_json"])
                except Exception:
                    pass
                scans.append(item)
            return scans
    except Exception as e:
        logger.error(f"Error fetching scan history: {e}")
        return []

def get_dashboard_metrics():
    """Retrieve global SOC aggregated metrics across all operations."""
    engine, db_type = get_engine()
    query = text("""
        SELECT 
            COUNT(*) as total_scans,
            SUM(CASE WHEN tool_name = 'Vulnerability Scanner' THEN 1 ELSE 0 END) as vuln_scans,
            SUM(CASE WHEN tool_name = 'Password Checker' THEN 1 ELSE 0 END) as pwd_scans,
            SUM(CASE WHEN tool_name = 'Phishing Detector' THEN 1 ELSE 0 END) as phish_scans
        FROM scan_history
    """)
    try:
        with engine.connect() as conn:
            row = conn.execute(query).mappings().first()
            metrics = dict(row) if row else {}
            # Provide sensible non-zero SOC base values for visualization
            total = metrics.get("total_scans") or 0
            return {
                "total_scans": total,
                "vuln_scans": metrics.get("vuln_scans") or 0,
                "pwd_scans": metrics.get("pwd_scans") or 0,
                "phish_scans": metrics.get("phish_scans") or 0,
                "db_type": db_type
            }
    except Exception as e:
        logger.error(f"Error computing dashboard metrics: {e}")
        return {
            "total_scans": 0,
            "vuln_scans": 0,
            "pwd_scans": 0,
            "phish_scans": 0,
            "db_type": db_type
        }
