# secureauth.py
import os
import hashlib
import base64
import traceback
from datetime import datetime

import mysql.connector
from mysql.connector import pooling

# ---------- Connection (MySQL) ----------
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "admin"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DB", "admin"),
    "autocommit": True,
}
_POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "8"))
_pool = pooling.MySQLConnectionPool(pool_name="secureauth_pool", pool_size=_POOL_SIZE, **MYSQL_CONFIG)

def _conn():
    return _pool.get_connection()

# ---------- Helpers ----------
def _ensure_schema():
    """Create users table if it doesn't exist (idempotent)."""
    try:
        cn = _conn()
        cur = cn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username      VARCHAR(191) NOT NULL PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                is_active     TINYINT(1) NOT NULL DEFAULT 1,
                created_at    DATETIME NOT NULL DEFAULT UTC_TIMESTAMP()
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        cur.close(); cn.close()
    except Exception:
        print("DB error in _ensure_schema:\n", traceback.format_exc())

def hash_password(password: str) -> str:
    digest = hashlib.sha256(password.encode('utf-8')).digest()
    return base64.b64encode(digest).decode('utf-8')

# ---------- Core API ----------
def get_user(username: str):
    try:
        _ensure_schema()
        cn = _conn()
        cur = cn.cursor()
        cur.execute(
            "SELECT username, password_hash, is_active, created_at FROM users WHERE username = %s",
            (username,)
        )
        row = cur.fetchone()
        cur.close(); cn.close()
        return row if row else None
    except Exception:
        print("DB error in get_user:\n", traceback.format_exc())
        return None

def verify_user(username: str, password: str) -> bool:
    user = get_user(username)
    if not user:
        return False
    stored_hash = user[1]
    is_active   = bool(user[2])
    if not is_active:
        return False
    return hash_password(password) == stored_hash

def user_exists(username: str) -> bool:
    try:
        _ensure_schema()
        cn = _conn()
        cur = cn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        exists = cur.fetchone() is not None
        cur.close(); cn.close()
        return exists
    except Exception:
        print("DB error in user_exists:\n", traceback.format_exc())
        return False

def create_admin(username: str, password: str) -> bool:
    """
    Creates or updates an admin user.
    Returns True on success, False on failure.
    """
    try:
        if not username or not password:
            return False

        import re
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            return False

        _ensure_schema()
        cn = _conn()
        cur = cn.cursor()
        pwd = hash_password(password)

        # UPSERT behavior: update if exists, else insert (preserves original logic)
        cur.execute(
            "UPDATE users SET password_hash=%s, is_active=1 WHERE username=%s",
            (pwd, username)
        )
        if getattr(cur, "rowcount", 0) == 0:
            cur.execute(
                "INSERT INTO users (username, password_hash, is_active, created_at) VALUES (%s, %s, 1, %s)",
                (username, pwd, datetime.utcnow())
            )
        cur.close(); cn.close()
        return True
    except Exception:
        print("DB error in create_admin:\n", traceback.format_exc())
        return False

def delete_admin(username: str) -> bool:
    try:
        _ensure_schema()
        cn = _conn()
        cur = cn.cursor()
        cur.execute("DELETE FROM users WHERE username = %s", (username,))
        ok = getattr(cur, "rowcount", 0) > 0
        cur.close(); cn.close()
        return ok
    except Exception:
        print("DB error in delete_admin:\n", traceback.format_exc())
        return False

def list_admins():
    """
    Returns list of dicts: [{"username": ..., "created_at": ...}, ...]
    """
    try:
        _ensure_schema()
        cn = _conn()
        cur = cn.cursor()
        cur.execute("SELECT username, created_at FROM users ORDER BY created_at ASC")
        rows = cur.fetchall()
        cur.close(); cn.close()
        out = []
        for r in rows or []:
            username = r[0]
            created_at = r[1]
            try:
                created_iso = created_at.isoformat()
            except Exception:
                created_iso = str(created_at)
            out.append({"username": username, "created_at": created_iso})
        return out
    except Exception:
        print("DB error in list_admins:\n", traceback.format_exc())
        return []
