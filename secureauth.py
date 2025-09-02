# secureauth.py — MySQL edition
# Uses the shared MySQL pool + auto-schema from mysql_db.py

import hashlib
import base64
import traceback
import re
from datetime import datetime

from mysql_db import init_mysql, get_conn, upsert_user  # ensures DB + tables

# Initialize MySQL pool and ensure schema (users table, etc.)
init_mysql()

# ---------- Helpers ----------
def hash_password(password: str) -> str:
    """SHA-256 (binary) → base64, same format as your previous implementation."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("utf-8")

def _valid_username(u: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u or ""))

# ---------- Core API ----------
def get_user(username: str):
    """Return tuple (username, password_hash, is_active, created_at) or None."""
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT username, password_hash, is_active, created_at FROM users WHERE username=%s",
                (username,),
            )
            row = cur.fetchone()
            return row if row else None
    except Exception:
        print("DB error in get_user:\n", traceback.format_exc())
        return None

def verify_user(username: str, password: str) -> bool:
    """Check username/password; requires is_active=1."""
    try:
        user = get_user(username)
        if not user:
            return False
        stored_hash = user[1]
        is_active   = int(user[2]) == 1
        if not is_active:
            return False
        return hash_password(password) == stored_hash
    except Exception:
        print("verify_user error:\n", traceback.format_exc())
        return False

def user_exists(username: str) -> bool:
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
            return cur.fetchone() is not None
    except Exception:
        print("DB error in user_exists:\n", traceback.format_exc())
        return False

def create_admin(username: str, password: str) -> bool:
    """
    Creates or updates an admin user (is_admin=1). Activates the user.
    Returns True on success.
    """
    try:
        if not _valid_username(username) or not password:
            return False
        pwd = hash_password(password)
        # Use upsert helper (unique on username) — sets/updates hash + flags
        upsert_user(username, pwd, is_admin=1, is_active=1)
        return True
    except Exception:
        print("DB error in create_admin:\n", traceback.format_exc())
        return False

def delete_admin(username: str) -> bool:
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE username=%s", (username,))
            return getattr(cur, "rowcount", 0) > 0
    except Exception:
        print("DB error in delete_admin:\n", traceback.format_exc())
        return False

def list_admins():
    """
    Returns list of dicts: [{"username": "...", "created_at": "..."}, ...]
    If your table has is_admin, we filter by it; otherwise returns any users present.
    """
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            # If column is present (it is, in mysql_db.py), filter admins only.
            try:
                cur.execute("SELECT username, created_at FROM users WHERE is_admin=1 ORDER BY created_at ASC")
            except Exception:
                cur.execute("SELECT username, created_at FROM users ORDER BY created_at ASC")
            rows = cur.fetchall() or []
        out = []
        for username, created_at in rows:
            try:
                created_iso = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)
            except Exception:
                created_iso = str(created_at)
            out.append({"username": username, "created_at": created_iso})
        return out
    except Exception:
        print("DB error in list_admins:\n", traceback.format_exc())
        return []

# ---------- Password helpers for route compatibility ----------
def set_password(username: str, new_password: str) -> bool:
    """Set password for an existing user; keeps is_admin/is_active unchanged."""
    try:
        if not _valid_username(username) or not new_password:
            return False
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET password_hash=%s WHERE username=%s",
                (hash_password(new_password), username),
            )
            if getattr(cur, "rowcount", 0) == 0:
                # if user doesn't exist, create as active admin by convention
                upsert_user(username, hash_password(new_password), is_admin=1, is_active=1)
        return True
    except Exception:
        print("DB error in set_password:\n", traceback.format_exc())
        return False

def reset_password(username: str, new_password: str) -> bool:
    return set_password(username, new_password)

def update_admin_password(username: str, new_password: str) -> bool:
    return set_password(username, new_password)
