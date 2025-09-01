#!/usr/bin/env python3
"""
secureauth.py
- Env-based MySQL config
- bcrypt password hashing (salted)
- Minimal, safe logging
- Auto-create `users` table if missing
- CLI: create/update a user password

Env:
  MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
  BCRYPT_ROUNDS (default 12)
"""

import os
import logging
import traceback
import mysql.connector
from mysql.connector import pooling
import bcrypt

# ---------- Logging ----------
logger = logging.getLogger("secureauth")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(ch)

# ---------- Config ----------
MYSQL_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "admin"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "autocommit": True,
}
POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

_pool = None


def _pool_conn():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(pool_name="secureauth_pool", pool_size=POOL_SIZE, **MYSQL_CFG)
        _ensure_schema()
    return _pool.get_connection()


def _ensure_schema():
    sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(64) NOT NULL UNIQUE,
        password_hash VARCHAR(128) NOT NULL,
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    cn = _pool.get_connection()
    try:
        with cn.cursor() as cur:
            cur.execute(sql)
        cn.commit()
    finally:
        cn.close()


def hash_password(password: str) -> str:
    """bcrypt salted hash -> str"""
    pw = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(pw, salt).decode("utf-8")


def get_user(username: str):
    """Return (username, password_hash, is_active) or None"""
    try:
        cn = _pool_conn()
        with cn.cursor() as cur:
            cur.execute("SELECT username, password_hash, is_active FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
        cn.close()
        return row
    except Exception:
        logger.error("DB error in get_user\n%s", traceback.format_exc())
        return None


def verify_user(username: str, password: str) -> bool:
    row = get_user(username)
    if not row:
        return False
    _, pw_hash, is_active = row
    if not is_active:
        return False
    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8"))
        return bool(ok)
    except Exception:
        logger.error("bcrypt verify error\n%s", traceback.format_exc())
        return False


def create_or_update_user(username: str, password: str, active: bool = True) -> None:
    """Create or update user with new password hash."""
    pw_hash = hash_password(password)
    cn = _pool_conn()
    try:
        with cn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, password_hash, is_active)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                   password_hash=VALUES(password_hash),
                   is_active=VALUES(is_active)
                """,
                (username, pw_hash, 1 if active else 0),
            )
        cn.commit()
        logger.info("✅ user upserted: %s (active=%s)", username, active)
    finally:
        cn.close()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Manage WAF users")
    p.add_argument("--set-user", metavar="USERNAME")
    p.add_argument("--password", metavar="PASSWORD")
    p.add_argument("--activate", action="store_true")
    p.add_argument("--deactivate", action="store_true")
    args = p.parse_args()

    if args.set_user and args.password:
        create_or_update_user(
            args.set_user,
            args.password,
            active=not args.deactivate if (args.activate or args.deactivate) else True,
        )
    else:
        logger.info("Usage: python secureauth.py --set-user admin --password 'StrongPass123' --activate")
