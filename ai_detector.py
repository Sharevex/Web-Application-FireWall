#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
mysql_db.py
-----------
Lightweight MySQL helper with connection pooling and safe, simple helpers.

Env (from your .env):
  MYSQL_HOST=127.0.0.1
  MYSQL_PORT=3306
  MYSQL_USER=admin
  MYSQL_PASSWORD='At@1381928'
  MYSQL_DB=admin
  MYSQL_POOL_SIZE=8
"""

import os
import logging
from contextlib import contextmanager
import mysql.connector
from mysql.connector import pooling, Error

logger = logging.getLogger("mysql_db")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(_h)

MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DB", "test"),
    "autocommit": True,
    "charset": "utf8mb4",
    "use_pure": True,
}

POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))

# Create a global pool once
_pool = pooling.MySQLConnectionPool(
    pool_name="app_pool",
    pool_size=POOL_SIZE,
    **MYSQL_CONFIG
)


def _get_conn():
    """Get a pooled connection and ensure it's alive."""
    conn = _pool.get_connection()
    try:
        conn.ping(reconnect=True, attempts=2, delay=0.2)
    except Error as e:
        logger.warning("MySQL ping failed, reconnecting: %s", e)
        conn.reconnect(attempts=2, delay=0.2)
    return conn


@contextmanager
def get_cursor(dictionary=True):
    """
    Usage:
        with get_cursor() as cur:
            cur.execute("SELECT 1")
            print(cur.fetchall())
    """
    conn = _get_conn()
    cur = conn.cursor(dictionary=dictionary)
    try:
        yield cur
    finally:
        try:
            cur.close()
        finally:
            conn.close()


def query_all(sql: str, params=None, dictionary=True):
    with get_cursor(dictionary=dictionary) as cur:
        cur.execute(sql, params or ())
        return cur.fetchall()


def query_one(sql: str, params=None, dictionary=True):
    with get_cursor(dictionary=dictionary) as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()


def execute(sql: str, params=None) -> int:
    """Execute DML/DDL, return affected rows."""
    with get_cursor(dictionary=True) as cur:
        cur.execute(sql, params or ())
        return cur.rowcount


def executemany(sql: str, seq_params) -> int:
    """Bulk execute, return total affected rows."""
    with get_cursor(dictionary=True) as cur:
        cur.executemany(sql, seq_params)
        return cur.rowcount


@contextmanager
def transaction():
    """
    Transaction context manager (manual commit/rollback).
    Usage:
        with transaction() as cur:
            cur.execute("UPDATE ...")
            cur.execute("INSERT ...")
    """
    conn = _get_conn()
    conn.autocommit = False
    cur = conn.cursor(dictionary=True)
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            cur.close()
        finally:
            conn.autocommit = True
            conn.close()


# Optional: quick schema helpers (call once if you want)
CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(191) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_BLOCKED_IPS_SQL = """
CREATE TABLE IF NOT EXISTS blocked_ips (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(64) NOT NULL,
  reason VARCHAR(255) NULL,
  expires_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_ip (ip),
  KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

def ensure_base_schema():
    execute(CREATE_USERS_SQL)
    execute(CREATE_BLOCKED_IPS_SQL)
    logger.info("Verified base tables: users, blocked_ips")
