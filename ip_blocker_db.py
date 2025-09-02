#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ip_blocker_db.py  — MySQL edition
- Persists blocked IPs in MySQL with TTL (auto-expire)
- Auto-creates DATABASE and TABLE if they don't exist
- Periodically syncs with OS firewall (nftables preferred; falls back to ipset/iptables, Windows netsh, or pfctl)
- API: block_ip(), unblock_ip(), get_active_blocks(), sweep_expired(),
       start_background_sync(), stop_background_sync(), is_blocked()

ENV (typical):
  MYSQL_HOST=127.0.0.1
  MYSQL_PORT=3306
  MYSQL_USER=admin
  MYSQL_PASSWORD=At@1381928
  MYSQL_DB=admin
  MYSQL_POOL_SIZE=8
  BLOCK_TTL_SECONDS=300
  BLOCK_SWEEP_SECONDS=30
  FW_OS_MODE=auto   # auto | nft | ipset | off
"""

import os
import time
import shutil
import subprocess
import threading
import logging
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from ipaddress import ip_address

import mysql.connector
from mysql.connector import pooling, errorcode

# ---------- Logging ----------
logger = logging.getLogger("ip_blocker_db")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(h)

# ---------- ENV / Config ----------
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "waf")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DB = os.getenv("MYSQL_DB", "wafdb")
MYSQL_POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "8"))

DEFAULT_TTL = int(os.getenv("BLOCK_TTL_SECONDS", "300"))     # seconds
SWEEP_EVERY = int(os.getenv("BLOCK_SWEEP_SECONDS", "30"))    # seconds
OS_MODE = os.getenv("FW_OS_MODE", "auto")                    # auto | nft | ipset | off

_pool: pooling.MySQLConnectionPool | None = None

# ---------- DDL ----------
DDL_DB = f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
DDL_BLOCKED_IPS = """
CREATE TABLE IF NOT EXISTS blocked_ips (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(45) NOT NULL UNIQUE,
  reason VARCHAR(255) NULL,
  blocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# ---------- MySQL Helpers ----------
def _connect_without_db():
    return mysql.connector.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER, password=MYSQL_PASSWORD
    )

def _ensure_database():
    try:
        mysql.connector.connect(
            host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER,
            password=MYSQL_PASSWORD, database=MYSQL_DB
        ).close()
    except mysql.connector.Error as e:
        if e.errno == errorcode.ER_BAD_DB_ERROR:
            conn = _connect_without_db()
            cur = conn.cursor()
            cur.execute(DDL_DB)
            conn.commit()
            cur.close(); conn.close()
            logger.info("Created database %s", MYSQL_DB)
        else:
            raise

def _ensure_schema():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(DDL_BLOCKED_IPS)
        conn.commit()

def init_mysql_pool():
    global _pool
    if _pool is not None:
        return
    _ensure_database()
    _pool = pooling.MySQLConnectionPool(
        pool_name="ipblocker_pool",
        pool_size=MYSQL_POOL_SIZE,
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        autocommit=False,
    )
    _ensure_schema()
    logger.info("MySQL pool ready; schema ensured.")

@contextmanager
def get_conn():
    if _pool is None:
        init_mysql_pool()
    conn = _pool.get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ---------- OS Enforcement ----------
class OSEnforcer:
    def __init__(self, mode: str = "auto"):
        self.mode = self._detect_mode(mode)
        self._ensure_setup()

    def _detect_mode(self, mode: str) -> str:
        if mode in ("nft", "ipset", "off"):
            return mode
        if shutil.which("nft"):
            return "nft"
        if shutil.which("ipset") and shutil.which("iptables"):
            return "ipset"
        # last resort: plain iptables if available
        if shutil.which("iptables"):
            return "ipset"  # we'll use iptables checks/adds without ipset
        return "off"

    def _run(self, *args):
        try:
            return subprocess.run(args, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            logger.debug("Cmd failed: %s\nstdout=%s\nstderr=%s", " ".join(args), e.stdout, e.stderr)
            return None

    def _ensure_setup(self):
        if self.mode == "nft":
            # idempotent-ish: these 'add' calls fail if they exist; ignore errors
            self._run("nft", "add", "table", "inet", "filter")
            self._run("nft", "add", "set", "inet", "filter", "fw_blocked",
                      "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}")
            self._run("nft", "add", "set", "inet", "filter", "fw6_blocked",
                      "{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}")
            self._run("nft", "add", "chain", "inet", "filter", "input",
                      "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}")
            self._run("nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", "@fw_blocked", "drop")
            self._run("nft", "add", "rule", "inet", "filter", "input", "ip6", "saddr", "@fw6_blocked", "drop")
        elif self.mode == "ipset":
            # create if not exists; ignore failures
            subprocess.run(["ipset", "create", "fw_blocked", "hash:ip", "timeout", "0"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # ensure jump rules exist (best effort)
            subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if shutil.which("ip6tables"):
                subprocess.run(["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["ip6tables", "-I", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def add(self, ip: str, ttl: int):
        try:
            addr = ip_address(ip)
        except ValueError:
            logger.warning("Invalid IP for OS enforce: %s", ip)
            return
        if self.mode == "nft":
            if addr.version == 4:
                self._run("nft", "add", "element", "inet", "filter", "fw_blocked",
                          "{", ip, "timeout", f"{ttl}s", "}")
            else:
                self._run("nft", "add", "element", "inet", "filter", "fw6_blocked",
                          "{", ip, "timeout", f"{ttl}s", "}")
        elif self.mode == "ipset":
            if shutil.which("ipset"):
                subprocess.run(["ipset", "add", "fw_blocked", ip, "timeout", str(ttl)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # plain iptables fallback: check then insert
                subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            pass  # OS enforcement off

    def remove(self, ip: str):
        try:
            addr = ip_address(ip)
        except ValueError:
            return
        if self.mode == "nft":
            if addr.version == 4:
                self._run("nft", "delete", "element", "inet", "filter", "fw_blocked", "{", ip, "}")
            else:
                self._run("nft", "delete", "element", "inet", "filter", "fw6_blocked", "{", ip, "}")
        elif self.mode == "ipset":
            if shutil.which("ipset"):
                subprocess.run(["ipset", "del", "fw_blocked", ip],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            pass

# ---------- Blocker ----------
class MySQLIPBlocker:
    def __init__(self, default_ttl_seconds: int = DEFAULT_TTL, sync_interval_sec: int = SWEEP_EVERY):
        init_mysql_pool()
        self.default_ttl = int(default_ttl_seconds)
        self._stop = threading.Event()
        self._interval = int(sync_interval_sec)
        self.enforcer = OSEnforcer(OS_MODE)
        self._thread: threading.Thread | None = None

    # DB ops
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: int | None = None):
        ttl = int(ttl_seconds) if ttl_seconds else self.default_ttl
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO blocked_ips (ip, reason, expires_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  reason=VALUES(reason),
                  expires_at=VALUES(expires_at)
            """, (ip, (reason or "")[:255], expires_at.replace(tzinfo=None)))
        self.enforcer.add(ip, ttl)

    def unblock_ip(self, ip: str):
        with get_conn() as conn:
            conn.cursor().execute("DELETE FROM blocked_ips WHERE ip=%s", (ip,))
        self.enforcer.remove(ip)

    def is_blocked(self, ip: str) -> bool:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT expires_at FROM blocked_ips WHERE ip=%s", (ip,))
            row = cur.fetchone()
        if not row:
            return False
        expires_at = row[0]
        return expires_at is None or datetime.utcnow() <= expires_at

    def get_active_blocks(self):
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT ip, COALESCE(reason,''), expires_at
                FROM blocked_ips
                WHERE expires_at > UTC_TIMESTAMP()
                ORDER BY expires_at ASC
            """)
            rows = cur.fetchall() or []
        return [(r[0], r[1], r[2]) for r in rows]

    def sweep_expired(self):
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP()")
            expired = [r[0] for r in cur.fetchall() or []]
            cur.execute("DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP()")
        for ip in expired:
            self.enforcer.remove(ip)

    # Background sync
    def start_background_sync(self):
        if self._thread and self._thread.is_alive():
            return self._thread
        self._thread = threading.Thread(target=self._sync_loop, name="mysql_blocker_sweeper", daemon=True)
        self._thread.start()
        return self._thread

    def stop_background_sync(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _sync_loop(self):
        while not self._stop.is_set():
            try:
                self.sweep_expired()
                # ensure all active entries are present at OS level (best effort)
                for ip, _, _ in self.get_active_blocks():
                    self.enforcer.add(ip, ttl=60)  # re-affirm short TTL; nft/ipset will refresh timers
            except Exception as e:
                logger.debug("Sync loop error: %s", e)
            self._stop.wait(self._interval)

# Backward-compat alias (so old imports won't break)
MSSQLIPBlocker = MySQLIPBlocker
