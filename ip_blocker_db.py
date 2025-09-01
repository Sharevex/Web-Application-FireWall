#!/usr/bin/env python3
"""
ip_blocker_db.py
- MySQL-backed IP blocklist with TTL + background sweeper
- Optional OS enforcer injection (preferred)
- Fallback to nftables/ipset if no enforcer provided
- Correct nftables 'add element {... timeout 300s }' syntax
- Pooled connections, UTC DATETIME, indexes

Env:
  MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
  MYSQL_POOL_SIZE (default 5)
  BLOCK_TTL_SECONDS (default 300)
"""

import os
import time
import logging
import platform
import subprocess
import shutil
import threading
from datetime import datetime, timedelta, timezone
import mysql.connector
from mysql.connector import pooling

# ---------- Logging ----------
logger = logging.getLogger("ip_blocker_db")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(ch)

# ---------- Config ----------
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "admin"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "charset": "utf8mb4",
    "use_pure": True,
}
POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))
DEFAULT_BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", "300"))


def _os_name():
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    if "darwin" in s:
        return "darwin"
    return "linux"


class MySQLIPBlocker:
    """
    Table schema (auto-created):

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL UNIQUE,
            reason VARCHAR(255) NULL,
            blocked_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at DATETIME NOT NULL,
            INDEX idx_expires_at (expires_at),
            INDEX idx_ip (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

    Public API:
      - block_ip(ip, reason="", ttl_seconds=None)
      - unblock_ip(ip)
      - get_active_blocks() -> [(ip, reason, expires_at), ...]
      - start_background_sync()
      - stop_background_sync()
    """

    def __init__(self, mysql_cfg: dict = MYSQL_CONFIG, default_ttl_seconds: int = DEFAULT_BLOCK_TTL_SECONDS,
                 sync_interval_sec: int = 30, os_enforcer=None):
        self.cfg = dict(mysql_cfg)
        self.default_ttl = max(1, int(default_ttl_seconds))
        self.sync_interval = int(sync_interval_sec)
        self._stop = threading.Event()
        self._known_applied = set()
        self._enforcer = os_enforcer

        self.pool = pooling.MySQLConnectionPool(pool_name="ipblocker_pool", pool_size=POOL_SIZE, **self.cfg)
        self._ensure_schema()

        # Fallback OS method detection (if no external enforcer)
        self._fallback = self._detect_fallback_method()

    # ---------- DB ----------
    def _connect(self):
        return self.pool.get_connection()

    def _ensure_schema(self):
        sql = """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL UNIQUE,
            reason VARCHAR(255) NULL,
            blocked_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at DATETIME NOT NULL,
            INDEX idx_expires_at (expires_at),
            INDEX idx_ip (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        cn = self._connect()
        try:
            with cn.cursor() as cur:
                cur.execute(sql)
            cn.commit()
        finally:
            cn.close()

    # ---------- Public API ----------
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: int | None = None):
        ttl = self.default_ttl if ttl_seconds is None else max(1, int(ttl_seconds))
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        upsert = """
        INSERT INTO blocked_ips (ip, reason, expires_at)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
          reason=VALUES(reason),
          expires_at=VALUES(expires_at)
        """
        cn = self._connect()
        try:
            with cn.cursor() as cur:
                cur.execute(upsert, (ip, reason, expires_at.replace(tzinfo=None)))
            cn.commit()
        finally:
            cn.close()

        self._apply_os_block(ip, ttl)

    def unblock_ip(self, ip: str):
        cn = self._connect()
        try:
            with cn.cursor() as cur:
                cur.execute("DELETE FROM blocked_ips WHERE ip=%s", (ip,))
            cn.commit()
        finally:
            cn.close()
        self._remove_os_block(ip)

    def get_active_blocks(self):
        sel = """
        SELECT ip, COALESCE(reason,''), expires_at
          FROM blocked_ips
         WHERE expires_at > UTC_TIMESTAMP()
         ORDER BY expires_at DESC;
        """
        cn = self._connect()
        try:
            with cn.cursor() as cur:
                cur.execute(sel)
                rows = cur.fetchall()
        finally:
            cn.close()
        return rows

    def sweep_expired(self):
        sel = "SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP()"
        delq = "DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP()"
        cn = self._connect()
        try:
            with cn.cursor() as cur:
                cur.execute(sel)
                expired = [r[0] for r in cur.fetchall()]
                cur.execute(delq)
            cn.commit()
        finally:
            cn.close()
        for ip in expired:
            self._remove_os_block(ip)

    # ---------- Background ----------
    def start_background_sync(self):
        t = threading.Thread(target=self._sync_loop, daemon=True)
        t.start()
        return t

    def stop_background_sync(self):
        self._stop.set()

    def _sync_loop(self):
        while not self._stop.is_set():
            try:
                self.sweep_expired()
                active = {ip for (ip, _, _) in self.get_active_blocks()}
                for ip in active:
                    if ip not in self._known_applied:
                        self._apply_os_block(ip, self.default_ttl)
                for ip in list(self._known_applied - active):
                    self._remove_os_block(ip)
            except Exception as e:
                logger.error("sync error: %s", e)
            self._stop.wait(self.sync_interval)

    # ---------- OS Apply / Remove ----------
    def _apply_os_block(self, ip: str, ttl: int):
        # Prefer external enforcer
        if self._enforcer:
            if self._enforcer.block_ip(ip, ttl):
                self._known_applied.add(ip)
                return
            else:
                logger.warning("external enforcer failed, falling back")

        # Fallback: nftables > ipset+iptables > plain iptables
        method = self._fallback
        try:
            if method == "nft":
                # ensure table/set exist
                self._nft_setup()
                # add with timeout — need shell to keep braces
                cmd = f"nft add element inet firewall blocked_ips '{{ {ip} timeout {int(ttl)}s }}'"
                subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                self._known_applied.add(ip)
            elif method == "ipset":
                subprocess.run(
                    ["ipset", "add", "firewall_blocked", ip, "timeout", str(int(ttl)), "-exist"],
                    capture_output=True, text=True, timeout=5
                )
                # make sure iptables rule exists (drop match-set)
                self._iptables_ensure_rule()
                self._known_applied.add(ip)
            elif method == "iptables":
                subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True, text=True, timeout=5)
                # if not present, add
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True, text=True, timeout=5)
                self._known_applied.add(ip)
        except Exception as e:
            logger.error("fallback OS block failed for %s: %s", ip, e)

    def _remove_os_block(self, ip: str):
        if self._enforcer:
            self._enforcer.unblock_ip(ip)
            self._known_applied.discard(ip)
            return

        method = self._fallback
        try:
            if method == "nft":
                cmd = f"nft delete element inet firewall blocked_ips '{{ {ip} }}'"
                subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            elif method == "ipset":
                subprocess.run(["ipset", "del", "firewall_blocked", ip],
                               capture_output=True, text=True, timeout=5)
            elif method == "iptables":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True, text=True, timeout=5)
        except Exception as e:
            logger.warning("fallback OS unblock error for %s: %s", ip, e)
        finally:
            self._known_applied.discard(ip)

    # ---------- Fallback detection & setup ----------
    def _detect_fallback_method(self) -> str:
        if shutil.which("nft"):
            return "nft"
        if shutil.which("ipset") and shutil.which("iptables"):
            return "ipset"
        if shutil.which("iptables"):
            return "iptables"
        return "none"

    def _nft_setup(self):
        # Create table/set/chain (idempotent). ignore "already exists".
        cmds = [
            "nft add table inet firewall",
            "nft add set inet firewall blocked_ips '{ type ipv4_addr; flags timeout; }'",
            "nft add chain inet firewall input '{ type filter hook input priority 0; policy accept; }'",
            "nft insert rule inet firewall input ip saddr @blocked_ips drop",
        ]
        for cmd in cmds:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if r.returncode != 0 and "already exists" not in (r.stderr or "").lower():
                logger.debug("nft setup warn: %s => %s", cmd, r.stderr)

    def _iptables_ensure_rule(self):
        # Ensure ipset exists & iptables rule installed
        subprocess.run(["ipset", "create", "firewall_blocked", "hash:ip", "timeout", str(self.default_ttl), "-exist"],
                       capture_output=True, text=True, timeout=5)
        chk = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "firewall_blocked", "src", "-j", "DROP"],
                             capture_output=True, text=True, timeout=5)
        if chk.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "firewall_blocked", "src", "-j", "DROP"],
                           capture_output=True, text=True, timeout=5)
