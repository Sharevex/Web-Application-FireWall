
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ip_blocker_db.py
----------------
MySQL-backed IP blocker with TTL, optional OS enforcement.

Env:
  MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_POOL_SIZE
  BLOCK_TTL_SECONDS               (default 300)
  DB_APPLIES_OS                   (default 1)  -> if "1", apply OS rules here
"""

import os
import time
import platform
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import mysql.connector
from mysql.connector import pooling

MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "charset": "utf8mb4",
    "use_pure": True,
}
POOL_NAME = "ipblocker_pool"
POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))
DEFAULT_BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", "300"))
DB_APPLIES_OS = os.getenv("DB_APPLIES_OS", "1") == "1"

SYS = platform.system().lower()
IS_LINUX = "linux" in SYS
IS_WINDOWS = "windows" in SYS
IS_DARWIN = "darwin" in SYS

class MySQLIPBlocker:
    """
    Table schema (auto-created):
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            ip         VARCHAR(45) NOT NULL UNIQUE,
            reason     VARCHAR(255) NULL,
            blocked_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at DATETIME NOT NULL,
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    def __init__(self, mysql_cfg: dict = MYSQL_CONFIG, default_ttl_seconds: int = DEFAULT_BLOCK_TTL_SECONDS, sync_interval_sec: int = 30):
        self.cfg = dict(mysql_cfg)
        self.default_ttl = max(1, int(default_ttl_seconds))
        self.sync_interval = int(sync_interval_sec)
        self._stop = threading.Event()
        self._known_applied = set()

        self.pool = pooling.MySQLConnectionPool(pool_name=POOL_NAME, pool_size=POOL_SIZE, **self.cfg)
        self._ensure_schema()

    def _connect(self):
        return self.pool.get_connection()

    def _ensure_schema(self):
        sql = """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            ip         VARCHAR(45) NOT NULL UNIQUE,
            reason     VARCHAR(255) NULL,
            blocked_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at DATETIME NOT NULL,
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._connect() as cn, cn.cursor() as cur:
            cur.execute(sql)
            cn.commit()

    # ---------- Public API ----------
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: int | None = None):
        ttl = self.default_ttl if ttl_seconds is None else max(1, int(ttl_seconds))
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        upsert = """
        INSERT INTO blocked_ips (ip, reason, expires_at)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE reason=VALUES(reason), expires_at=VALUES(expires_at);
        """
        with self._connect() as cn, cn.cursor() as cur:
            cur.execute(upsert, (ip, reason, expires_at.replace(tzinfo=None)))
            cn.commit()

        if DB_APPLIES_OS:
            self._apply_os_block(ip, ttl)

    def unblock_ip(self, ip: str):
        with self._connect() as cn, cn.cursor() as cur:
            cur.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
            cn.commit()
        if DB_APPLIES_OS:
            self._remove_os_block(ip)

    def get_active_blocks(self) -> List[Tuple[str, str, datetime]]:
        sel = """
        SELECT ip, COALESCE(reason, ''), expires_at
          FROM blocked_ips
         WHERE expires_at > UTC_TIMESTAMP()
         ORDER BY expires_at ASC;
        """
        with self._connect() as cn, cn.cursor() as cur:
            cur.execute(sel)
            rows = cur.fetchall()
        return rows

    def sweep_expired(self):
        sel = "SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        delq = "DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        with self._connect() as cn, cn.cursor() as cur:
            cur.execute(sel)
            expired = [r[0] for r in cur.fetchall()]
            cur.execute(delq)
            cn.commit()
        if DB_APPLIES_OS:
            for ip in expired:
                self._remove_os_block(ip)

    # ---------- Background Sync ----------
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
                active_ips = {ip for (ip, _, _) in self.get_active_blocks()}
                for ip in list(self._known_applied - active_ips):
                    self._remove_os_block(ip)
            except Exception as e:
                print("[ip_blocker_db] sync error:", e)
            self._stop.wait(self.sync_interval)

    # ---------- OS firewall helpers ----------
    def _run(self, args: list[str] | str):
        try:
            if isinstance(args, str):
                return subprocess.run(args, shell=True, text=True, capture_output=True, timeout=5)
            return subprocess.run(args, text=True, capture_output=True, timeout=5)
        except Exception as e:
            print("[ip_blocker_db] OS cmd error:", e)
            return None

    def _apply_os_block(self, ip: str, ttl: int):
        if IS_LINUX:
            # Use iptables+ipset if available; else plain iptables
            if shutil.which("ipset"):
                self._run(["ipset", "create", "db_blocked", "hash:ip", "timeout", str(ttl), "-exist"])
                self._run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "db_blocked", "src", "-j", "DROP"])
                self._run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "db_blocked", "src", "-j", "DROP"])
                self._run(["ipset", "add", "db_blocked", ip, "timeout", str(ttl), "-exist"])
            else:
                # fallback
                self._run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
                self._run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        elif IS_WINDOWS:
            self._run(f'netsh advfirewall firewall add rule name="DBBlock {ip}" dir=in action=block remoteip={ip}')
        elif IS_DARWIN:
            self._run("pfctl -t db_blocked -T add " + ip)
        self._known_applied.add(ip)

    def _remove_os_block(self, ip: str):
        if IS_LINUX:
            if shutil.which("ipset"):
                self._run(["ipset", "del", "db_blocked", ip])
            else:
                self._run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        elif IS_WINDOWS:
            self._run(f'netsh advfirewall firewall delete rule name="DBBlock {ip}"')
        elif IS_DARWIN:
            self._run("pfctl -t db_blocked -T delete " + ip)
        self._known_applied.discard(ip)
