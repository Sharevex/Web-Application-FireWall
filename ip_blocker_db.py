#!/usr/bin/env python3
"""
ip_blocker_db_mysql.py
- Persist blocked IPs in **MySQL** with TTL (auto-expire)
- Periodically sync with OS firewall (Linux/Windows/macOS)
- Public API: block_ip(), unblock_ip(), get_active_blocks(), start_background_sync()

Requires:
    pip install mysql-connector-python
"""

import os
import time
import threading
from datetime import datetime, timedelta, timezone

import mysql.connector
from mysql.connector import pooling

# =========================
#   CONFIG (edit or set env)
# =========================
MYSQL_CONFIG = {
    "host":     os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port":     int(os.getenv("MYSQL_PORT", "3306")),
    "user":     os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "charset":  "utf8mb4",
    "use_pure": True,
}
POOL_NAME = "ipblocker_pool"
POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))

# ----- OS detection -----
import platform
def _detect_os():
    sysname = platform.system().lower()
    if "windows" in sysname:
        return "windows"
    if "darwin" in sysname:
        return "darwin"
    return "linux"

CURRENT_OS = _detect_os()


class MySQLIPBlocker:
    """
    MySQL-backed IP blocker with OS firewall enforcement.

    Schema (auto-created on first use):

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            ip          VARCHAR(45)  NOT NULL UNIQUE,
            reason      VARCHAR(255) NULL,
            blocked_at  DATETIME      NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at  DATETIME      NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    def __init__(self, mysql_cfg: dict = MYSQL_CONFIG, default_ttl_seconds: int = 3600, sync_interval_sec: int = 30):
        self.cfg = dict(mysql_cfg)
        self.default_ttl = default_ttl_seconds
        self.sync_interval = sync_interval_sec
        self._stop = threading.Event()
        self._known_applied = set()

        # Connection pool
        self.pool = pooling.MySQLConnectionPool(pool_name=POOL_NAME, pool_size=POOL_SIZE, **self.cfg)

        self._ensure_schema()

    # ---------- DB Helpers ----------
    def _connect(self):
        return self.pool.get_connection()

    def _ensure_schema(self):
        create_sql = """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            ip          VARCHAR(45)  NOT NULL UNIQUE,
            reason      VARCHAR(255) NULL,
            blocked_at  DATETIME      NOT NULL DEFAULT (UTC_TIMESTAMP()),
            expires_at  DATETIME      NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(create_sql)
            cn.commit()

    # ---------- Public API ----------
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: int | None = None):
        """Insert or update an IP block with a TTL (from now)."""
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        # Use MySQL upsert
        sql = """
        INSERT INTO blocked_ips (ip, reason, expires_at)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            reason = VALUES(reason),
            expires_at = VALUES(expires_at);
        """
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(sql, (ip, reason, expires_at.replace(tzinfo=None)))
            cn.commit()

        self._apply_os_block(ip)

    def unblock_ip(self, ip: str):
        """Remove an IP from DB and OS firewall."""
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute("DELETE FROM blocked_ips WHERE ip = %s;", (ip,))
            cn.commit()
        self._remove_os_block(ip)

    def get_active_blocks(self):
        """Return list of (ip, reason, expires_at) that are not expired (UTC)."""
        sql = """
        SELECT ip, COALESCE(reason, ''), expires_at
          FROM blocked_ips
         WHERE expires_at > UTC_TIMESTAMP()
         ORDER BY expires_at ASC;
        """
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall()
        # rows: List[Tuple[str, str, datetime]]
        return rows

    def sweep_expired(self):
        """Delete expired rows and clean OS firewall for them."""
        sel = "SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        delq = "DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(sel)
                expired = [r[0] for r in cur.fetchall()]
                cur.execute(delq)
            cn.commit()
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
                # 1) purge expired
                self.sweep_expired()

                # 2) ensure active entries are applied to OS
                active = self.get_active_blocks()
                active_ips = {ip for (ip, _, _) in active}
                for ip in active_ips:
                    if ip not in self._known_applied:
                        self._apply_os_block(ip)

                # 3) remove OS rules we applied that are no longer active
                for ip in list(self._known_applied - active_ips):
                    self._remove_os_block(ip)

            except Exception as e:
                print("[ip_blocker_db_mysql] Sync error:", e)

            self._stop.wait(self.sync_interval)

    # ---------- OS Firewall ----------
    def _apply_os_block(self, ip: str):
        if CURRENT_OS == "linux":
            cmd = f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null || sudo iptables -A INPUT -s {ip} -j DROP"
        elif CURRENT_OS == "windows":
            cmd = f'netsh advfirewall firewall add rule name="DBBlock {ip}" dir=in action=block remoteip={ip}'
        elif CURRENT_OS == "darwin":
            cmd = f"echo 'block drop from {ip} to any' | sudo pfctl -ef -"
        else:
            print(f"[ip_blocker_db_mysql] Unsupported OS for apply: {CURRENT_OS}")
            return
        os.system(cmd)
        self._known_applied.add(ip)

    def _remove_os_block(self, ip: str):
        if CURRENT_OS == "linux":
            cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        elif CURRENT_OS == "windows":
            cmd = f'netsh advfirewall firewall delete rule name="DBBlock {ip}"'
        elif CURRENT_OS == "darwin":
            cmd = "sudo pfctl -F rules -f /etc/pf.conf"
        else:
            print(f"[ip_blocker_db_mysql] Unsupported OS for remove: {CURRENT_OS}")
            return
        os.system(cmd)
        self._known_applied.discard(ip)
