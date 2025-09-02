#!/usr/bin/env python3
"""
ip_blocker_db.py
- Persist blocked IPs in **MySQL** with TTL (auto-expire)
- Periodically sync with OS firewall (Windows/Linux/macOS)
- Simple API: block_ip(), unblock_ip(), get_active_blocks(), start_background_sync()

Requires: mysql-connector-python
    pip install mysql-connector-python
"""

import os
import time
import threading
from datetime import datetime, timedelta
import platform
import mysql.connector
from mysql.connector import pooling

# ====== MySQL connection config (uses env if set) ======
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "admin"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DB", "admin"),
    "autocommit": True,
}
_POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "8"))
_pool = pooling.MySQLConnectionPool(pool_name="ipblocker_pool", pool_size=_POOL_SIZE, **MYSQL_CONFIG)

def _detect_os():
    sysname = platform.system().lower()
    if "windows" in sysname:
        return "windows"
    if "darwin" in sysname:
        return "darwin"
    return "linux"

CURRENT_OS = _detect_os()

class MSSQLIPBlocker:
    """
    NOTE: Name kept for compatibility with existing imports.
    Backend is **MySQL**.
    """
    def __init__(self, default_ttl_seconds=120, sync_interval_sec=30):
        self.default_ttl = default_ttl_seconds
        self.sync_interval = sync_interval_sec
        self._stop = threading.Event()
        self._known_applied = set()
        self._ensure_schema()

    # ---------- DB Helpers ----------
    def _connect(self):
        cn = _pool.get_connection()
        # Force UTC so CURRENT_TIMESTAMP/UTC_TIMESTAMP align with UTC calculations
        try:
            cur = cn.cursor()
            cur.execute("SET time_zone = '+00:00'")
            cur.close()
        except Exception:
            pass
        return cn

    def _ensure_schema(self):
        # Use TIMESTAMP with CURRENT_TIMESTAMP default (portable).
        create_sql = """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            ip          VARCHAR(45) NOT NULL UNIQUE,
            reason      VARCHAR(255) NULL,
            blocked_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at  TIMESTAMP NOT NULL,
            INDEX idx_expires_at (expires_at),
            INDEX idx_ip (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        cn = self._connect()
        try:
            cur = cn.cursor()
            cur.execute(create_sql)
        finally:
            cur.close(); cn.close()

    # ---------- Public API ----------
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: int = None):
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

        upsert_sql = """
        INSERT INTO blocked_ips (ip, reason, expires_at)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            reason = VALUES(reason),
            expires_at = VALUES(expires_at);
        """
        cn = self._connect()
        try:
            cur = cn.cursor()
            cur.execute(upsert_sql, (ip, reason, expires_at))
        finally:
            cur.close(); cn.close()

        self._apply_os_block(ip)

    def unblock_ip(self, ip: str):
        cn = self._connect()
        try:
            cur = cn.cursor()
            cur.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
        finally:
            cur.close(); cn.close()
        self._remove_os_block(ip)

    def get_active_blocks(self):
        sql = """
        SELECT ip, IFNULL(reason, ''), expires_at
        FROM blocked_ips
        WHERE expires_at > UTC_TIMESTAMP()
        ORDER BY expires_at ASC;
        """
        cn = self._connect()
        try:
            cur = cn.cursor()
            cur.execute(sql)
            rows = cur.fetchall()
            return [(r[0], r[1], r[2]) for r in rows]
        finally:
            cur.close(); cn.close()

    def sweep_expired(self):
        sel = "SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        delq = "DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        cn = self._connect()
        try:
            cur = cn.cursor()
            cur.execute(sel)
            expired = [r[0] for r in cur.fetchall()]
            cur.execute(delq)
        finally:
            cur.close(); cn.close()

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
                active = self.get_active_blocks()
                active_ips = set(ip for ip, _, _ in active)
                for ip in active_ips:
                    if ip not in self._known_applied:
                        self._apply_os_block(ip)
                to_remove = self._known_applied - active_ips
                for ip in list(to_remove):
                    self._remove_os_block(ip)
            except Exception as e:
                print("[ip_blocker_db] Sync error:", e)
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
            print(f"[ip_blocker_db] Unsupported OS for apply: {CURRENT_OS}")
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
            print(f"[ip_blocker_db] Unsupported OS for remove: {CURRENT_OS}")
            return
        os.system(cmd)
        self._known_applied.discard(ip)
