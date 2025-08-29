#!/usr/bin/env python3
"""
ip_blocker_db.py
- Persist blocked IPs in MSSQL with TTL (auto-expire)
- Periodically sync with OS firewall (Windows/Linux/macOS)
- Simple API: block_ip(), unblock_ip(), get_active_blocks(), start_background_sync()

Requires: pyodbc
    pip install pyodbc
"""

import os
import time
import threading
from datetime import datetime, timedelta, timezone
import pyodbc

# ====== EDIT THIS: your MSSQL connection string ======
MSSQL_CONN = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=DESKTOP-HP5RE4K;"
    "DATABASE=admin;"
    "Trusted_Connection=yes;"
)

# OS detection (very small shim; align with your existing detect_os() if you prefer)
import platform
def _detect_os():
    sysname = platform.system().lower()
    if "windows" in sysname:
        return "windows"
    if "darwin" in sysname:
        return "darwin"
    return "linux"

CURRENT_OS = _detect_os()


class MSSQLIPBlocker:
    def __init__(self, conn_str=MSSQL_CONN, default_ttl_seconds=3600, sync_interval_sec=30):
        """
        default_ttl_seconds: how long a new block lasts (unless you override per call)
        sync_interval_sec : how often the background thread reconciles DB ↔ OS firewall
        """
        self.conn_str = conn_str
        self.default_ttl = default_ttl_seconds
        self.sync_interval = sync_interval_sec
        self._stop = threading.Event()
        self._known_applied = set()  # what we've already applied to OS this run

        self._ensure_schema()

    # ---------- DB Helpers ----------
    def _connect(self):
        return pyodbc.connect(self.conn_str, autocommit=True)

    def _ensure_schema(self):
        create_sql = """
        IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[blocked_ips]') AND type in (N'U'))
        BEGIN
            CREATE TABLE [dbo].[blocked_ips](
                [id]            INT IDENTITY(1,1) PRIMARY KEY,
                [ip]            VARCHAR(45) NOT NULL UNIQUE,
                [reason]        NVARCHAR(255) NULL,
                [blocked_at]    DATETIME2(0) NOT NULL DEFAULT SYSUTCDATETIME(),
                [expires_at]    DATETIME2(0) NOT NULL
            );
        END;
        """
        with self._connect() as cn:
            cn.cursor().execute(create_sql)

    # ---------- Public API ----------
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: int = None):
        """Insert or update an IP block with a TTL (from now)."""
        if ttl_seconds is None:
            ttl_seconds = self.default_ttl
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        upsert_sql = """
        MERGE dbo.blocked_ips AS t
        USING (SELECT ? AS ip) AS s
            ON t.ip = s.ip
        WHEN MATCHED THEN
            UPDATE SET reason = ?, expires_at = ?
        WHEN NOT MATCHED THEN
            INSERT (ip, reason, expires_at)
            VALUES (s.ip, ?, ?);
        """
        with self._connect() as cn:
            cn.cursor().execute(upsert_sql, ip, reason, expires_at, reason, expires_at)

        # apply immediately to OS
        self._apply_os_block(ip)

    def unblock_ip(self, ip: str):
        """Remove an IP from DB and OS firewall."""
        with self._connect() as cn:
            cn.cursor().execute("DELETE FROM dbo.blocked_ips WHERE ip = ?", ip)
        self._remove_os_block(ip)

    def get_active_blocks(self):
        """Return list of (ip, reason, expires_at) that are not expired."""
        sql = """
        SELECT ip, ISNULL(reason, ''), expires_at
        FROM dbo.blocked_ips
        WHERE expires_at > SYSUTCDATETIME()
        ORDER BY expires_at ASC;
        """
        with self._connect() as cn:
            rows = cn.cursor().execute(sql).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]

    def sweep_expired(self):
        """Delete expired rows and clean OS firewall for them."""
        # First fetch expired to remove from OS:
        sel = "SELECT ip FROM dbo.blocked_ips WHERE expires_at <= SYSUTCDATETIME();"
        delq = "DELETE FROM dbo.blocked_ips WHERE expires_at <= SYSUTCDATETIME();"
        with self._connect() as cn:
            cur = cn.cursor()
            expired = [r[0] for r in cur.execute(sel).fetchall()]
            cur.execute(delq)

        for ip in expired:
            self._remove_os_block(ip)

    # ---------- Background Sync ----------
    def start_background_sync(self):
        """Start periodic DB↔OS firewall reconciliation in a thread."""
        t = threading.Thread(target=self._sync_loop, daemon=True)
        t.start()
        return t

    def stop_background_sync(self):
        self._stop.set()

    def _sync_loop(self):
        while not self._stop.is_set():
            try:
                # 1) expire old entries
                self.sweep_expired()

                # 2) ensure all active entries are applied in OS
                active = self.get_active_blocks()
                active_ips = set(ip for ip, _, _ in active)
                for ip in active_ips:
                    if ip not in self._known_applied:
                        self._apply_os_block(ip)

                # 3) if we have OS blocks that are no longer in DB (unlikely if only this module edits),
                #    try to remove them. (We only track what we applied.)
                to_remove = self._known_applied - active_ips
                for ip in list(to_remove):
                    self._remove_os_block(ip)

            except Exception as e:
                print("[ip_blocker_db] Sync error:", e)

            self._stop.wait(self.sync_interval)

    # ---------- OS Firewall ----------
    def _apply_os_block(self, ip: str):
        if CURRENT_OS == "linux":
            # add only if not exists
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
            # remove matching rule by name
            cmd = f'netsh advfirewall firewall delete rule name="DBBlock {ip}"'
        elif CURRENT_OS == "darwin":
            # pfctl doesn't track single rules by name; best-effort reset (you may keep a pf.conf and reload)
            cmd = "sudo pfctl -F rules -f /etc/pf.conf"
        else:
            print(f"[ip_blocker_db] Unsupported OS for remove: {CURRENT_OS}")
            return
        os.system(cmd)
        self._known_applied.discard(ip)
