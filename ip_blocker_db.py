#!/usr/bin/env python3
"""
ip_blocker_db.py
-----------------

This module provides a MySQL‑backed IP blocking service with automatic expiry and optional
OS‑level firewall enforcement. It is designed to integrate with a web application firewall
(WAF) but can be used independently to persist and enforce IP blocks across restarts.

Key features:

* **MySQL Persistence**: Blocks are stored in a `blocked_ips` table with an expiry timestamp. Blocks
  survive process restarts and can be queried via `get_active_blocks()`.
* **Connection Pooling**: Uses `mysql.connector`'s connection pooling for efficient, thread‑safe
  database access.
* **Automatic Schema Creation**: The required table is created on first use if it does not exist.
* **OS Enforcement**: Optionally applies blocks at the OS firewall level. On Linux, this module can
  use nftables, ipset+iptables, or plain iptables depending on what is available and the
  `IPB_OS_MODE` environment variable. On Windows and macOS, appropriate commands (netsh, pfctl)
  are used. Set `IPB_OS_MODE=off` to disable OS enforcement entirely.
* **Background Sync**: A background thread periodically sweeps expired entries and ensures that
  active blocks are applied at the OS level. Stale OS rules are removed when no longer present
  in the database.

Environment variables:

* `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DB`: Configure the MySQL
  connection. See the `MYSQL_CONFIG` default below for values.
* `MYSQL_POOL_SIZE`: Number of connections in the pool. Default: 5.
* `BLOCK_TTL_SECONDS`: Default block duration in seconds. Default: 300 (5 minutes).
* `IPB_OS_MODE`: Choose OS enforcement backend for Linux. Options: `auto` (default), `nft`, `ipset`,
  `iptables`, `off`. Ignored on non‑Linux platforms. In `auto` mode, the first available method
  (nft > ipset > iptables) is chosen.

Dependencies:

You need `mysql-connector-python` installed. On Linux, `iptables` is typically available by default.
To use nftables, install `nft`. For ipset, install `ipset` and ensure `iptables` is installed.

"""

from __future__ import annotations

import os
import threading
import platform
import subprocess
import shutil
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional, Dict, Set

import mysql.connector
from mysql.connector import pooling

# =========================
#   CONFIGURATION
# =========================

# MySQL connection parameters (can be overridden via environment variables)
MYSQL_CONFIG: Dict[str, object] = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "changeme"),
    "database": os.getenv("MYSQL_DB", "admin"),
    "charset": "utf8mb4",
    "use_pure": True,
}

# Connection pool name and size
POOL_NAME = "ipblocker_pool"
POOL_SIZE = int(os.getenv("MYSQL_POOL_SIZE", "5"))

# Default TTL (seconds) for blocks if not specified. Environment variable can override.
DEFAULT_BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", "300"))  # 5 minutes

# OS enforcement mode on Linux: 'auto' | 'nft' | 'ipset' | 'iptables' | 'off'
OS_MODE = os.getenv("IPB_OS_MODE", "auto").lower()

# Detect current OS for cross‑platform handling
def _detect_os() -> str:
    sysname = platform.system().lower()
    if "windows" in sysname:
        return "windows"
    if "darwin" in sysname:
        return "darwin"
    return "linux"

CURRENT_OS = _detect_os()


# Helper to check if a binary is available
def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


class MySQLIPBlocker:
    """MySQL‑backed IP blocker with optional OS firewall enforcement."""

    def __init__(
        self,
        mysql_cfg: Dict[str, object] = MYSQL_CONFIG,
        default_ttl_seconds: int = DEFAULT_BLOCK_TTL_SECONDS,
        sync_interval_sec: int = 30,
        os_mode: Optional[str] = None,
    ) -> None:
        """
        Initialise the IP blocker.

        Args:
            mysql_cfg: Dictionary of MySQL connection parameters. If omitted, defaults are used.
            default_ttl_seconds: Default block duration (seconds) for calls to block_ip() when no
                TTL is provided.
            sync_interval_sec: How often (seconds) the background sync thread runs to purge
                expired entries and reconcile OS firewall state.
            os_mode: Optional override for the OS enforcement mode on Linux. Overrides the
                `IPB_OS_MODE` environment variable if provided.
        """
        self.cfg = dict(mysql_cfg)
        self.default_ttl = max(1, int(default_ttl_seconds))
        self.sync_interval = int(sync_interval_sec)
        self._stop_event = threading.Event()
        self._known_applied: Set[str] = set()  # Track IPs we have applied in OS to avoid duplicates

        # Determine OS enforcement method
        if CURRENT_OS == "linux":
            self.os_mode = (os_mode or OS_MODE).lower()
        else:
            # On Windows or macOS, os_mode is ignored (we use native commands)
            self.os_mode = "system"

        # Connection pool
        self.pool = pooling.MySQLConnectionPool(pool_name=POOL_NAME, pool_size=POOL_SIZE, **self.cfg)

        # Initialise DB schema
        self._ensure_schema()

        # Prepare OS enforcement
        self._setup_os_enforcement(self.default_ttl)

    # ---------- Database Helpers ----------
    def _connect(self):
        return self.pool.get_connection()

    def _ensure_schema(self) -> None:
        """Ensure the blocked_ips table exists."""
        create_sql = (
            "CREATE TABLE IF NOT EXISTS blocked_ips ("
            " id INT AUTO_INCREMENT PRIMARY KEY,"
            " ip VARCHAR(45) NOT NULL UNIQUE,"
            " reason VARCHAR(255) NULL,"
            " blocked_at DATETIME NOT NULL DEFAULT (UTC_TIMESTAMP()),"
            " expires_at DATETIME NOT NULL"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        )
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(create_sql)
            cn.commit()

    # ---------- OS Enforcement Setup ----------
    def _setup_os_enforcement(self, ttl_seconds: int) -> None:
        """Initialise OS firewall mechanisms depending on the current OS and chosen mode."""
        self.os_method = "off"
        if CURRENT_OS != "linux":
            # Non‑Linux platforms use system commands directly; nothing to set up here
            self.os_method = "system"
            return
        # On Linux, choose backend based on os_mode
        mode = self.os_mode
        if mode == "off":
            self.os_method = "off"
            return
        chosen = mode
        if mode == "auto":
            if _have("nft"):
                chosen = "nft"
            elif _have("ipset") and _have("iptables"):
                chosen = "ipset"
            elif _have("iptables"):
                chosen = "iptables"
            else:
                chosen = "off"
        # Setup for nftables
        if chosen == "nft":
            if not _have("nft"):
                self.os_method = "off"
                return
            # Create a table and set for IPv4 addresses with per‑IP timeout
            script = (
                f"add table inet ipb_filter\n"
                f"add set inet ipb_filter blocked {{ type ipv4_addr; timeout {ttl_seconds}s; flags timeout; }}\n"
                f"add chain inet ipb_filter input {{ type filter hook input priority 0; policy accept; }}\n"
                f"add rule inet ipb_filter input ip saddr @blocked drop"
            )
            subprocess.run(["nft", "-f", "-"], input=script.encode(), check=False)
            self.os_method = "nft"
            return
        # Setup for ipset + iptables
        if chosen == "ipset":
            if not (_have("ipset") and _have("iptables")):
                self.os_method = "off"
                return
            # Create set with timeout and iptables drop rule
            subprocess.run(["ipset", "create", "ipb_blocked", "hash:ip", "timeout", str(ttl_seconds), "-exist"], check=False)
            probe = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "ipb_blocked", "src", "-j", "DROP"], check=False)
            if probe.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "ipb_blocked", "src", "-j", "DROP"], check=False)
            self.os_method = "ipset"
            return
        # Setup for plain iptables
        if chosen == "iptables":
            if not _have("iptables"):
                self.os_method = "off"
                return
            self.os_method = "iptables"
            return
        # Anything else: disable OS enforcement
        self.os_method = "off"

    # ---------- OS Enforcement Actions ----------
    def _apply_os_block(self, ip: str) -> None:
        """Apply an IP block at the OS level if possible."""
        if not ip:
            return
        if CURRENT_OS == "windows":
            # Windows firewall via netsh
            cmd = f'netsh advfirewall firewall add rule name="IPBLock {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=False)
            self._known_applied.add(ip)
            return
        if CURRENT_OS == "darwin":
            # macOS using pfctl
            cmd = f"echo 'block drop from {ip} to any' | sudo pfctl -ef -"
            subprocess.run(cmd, shell=True, check=False)
            self._known_applied.add(ip)
            return
        if CURRENT_OS != "linux":
            # Unsupported platform
            return
        # Linux backends
        method = self.os_method
        if method == "nft":
            element = f"{{ {ip} timeout {self.default_ttl}s }}"
            subprocess.run(["nft", "add", "element", "inet", "ipb_filter", "blocked", element], check=False)
            self._known_applied.add(ip)
            return
        if method == "ipset":
            subprocess.run(["ipset", "add", "ipb_blocked", ip, "timeout", str(self.default_ttl), "-exist"], check=False)
            self._known_applied.add(ip)
            return
        if method == "iptables":
            # Check if rule exists; if not, append
            subprocess.run([
                "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"
            ], check=False)
            # If iptables -C does not succeed, exit code will be non-zero; we always append
            subprocess.run([
                "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"
            ], check=False)
            self._known_applied.add(ip)
            return
        # If method off or unsupported, do nothing

    def _remove_os_block(self, ip: str) -> None:
        """Remove an IP block at the OS level if possible."""
        if not ip:
            return
        if CURRENT_OS == "windows":
            cmd = f'netsh advfirewall firewall delete rule name="IPBLock {ip}"'
            subprocess.run(cmd, shell=True, check=False)
            self._known_applied.discard(ip)
            return
        if CURRENT_OS == "darwin":
            # Clearing PF rules is global; cannot remove a single IP easily without stateful PF config
            # We simply flush rules (could disrupt other PF config). Use with caution.
            cmd = "sudo pfctl -F rules -f /etc/pf.conf"
            subprocess.run(cmd, shell=True, check=False)
            self._known_applied.discard(ip)
            return
        if CURRENT_OS != "linux":
            return
        # Linux backends
        method = self.os_method
        if method == "nft":
            element = f"{{ {ip} }}"
            subprocess.run(["nft", "delete", "element", "inet", "ipb_filter", "blocked", element], check=False)
            self._known_applied.discard(ip)
            return
        if method == "ipset":
            subprocess.run(["ipset", "del", "ipb_blocked", ip], check=False)
            self._known_applied.discard(ip)
            return
        if method == "iptables":
            subprocess.run([
                "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
            ], check=False)
            self._known_applied.discard(ip)
            return
        # If method off, do nothing

    # ---------- Public API ----------
    def block_ip(self, ip: str, reason: str = "", ttl_seconds: Optional[int] = None) -> None:
        """Insert or update an IP block with a TTL (from now). Default TTL used if not specified."""
        if not ip:
            return
        ttl = self.default_ttl if ttl_seconds is None else max(1, int(ttl_seconds))
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        sql = (
            "INSERT INTO blocked_ips (ip, reason, expires_at)"
            " VALUES (%s, %s, %s)"
            " ON DUPLICATE KEY UPDATE"
            " reason = VALUES(reason),"
            " expires_at = VALUES(expires_at)"
        )
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(sql, (ip, reason, expires_at.replace(tzinfo=None)))
            cn.commit()
        # Apply OS block
        self._apply_os_block(ip)

    def block_ip_5min(self, ip: str, reason: str = "") -> None:
        """Convenience wrapper to block for five minutes."""
        self.block_ip(ip, reason=reason, ttl_seconds=300)

    def unblock_ip(self, ip: str) -> None:
        """Remove an IP from the database and OS firewall."""
        if not ip:
            return
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute("DELETE FROM blocked_ips WHERE ip = %s;", (ip,))
            cn.commit()
        self._remove_os_block(ip)

    def get_active_blocks(self) -> List[Tuple[str, str, datetime]]:
        """Return a list of (ip, reason, expires_at) for currently active blocks."""
        sql = (
            "SELECT ip, COALESCE(reason, ''), expires_at"
            " FROM blocked_ips"
            " WHERE expires_at > UTC_TIMESTAMP()"
            " ORDER BY expires_at ASC"
        )
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall()
        return rows

    def sweep_expired(self) -> None:
        """Delete expired entries and remove them from the OS firewall."""
        sel = "SELECT ip FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        delq = "DELETE FROM blocked_ips WHERE expires_at <= UTC_TIMESTAMP();"
        expired: List[str] = []
        with self._connect() as cn:
            with cn.cursor() as cur:
                cur.execute(sel)
                expired = [r[0] for r in cur.fetchall()]
                cur.execute(delq)
            cn.commit()
        # Remove OS rules for expired IPs
        for ip in expired:
            self._remove_os_block(ip)

    # ---------- Background Sync ----------
    def start_background_sync(self) -> threading.Thread:
        """Start a background thread to periodically sync OS firewall with the DB."""
        t = threading.Thread(target=self._sync_loop, daemon=True)
        t.start()
        return t

    def stop_background_sync(self) -> None:
        """Signal the background sync thread to stop."""
        self._stop_event.set()

    def _sync_loop(self) -> None:
        """Background worker that keeps OS firewall and DB in sync."""
        while not self._stop_event.is_set():
            try:
                # 1) Purge expired DB entries and OS rules
                self.sweep_expired()
                # 2) Apply OS blocks for all active entries not yet applied
                active = self.get_active_blocks()
                active_ips = {ip for (ip, _, _) in active}
                for ip in active_ips:
                    if ip not in self._known_applied:
                        self._apply_os_block(ip)
                # 3) Remove OS rules that correspond to entries no longer in DB
                for ip in list(self._known_applied - active_ips):
                    self._remove_os_block(ip)
            except Exception as e:
                print("[ip_blocker_db] Sync error:", e)
            # Sleep until next run or until stop event is set
            self._stop_event.wait(self.sync_interval)

    # ---------- Utility ----------
    def __del__(self) -> None:
        """Ensure the background thread stops when the object is deleted."""
        try:
            self.stop_background_sync()
        except Exception:
            pass
