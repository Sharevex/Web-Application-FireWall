#!/usr/bin/env python3
# ip_blocker_db.py
import os, time, logging, shutil, subprocess, threading
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from mysql_db import get_conn, init_mysql

logger = logging.getLogger("ip_blocker_db")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(h)

DEFAULT_TTL = int(os.getenv("BLOCK_TTL_SECONDS", "300"))  # 5 min
SWEEP_EVERY = int(os.getenv("BLOCK_SWEEP_SECONDS", "30"))
OS_MODE = os.getenv("FW_OS_MODE", "auto")  # auto | nft | ipset | off

class OSEnforcer:
    def __init__(self, mode: str = "auto"):
        self.mode = self._detect_mode(mode)
        self._ensure_installed()

    def _detect_mode(self, mode: str) -> str:
        if mode in ("nft", "ipset", "off"):
            return mode
        # auto
        if shutil.which("nft"):
            return "nft"
        if shutil.which("ipset") and shutil.which("iptables"):
            return "ipset"
        return "off"

    def _run(self, *args):
        try:
            return subprocess.run(args, check=True, capture_output=True, text=True)
    # noqa: E701
        except subprocess.CalledProcessError as e:
            logger.warning("Command failed: %s\nstdout=%s\nstderr=%s", " ".join(args), e.stdout, e.stderr)
            return None

    def _ensure_installed(self):
        if self.mode == "nft":
            # Create table/sets/chain/rules if missing
            self._run("nft", "add", "table", "inet", "filter")  # harmless if exists
            # IPv4 set
            self._run("nft", "add", "set", "inet", "filter", "fw_blocked",
                      "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}",)
            # IPv6 set
            self._run("nft", "add", "set", "inet", "filter", "fw6_blocked",
                      "{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}",)
            # input chain and drop rules
            self._run("nft", "add", "chain", "inet", "filter", "input",
                      "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}",)
            self._run("nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", "@fw_blocked", "drop")
            self._run("nft", "add", "rule", "inet", "filter", "input", "ip6", "saddr", "@fw6_blocked", "drop")
        elif self.mode == "ipset":
            # Create set + iptables jump
            self._run("ipset", "create", "fw_blocked", "hash:ip", "timeout", "0")  # 0 timeout here; per-entry later
            self._run("iptables", "-I", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP")
            if shutil.which("ip6tables"):
                self._run("ip6tables", "-I", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP")

    def add(self, ip: str, ttl: int):
        if self.mode == "off":
            return
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
            # ipset expects seconds TTL per add
            self._run("ipset", "add", "fw_blocked", ip, "timeout", str(ttl))

    def remove(self, ip: str):
        if self.mode == "off":
            return
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
            self._run("ipset", "del", "fw_blocked", ip)

class MySQLIPBlocker:
    def __init__(self, default_ttl: int = DEFAULT_TTL):
        init_mysql()
        self.default_ttl = default_ttl
        self.enforcer = OSEnforcer(OS_MODE)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sweeper, name="block_sweeper", daemon=True)
        self._thread.start()

    def block(self, ip: str, ttl: int = None, reason: str = None, created_by: str = "waf") -> None:
        ttl = int(ttl) if ttl is not None else self.default_ttl
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        sql = """
        INSERT INTO blocked_ips (ip, reason, created_by, enforced, expires_at)
        VALUES (%s,%s,%s,1,%s)
        ON DUPLICATE KEY UPDATE
          reason=VALUES(reason),
          created_by=VALUES(created_by),
          enforced=1,
          expires_at=VALUES(expires_at)
        """
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, (ip, (reason or "")[:255], created_by, expires_at.replace(tzinfo=None)))
        # OS-level
        self.enforcer.add(ip, ttl)

    def unblock(self, ip: str) -> None:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE blocked_ips SET enforced=0, expires_at=NULL WHERE ip=%s", (ip,))
        self.enforcer.remove(ip)

    def is_blocked(self, ip: str) -> bool:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT enforced, expires_at FROM blocked_ips WHERE ip=%s",
                (ip,),
            )
            row = cur.fetchone()
        if not row:
            return False
        enforced, expires_at = row
        if not enforced:
            return False
        if expires_at is None:
            return True
        # treat DB datetime as naive -> UTC
        if datetime.utcnow() > expires_at:
            # lazily drop past-expired
            self.unblock(ip)
            return False
        return True

    def _sweeper(self):
        while not self._stop.is_set():
            try:
                self._expire_pass()
            except Exception as e:
                logger.warning("sweeper error: %s", e)
            self._stop.wait(SWEEP_EVERY)

    def _expire_pass(self):
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT ip FROM blocked_ips WHERE enforced=1 AND expires_at IS NOT NULL AND expires_at < UTC_TIMESTAMP()"
            )
            rows = cur.fetchall() or []
        for (ip,) in rows:
            try:
                self.unblock(ip)
            except Exception as e:
                logger.warning("failed to unblock expired %s: %s", ip, e)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
