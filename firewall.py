#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI-Powered Web Application Firewall (full rewrite)
==================================================

Features
- DDoS sliding-window limiter
- AI inspection of path, query, body, and key headers
- MySQL-backed blocklist with TTL (via ip_blocker_db.MySQLIPBlocker)
- OS-level enforcement (nftables preferred; fallback to iptables+ipset)
- Admin login (via secureauth.verify_user) + /dashboard, /login, /logout
- Admin APIs: /admin/block/<ip>, /admin/unblock/<ip>
- JSON APIs: /stats, /metrics, /top_ips, /top_requesting_ips, /health
- Safe proxy IP extraction (CF-Connecting-IP, X-Forwarded-For, etc.)
- Robust logging & config via environment variables

Environment
-----------
APP_SECRET_KEY          (default: random fallback)
FW_BLOCK_TTL            default 300
FW_DDOS_WINDOW          default 60
FW_DDOS_MAX             default 20
FW_TRUST_PROXY          default 1
FW_OS_MODE              auto | nft | iptables | off  (default: auto)
FW_DEBUG                0/1 (default 0)
FW_NETWORK_MONITOR      0/1 (default 1, requires scapy)
FW_DB_APPLIES_OS        0/1 (default 1) -> avoid double OS blocking if DB already applies rules
FW_ADMIN_RATE_WINDOW    seconds (default 300)
FW_ADMIN_RATE_MAX       attempts in window (default 10)

Notes
-----
- This app *assumes* your templates (login.html, dashboard.html) exist.
- If FW_DB_APPLIES_OS=1 (default), we do NOT also call OS enforcer when blocking,
  to avoid duplicate OS rules (since ip_blocker_db already applies iptables/pf/netsh).
"""

from __future__ import annotations

import os
import sys
import time
import json
import logging
import shutil
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, Tuple

# Third-party
import psutil
from flask import (
    Flask, request, jsonify, render_template, redirect, url_for,
    flash, session, abort
)

# Optional middlewares/libraries
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    _PROXY_FIX = True
except Exception:
    _PROXY_FIX = False

try:
    from scapy.all import sniff, IP, Raw  # type: ignore
    _SCAPY = True
except Exception:
    _SCAPY = False

try:
    from flask_talisman import Talisman  # type: ignore
    _TALISMAN = True
except Exception:
    _TALISMAN = False

# Local modules (required)
try:
    from ai_detector import detect_attack
except Exception as e:
    print(f"[startup] ai_detector import error: {e}")
    sys.exit(1)

try:
    from ip_blocker_db import MySQLIPBlocker
except Exception as e:
    print(f"[startup] ip_blocker_db import error: {e}")
    sys.exit(1)

try:
    import secureauth
except Exception as e:
    print(f"[startup] secureauth import error: {e}")
    sys.exit(1)


# =============================================================================
# Configuration
# =============================================================================

class FirewallConfig:
    BLOCK_TTL = int(os.getenv("FW_BLOCK_TTL", "300"))
    DDOS_WINDOW = int(os.getenv("FW_DDOS_WINDOW", "60"))
    DDOS_MAX_REQUESTS = int(os.getenv("FW_DDOS_MAX", "20"))
    TRUST_PROXY = os.getenv("FW_TRUST_PROXY", "1") == "1"
    OS_MODE = os.getenv("FW_OS_MODE", "auto").lower()  # auto|nft|iptables|off
    DEBUG_MODE = os.getenv("FW_DEBUG", "0") == "1"
    LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO
    SECRET_KEY = os.getenv("APP_SECRET_KEY") or os.urandom(32).hex()
    SESSION_TIMEOUT_HOURS = 12

    ENABLE_NETWORK_MONITORING = _SCAPY and os.getenv("FW_NETWORK_MONITOR", "1") == "1"

    # If True, rely on DB layer to apply OS rules; avoid double-enforcement from this app.
    DB_APPLIES_OS = os.getenv("FW_DB_APPLIES_OS", "1") == "1"

    # Admin login rate-limit
    ADMIN_RATE_WINDOW = int(os.getenv("FW_ADMIN_RATE_WINDOW", "300"))
    ADMIN_RATE_MAX = int(os.getenv("FW_ADMIN_RATE_MAX", "10"))

    # Paths excluded from firewall scanning
    EXCLUDED_PATHS = {
        "/favicon.ico", "/robots.txt", "/health", "/healthz", "/ping",
        "/metrics", "/stats", "/top_ips", "/top_requesting_ips",
        "/login", "/logout", "/dashboard"
    }

    @staticmethod
    def is_excluded(path: str) -> bool:
        if not path:
            return True
        if path in FirewallConfig.EXCLUDED_PATHS:
            return True
        static_prefixes = ("/static/", "/assets/", "/css/", "/js/", "/img/", "/images/", "/fonts/")
        return any(path.startswith(p) for p in static_prefixes)


# =============================================================================
# Logging
# =============================================================================

def init_logger() -> logging.Logger:
    lg = logging.getLogger("firewall")
    if lg.handlers:
        return lg
    lg.setLevel(FirewallConfig.LOG_LEVEL)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    lg.addHandler(sh)

    try:
        fh = logging.FileHandler("firewall.log", encoding="utf-8")
        fh.setFormatter(fmt)
        lg.addHandler(fh)
    except Exception as e:
        print(f"[startup] file logging disabled: {e}")

    return lg

logger = init_logger()


# =============================================================================
# Stats & Rate Limiting
# =============================================================================

class FirewallStats:
    def __init__(self):
        self._lock = Lock()
        self._start = time.time()

        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0

        self.ddos_blocks = 0
        self.ai_blocks = 0
        self.network_blocks = 0

        self.ip_hits: Dict[str, int] = defaultdict(int)
        self.ip_block_hits: Dict[str, int] = defaultdict(int)

        self._resp_times = deque(maxlen=1000)
        self.avg_rt = 0.0

    def inc(self, field: str, n: int = 1):
        with self._lock:
            setattr(self, field, getattr(self, field, 0) + n)

    def hit_ip(self, ip: str):
        with self._lock:
            self.ip_hits[ip] += 1

    def hit_blocked_ip(self, ip: str):
        with self._lock:
            self.ip_block_hits[ip] += 1

    def add_rt(self, seconds: float):
        with self._lock:
            self._resp_times.append(seconds)
            self.avg_rt = sum(self._resp_times) / len(self._resp_times)

    def uptime_seconds(self) -> int:
        return int(time.time() - self._start)

    def top_requesters(self, k: int = 5) -> List[Tuple[str, int]]:
        with self._lock:
            return sorted(self.ip_hits.items(), key=lambda x: x[1], reverse=True)[:k]

    def top_blocked(self, k: int = 5) -> List[Tuple[str, int]]:
        with self._lock:
            return sorted(self.ip_block_hits.items(), key=lambda x: x[1], reverse=True)[:k]

    def to_dict(self) -> Dict[str, Any]:
        up = self.uptime_seconds()
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "allowed_requests": self.allowed_requests,
                "blocked_requests": self.blocked_requests,
                "ddos_blocks": self.ddos_blocks,
                "ai_blocks": self.ai_blocks,
                "network_blocks": self.network_blocks,
                "avg_response_time": round(self.avg_rt, 4),
                "uptime_seconds": up,
                "uptime_formatted": _format_uptime(up),
                "config": {
                    "block_ttl": FirewallConfig.BLOCK_TTL,
                    "ddos_window": FirewallConfig.DDOS_WINDOW,
                    "ddos_max": FirewallConfig.DDOS_MAX_REQUESTS,
                    "network_monitoring": FirewallConfig.ENABLE_NETWORK_MONITORING,
                    "os_mode": os.getenv("FW_OS_MODE", "auto"),
                    "db_applies_os": FirewallConfig.DB_APPLIES_OS,
                    "debug": FirewallConfig.DEBUG_MODE
                }
            }

def _format_uptime(s: int) -> str:
    if s < 60: return f"{s}s"
    if s < 3600:
        m, r = divmod(s, 60)
        return f"{m}m {r}s"
    if s < 86400:
        h, r = divmod(s, 3600)
        return f"{h}h {r//60}m"
    d, r = divmod(s, 86400)
    return f"{d}d {r//3600}h"


class SlidingWindowLimiter:
    """IP → timestamps within window; deny if hits >= max."""
    def __init__(self, window_s: int, max_hits: int):
        self.window = window_s
        self.max_hits = max_hits
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._lock = Lock()
        logger.info(f"[ddos] limiter: {max_hits} req / {window_s}s")

    def _prune(self, dq: deque, now: float):
        while dq and now - dq[0] >= self.window:
            dq.popleft()

    def hit(self, key: str) -> bool:
        """Record a hit; return True if limit exceeded (block)."""
        now = time.time()
        with self._lock:
            dq = self._hits[key]
            self._prune(dq, now)
            if len(dq) >= self.max_hits:
                return True
            dq.append(now)
            return False

    def count(self, key: str) -> int:
        now = time.time()
        with self._lock:
            dq = self._hits[key]
            self._prune(dq, now)
            return len(dq)


# =============================================================================
# OS-level Enforcement
# =============================================================================

class OSEnforcer:
    """Prefer nftables; fallback to iptables+ipset. Safe, idempotent."""
    def __init__(self, block_ttl: int):
        self.block_ttl = block_ttl
        self.method = "off"
        self.initialized = False
        self._init()

    def _init(self):
        mode = FirewallConfig.OS_MODE
        if mode == "off":
            logger.info("[os] enforcement disabled by FW_OS_MODE=off")
            return

        if mode in ("auto", "nft"):
            if self._ensure_nftables():
                self.method = "nft"
                self.initialized = True
                logger.info("[os] nftables ready")
                return
            elif mode == "nft":
                logger.error("[os] nft requested but not available")
                return

        if mode in ("auto", "iptables"):
            if self._ensure_ipset():
                self.method = "ipset"
                self.initialized = True
                logger.info("[os] iptables+ipset ready")
                return
            elif mode == "iptables":
                logger.error("[os] iptables requested but not available")
                return

        logger.warning("[os] no OS-level enforcement tool available")

    # ---------- nftables ----------
    def _ensure_nftables(self) -> bool:
        if not shutil.which("nft"):
            return False
        # Create table, set (with timeout), chain, and rule. Ignore "exists" errors.
        cmds = [
            "nft add table inet firewall",
            "nft add set inet firewall blocked_ips { type ipv4_addr; flags timeout; }",
            "nft add chain inet firewall input { type filter hook input priority 0; policy accept; }",
            "nft insert rule inet firewall input ip saddr @blocked_ips drop",
        ]
        for c in cmds:
            try:
                p = subprocess.run(c, shell=True, text=True, capture_output=True, timeout=5)
                if p.returncode != 0 and "already exists" not in (p.stderr or "").lower():
                    logger.debug(f"[os][nft] {c} -> {p.returncode}: {p.stderr.strip()}")
            except Exception as e:
                logger.debug(f"[os][nft] setup warn: {e}")
        return True

    # ---------- iptables+ipset ----------
    def _ensure_ipset(self) -> bool:
        if not (shutil.which("ipset") and shutil.which("iptables")):
            return False
        try:
            subprocess.run(
                ["ipset", "create", "firewall_blocked", "hash:ip", "timeout", str(self.block_ttl), "-exist"],
                capture_output=True, text=True, timeout=5
            )
            # Ensure INPUT rule exists
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-m", "set", "--match-set", "firewall_blocked", "src", "-j", "DROP"],
                capture_output=True, text=True
            )
            if check.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "firewall_blocked", "src", "-j", "DROP"],
                    capture_output=True, text=True, timeout=5
                )
            return True
        except Exception as e:
            logger.error(f"[os] ipset setup failed: {e}")
            return False

    # ---------- Actions ----------
    def block(self, ip: str, ttl: Optional[int] = None) -> bool:
        if not self.initialized or self.method == "off":
            return True
        ttl = int(ttl or self.block_ttl)
        try:
            if self.method == "nft":
                # IMPORTANT: braces syntax & 'timeout 300s' must be a single shell arg -> use shell=True
                cmd = f"nft add element inet firewall blocked_ips {{ {ip} timeout {ttl}s }}"
                p = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=5)
                if p.returncode == 0:
                    return True
                logger.error(f"[os][nft] block fail {ip}: {p.stderr.strip()}")
            elif self.method == "ipset":
                p = subprocess.run(
                    ["ipset", "add", "firewall_blocked", ip, "timeout", str(ttl), "-exist"],
                    capture_output=True, text=True, timeout=5
                )
                if p.returncode == 0:
                    return True
                logger.error(f"[os][ipset] block fail {ip}: {p.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logger.error(f"[os] block timeout {ip}")
        except Exception as e:
            logger.error(f"[os] block error {ip}: {e}")
        return False

    def unblock(self, ip: str) -> bool:
        if not self.initialized or self.method == "off":
            return True
        try:
            if self.method == "nft":
                cmd = f"nft delete element inet firewall blocked_ips {{ {ip} }}"
                subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=5)
                return True
            elif self.method == "ipset":
                subprocess.run(["ipset", "del", "firewall_blocked", ip], capture_output=True, text=True, timeout=5)
                return True
        except Exception as e:
            logger.error(f"[os] unblock error {ip}: {e}")
        return False


# =============================================================================
# AI Analyzer
# =============================================================================

class AIAnalyzer:
    LABELS = {
        0: "Benign",
        1: "SQL Injection",
        2: "Cross-Site Scripting (XSS)",
        3: "DDoS Attack"
    }

    def analyze_text(self, text: str) -> Tuple[int, str]:
        text = (text or "").strip()
        if not text:
            return 0, "Benign"
        try:
            code = int(detect_attack(text))
        except Exception as e:
            logger.debug(f"[ai] detect error: {e}")
            return 0, "Benign"
        return code, self.LABELS.get(code, f"Unknown({code})")

    def analyze_request(self, req) -> Tuple[bool, str, str]:
        # Path
        code, name = self.analyze_text(req.path or "/")
        if code:
            return True, name, f"path:{req.path}"

        # Query
        qs = req.query_string.decode("utf-8", errors="ignore")
        if qs:
            code, name = self.analyze_text(qs)
            if code:
                return True, name, f"query:{qs[:180]}"

        # Body
        try:
            body = req.get_data(as_text=True, cache=False) or ""
            if body:
                code, name = self.analyze_text(body)
                if code:
                    return True, name, f"body:{body[:200]}"
        except Exception as e:
            logger.debug(f"[ai] read body error: {e}")

        # Suspicious headers
        for h in ("User-Agent", "Referer", "X-Forwarded-For", "Cookie"):
            val = req.headers.get(h, "")
            if val:
                code, name = self.analyze_text(val)
                if code:
                    return True, name, f"header:{h}={val[:160]}"

        return False, "Benign", ""


# =============================================================================
# Helpers
# =============================================================================

def client_ip_from_request() -> str:
    for hdr in ("CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"):
        v = request.headers.get(hdr, "").strip()
        if v:
            if hdr == "X-Forwarded-For":
                return v.split(",")[0].strip()
            return v
    return request.remote_addr or "unknown"


def system_metrics() -> Dict[str, Any]:
    try:
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        cpu = psutil.cpu_percent(interval=0.1)
        out = {
            "time": time.time(),
            "cpu": {"percent": round(cpu, 1), "cores": psutil.cpu_count()},
            "memory": {
                "total_gb": round(mem.total / (1024**3), 2),
                "used_gb": round(mem.used / (1024**3), 2),
                "percent": round(mem.percent, 1),
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "percent": round(disk.used / disk.total * 100, 1),
            },
        }
        try:
            net = psutil.net_io_counters()
            out["network"] = {
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv,
                "packets_sent": net.packets_sent,
                "packets_recv": net.packets_recv,
            }
        except Exception:
            pass
        return out
    except Exception as e:
        logger.error(f"[metrics] error: {e}")
        return {"error": str(e), "time": time.time()}


def login_required():
    if "user" not in session:
        flash("Please log in first", "error")
        return False
    return True


# =============================================================================
# App init
# =============================================================================

stats = FirewallStats()
ddos = SlidingWindowLimiter(FirewallConfig.DDOS_WINDOW, FirewallConfig.DDOS_MAX_REQUESTS)
osfw = OSEnforcer(FirewallConfig.BLOCK_TTL)
ai = AIAnalyzer()

# DB blocker (handles schema + (by default) OS enforcement too)
db_blocker = MySQLIPBlocker(default_ttl_seconds=FirewallConfig.BLOCK_TTL, sync_interval_sec=30)
db_blocker.start_background_sync()

# Flask
app = Flask(__name__)
app.secret_key = FirewallConfig.SECRET_KEY
app.config.update(
    SESSION_COOKIE_NAME="firewall_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # set True behind HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=FirewallConfig.SESSION_TIMEOUT_HOURS),
    JSON_SORT_KEYS=False,
)

if FirewallConfig.TRUST_PROXY and _PROXY_FIX:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    logger.info("[http] ProxyFix enabled")

if _TALISMAN:
    Talisman(app, content_security_policy=None)  # keep CSP open unless you define assets
    logger.info("[http] Talisman enabled")


# =============================================================================
# Middleware
# =============================================================================

# Admin login brute-force protection
_admin_attempts = SlidingWindowLimiter(FirewallConfig.ADMIN_RATE_WINDOW, FirewallConfig.ADMIN_RATE_MAX)

@app.before_request
def _inbound():
    request._ts_start = time.time()

    path = request.path or "/"
    if FirewallConfig.is_excluded(path):
        return None

    ip = client_ip_from_request()
    request._client_ip = ip

    stats.inc("total_requests")
    stats.hit_ip(ip)

    # Database block check
    try:
        active_ips = {r[0] for r in db_blocker.get_active_blocks()}
        if ip in active_ips:
            stats.inc("blocked_requests")
            stats.hit_blocked_ip(ip)
            logger.info(f"[block] DB-listed IP denied: {ip}")
            return jsonify({"status": "blocked", "reason": "IP on blocklist", "ip": ip}), 403
    except Exception as e:
        logger.error(f"[block] DB check error: {e}")


@app.after_request
def _outbound(resp):
    try:
        if hasattr(request, "_ts_start"):
            stats.add_rt(time.time() - request._ts_start)
    except Exception:
        pass

    # Add baseline headers
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # X-XSS-Protection has no effect in modern Chromium, but harmless:
    resp.headers.setdefault("X-XSS-Protection", "1; mode=block")

    # Count 2xx/3xx as allowed (for non-excluded only)
    if not FirewallConfig.is_excluded(request.path or "/"):
        if 200 <= resp.status_code < 400:
            stats.inc("allowed_requests")
    return resp


# =============================================================================
# Routes: JSON APIs
# =============================================================================

@app.get("/stats")
def api_stats():
    return jsonify(stats.to_dict())

@app.get("/metrics")
def api_metrics():
    return jsonify(system_metrics())

@app.get("/top_ips")
def api_top_ips():
    try:
        limit = min(int(request.args.get("limit", 10)), 50)
    except Exception:
        limit = 10
    rows = db_blocker.get_active_blocks()
    rows_sorted = sorted(rows, key=lambda x: x[2], reverse=True)[:limit]
    out = []
    now = datetime.now()
    for ip, reason, expires_at in rows_sorted:
        eta = max(0, int((expires_at - now).total_seconds()))
        out.append({"ip": ip, "reason": reason, "expires_at": expires_at.isoformat(), "expires_in": eta})
    return jsonify(out)

@app.get("/top_requesting_ips")
def api_top_requesting_ips():
    try:
        limit = min(int(request.args.get("limit", 10)), 50)
    except Exception:
        limit = 10
    return jsonify([{"ip": ip, "request_count": c} for ip, c in stats.top_requesters(limit)])


@app.get("/health")
def api_health():
    return jsonify({
        "status": "healthy",
        "time": time.time(),
        "uptime": stats.uptime_seconds(),
        "version": "2.1.0"
    })


# =============================================================================
# Routes: Admin Auth + Dashboard
# =============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = client_ip_from_request()
        # rate limiting by IP
        if _admin_attempts.hit(ip):
            flash("Too many attempts. Try later.", "error")
            return render_template("login.html"), 429

        user = (request.form.get("username") or "").strip()
        pwd = (request.form.get("password") or "").strip()
        if not user or not pwd:
            flash("Please enter username and password.", "error")
            return render_template("login.html")

        try:
            if secureauth.verify_user(user, pwd):
                session["user"] = user
                session["login_at"] = time.time()
                session.permanent = True
                logger.info(f"[auth] login ok user={user} ip={ip}")
                return redirect(url_for("dashboard"))
        except Exception as e:
            logger.error(f"[auth] verify error: {e}")

        logger.warning(f"[auth] login fail user={user} ip={ip}")
        flash("Invalid credentials.", "error")
    return render_template("login.html")

@app.post("/logout")
@app.get("/logout")
def logout():
    user = session.get("user")
    session.clear()
    if user:
        logger.info(f"[auth] logout user={user}")
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.get("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    try:
        fw = stats.to_dict()
        metrics = system_metrics()
        top_blocked = sorted(db_blocker.get_active_blocks(), key=lambda x: x[2], reverse=True)[:5]
        top_requesters = stats.top_requesters(5)
        return render_template(
            "dashboard.html",
            stats=fw,
            metrics=metrics,
            top_blocked=top_blocked,
            top_requesting=top_requesters,
            user=session.get("user")
        )
    except Exception as e:
        logger.error(f"[dashboard] error: {e}")
        flash("Dashboard error.", "error")
        return render_template("dashboard.html", error=str(e))


# =============================================================================
# Routes: Admin actions (manual block/unblock)
# =============================================================================

@app.post("/admin/block/<ip>")
def admin_block(ip: str):
    if not login_required():
        return redirect(url_for("login"))
    reason = request.form.get("reason", "manual block")
    ttl = request.form.get("ttl")
    ttl_i = None
    try:
        ttl_i = int(ttl) if ttl else None
    except Exception:
        ttl_i = None

    try:
        db_blocker.block_ip(ip, reason=reason, ttl_seconds=ttl_i or FirewallConfig.BLOCK_TTL)
        # Avoid double OS blocks if DB is already applying rules
        if not FirewallConfig.DB_APPLIES_OS:
            osfw.block(ip, ttl_i)
        logger.info(f"[admin] blocked {ip} (reason={reason})")
        flash(f"Blocked {ip}", "success")
    except Exception as e:
        logger.error(f"[admin] block error {ip}: {e}")
        flash(f"Failed to block {ip}: {e}", "error")
    return redirect(url_for("dashboard"))

@app.post("/admin/unblock/<ip>")
def admin_unblock(ip: str):
    if not login_required():
        return redirect(url_for("login"))
    try:
        db_blocker.unblock_ip(ip)
        if not FirewallConfig.DB_APPLIES_OS:
            osfw.unblock(ip)
        logger.info(f"[admin] unblocked {ip}")
        flash(f"Unblocked {ip}", "success")
    except Exception as e:
        logger.error(f"[admin] unblock error {ip}: {e}")
        flash(f"Failed to unblock {ip}: {e}", "error")
    return redirect(url_for("dashboard"))


# =============================================================================
# Main WAF handler
# =============================================================================

@app.route("/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def waf(subpath: str):
    path = f"/{subpath}" if subpath else "/"
    if FirewallConfig.is_excluded(path):
        return jsonify({"status": "allowed", "reason": "excluded", "path": path})

    ip = getattr(request, "_client_ip", None) or client_ip_from_request()
    method = request.method

    # DDoS limiter
    if ddos.hit(ip):
        stats.inc("blocked_requests")
        stats.inc("ddos_blocks")
        stats.hit_blocked_ip(ip)
        reason = f"Rate limit exceeded ({FirewallConfig.DDOS_MAX_REQUESTS}/{FirewallConfig.DDOS_WINDOW}s)"
        # persist + OS block (respect DB_APPLIES_OS)
        try:
            db_blocker.block_ip(ip, reason=reason, ttl_seconds=FirewallConfig.BLOCK_TTL)
            if not FirewallConfig.DB_APPLIES_OS:
                osfw.block(ip)
        except Exception as e:
            logger.error(f"[ddos] block fail {ip}: {e}")

        logger.warning(f"[ddos] blocked {ip}: {reason}")
        return jsonify({"status": "blocked", "reason": reason, "ip": ip, "count": ddos.count(ip)}), 429

    # AI inspection
    is_bad, kind, where = ai.analyze_request(request)
    if is_bad:
        stats.inc("blocked_requests")
        stats.inc("ai_blocks")
        stats.hit_blocked_ip(ip)
        reason = f"AI detected: {kind}"
        try:
            db_blocker.block_ip(ip, reason=reason, ttl_seconds=FirewallConfig.BLOCK_TTL)
            if not FirewallConfig.DB_APPLIES_OS:
                osfw.block(ip)
        except Exception as e:
            logger.error(f"[ai] block fail {ip}: {e}")

        logger.warning(f"[ai] {ip} blocked -> {reason} ({where})")
        return jsonify({
            "status": "blocked",
            "reason": reason,
            "ip": ip,
            "where": (where[:120] + "...") if len(where) > 120 else where
        }), 403

    # Allowed request (echo limited info)
    try:
        body = request.get_data(as_text=True) or ""
    except Exception:
        body = ""
    logger.info(f"[allow] {ip} {method} {path}")
    return jsonify({
        "status": "allowed",
        "method": method,
        "path": path,
        "ip": ip,
        "timestamp": time.time(),
        "echo": (body[:200] + "...") if len(body) > 200 else body
    })


# =============================================================================
# Network Monitor (optional)
# =============================================================================

class NetMonitor:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self._running = False
        self._thr: Optional[Thread] = None

    def start(self):
        if not self.enabled:
            return
        if self._running:
            return
        self._running = True
        self._thr = Thread(target=self._loop, daemon=True)
        self._thr.start()
        logger.info("[net] monitor started")

    def stop(self):
        if not self._running:
            return
        self._running = False
        logger.info("[net] monitor stopping...")

    def _loop(self):
        try:
            sniff(
                filter="tcp port 80 or tcp port 443 or tcp port 8080",
                prn=self._on_packet,
                store=False,
                stop_filter=lambda pkt: not self._running
            )
        except Exception as e:
            logger.error(f"[net] sniff error: {e}")

    def _on_packet(self, pkt):
        try:
            if not pkt.haslayer(IP) or not pkt.haslayer(Raw):
                return
            src = pkt[IP].src
            try:
                payload = pkt[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                return
            if not payload or len(payload.strip()) < 10:
                return
            code, name = ai.analyze_text(payload)
            if code:
                stats.inc("network_blocks")
                stats.inc("blocked_requests")
                stats.hit_blocked_ip(src)
                reason = f"Network {name}"
                try:
                    db_blocker.block_ip(src, reason=reason, ttl_seconds=FirewallConfig.BLOCK_TTL)
                    if not FirewallConfig.DB_APPLIES_OS:
                        osfw.block(src)
                except Exception as e:
                    logger.error(f"[net] block fail {src}: {e}")
                logger.warning(f"[net] {src} blocked -> {reason}")
        except Exception as e:
            logger.debug(f"[net] analyze error: {e}")

netmon = NetMonitor(FirewallConfig.ENABLE_NETWORK_MONITORING)


# =============================================================================
# Startup / Shutdown
# =============================================================================

def initialize():
    logger.info("=== Starting AI WAF v2.1.0 ===")
    logger.info(f"- Block TTL: {FirewallConfig.BLOCK_TTL}s")
    logger.info(f"- DDoS: {FirewallConfig.DDOS_MAX_REQUESTS}/{FirewallConfig.DDOS_WINDOW}s")
    logger.info(f"- OS mode: {FirewallConfig.OS_MODE} (resolved: {osfw.method})")
    logger.info(f"- Network monitor: {'on' if FirewallConfig.ENABLE_NETWORK_MONITORING else 'off'}")
    logger.info(f"- Debug: {'on' if FirewallConfig.DEBUG_MODE else 'off'}")
    netmon.start()

def finalize():
    logger.info("[shutdown] stopping...")
    try:
        netmon.stop()
    except Exception as e:
        logger.error(f"[shutdown] error: {e}")
    logger.info("[shutdown] done.")


# =============================================================================
# Entrypoint
# =============================================================================

def main():
    try:
        initialize()
        app.run(
            host="0.0.0.0",
            port=8080,
            debug=FirewallConfig.DEBUG_MODE,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"[fatal] {e}")
        sys.exit(1)
    finally:
        finalize()

if __name__ == "__main__":
    main()
