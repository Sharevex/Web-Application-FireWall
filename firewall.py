#!/usr/bin/env python3
"""
firewall.py
-----------

This module implements a robust web application firewall with the following features:

* Per‑IP request counting and DDoS rate limiting (configurable via environment variables).
* AI‑based request content inspection using an external classifier (see ai_detector.detect_attack).
* Persistent IP blocking backed by a MySQL database with automatic expiry (via ip_blocker_db.MySQLIPBlocker).
* OS‑level blocking using nftables or ipset/iptables with automatic expiry.
* Simple dashboard with login, logout and JSON endpoints for statistics and metrics.

The firewall is highly configurable via environment variables. Defaults are chosen to minimise false
positives while still providing basic protections. See the top of this file for a list of supported
environment variables.

Usage:
    python3 firewall.py

Environment variables:
    FW_BLOCK_TTL          Default block TTL in seconds (for both DB and OS rules). Default: 300.
    FW_DDOS_WINDOW        Sliding window in seconds for DDoS rate limiting. Default: 60.
    FW_DDOS_MAX           Maximum allowed requests per IP within the window. Default: 20.
    FW_DDOS_ENABLED       Set to "0" to disable the DDoS rate limiter entirely. Default: "1".
    FW_AI_DETECTION       Set to "0" to disable AI inspection completely. Default: "1".
    FW_AI_DETECTION_PATH  Set to "1" to enable AI inspection of request paths. Default: "0".
    FW_AI_DETECTION_QUERY Set to "0" to disable AI inspection of query strings. Default: "1".
    FW_AI_DETECTION_BODY  Set to "0" to disable AI inspection of request bodies. Default: "1".
    FW_AI_DETECTION_HEADERS
                          Set to "1" to enable AI inspection of selected headers. Default: "0".
    FW_AI_BLOCK_THRESHOLD Minimum number of malicious detections required to block a request. Default: 2.
    FW_OS_MODE            Set to "auto", "nft", "ipset" or "off" to choose OS enforcement backend. Default: "auto".
    FW_TRUST_PROXY        Set to "0" to disable ProxyFix (trust no proxy headers). Default: "1".
    FW_USE_REMOTE_ADDR    Set to "1" to ignore proxy headers entirely and rely on remote_addr. Default: "0".

This module should be considered self‑contained; it depends only on ai_detector.py, ip_blocker_db.py,
and secureauth.py in the same project. External dependencies such as Flask and scapy must be installed.
"""

from __future__ import annotations

import os
import re
import time
import logging
import threading
import subprocess
import shutil
from datetime import timedelta
from collections import defaultdict, deque
from typing import List, Tuple, Optional, Dict, Any

import psutil
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash, session, abort, g
)
from werkzeug.middleware.proxy_fix import ProxyFix

# -------- Local imports --------
try:
    from scapy.all import sniff, IP, Raw  # type: ignore
except Exception:
    # Gracefully handle missing scapy; sniffing will be disabled
    sniff = None  # type: ignore
    IP = Raw = None  # type: ignore

from ip_blocker_db import MySQLIPBlocker
from ai_detector import detect_attack
import secureauth

# ---------------- Config ---------------- #

# Default block TTL in seconds (used for DB and OS level). Can be overridden with FW_BLOCK_TTL.
BLOCK_TTL_SECONDS = int(os.environ.get("FW_BLOCK_TTL", "300"))

# OS enforcement mode: 'auto' | 'nft' | 'ipset' | 'off'
OS_MODE = os.environ.get("FW_OS_MODE", "auto").lower()

# AI detection flags
AI_DETECTION_ENABLED = os.environ.get("FW_AI_DETECTION", "1") != "0"
AI_DETECTION_PATH = os.environ.get("FW_AI_DETECTION_PATH", "0") != "0"
AI_DETECTION_QUERY = os.environ.get("FW_AI_DETECTION_QUERY", "1") != "0"
AI_DETECTION_BODY = os.environ.get("FW_AI_DETECTION_BODY", "1") != "0"
AI_DETECTION_HEADERS = os.environ.get("FW_AI_DETECTION_HEADERS", "0") != "0"
try:
    AI_BLOCK_THRESHOLD = max(1, int(os.environ.get("FW_AI_BLOCK_THRESHOLD", "2")))
except Exception:
    AI_BLOCK_THRESHOLD = 2

# DDoS limiter configuration
DDOS_ENABLED = os.environ.get("FW_DDOS_ENABLED", "1") != "0"
DDOS_WINDOW = int(os.environ.get("FW_DDOS_WINDOW", "60"))
DDOS_MAX = int(os.environ.get("FW_DDOS_MAX", "20"))

# Proxy and remote address handling
TRUST_PROXY = os.environ.get("FW_TRUST_PROXY", "1") != "0"
USE_REMOTE_ADDR_ONLY = os.environ.get("FW_USE_REMOTE_ADDR", "0") != "0"

# Logging setup
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Excluded paths that should not be counted in general statistics. These are typically
# static assets or health endpoints. Paths starting with /static/ are excluded.
EXCLUDED_PATHS = {
    "/favicon.ico",
    "/robots.txt",
    "/health",
    "/healthz",
    "/metrics",
    "/stats",
    "/top_ips",
    "/login",
    "/logout",
}

# Precompiled pattern to quickly identify suspicious text that might merit AI inspection.
# This covers common SQL keywords and script tags, ignoring case.
SUSPICIOUS_PATTERN = re.compile(r"(?i)(select|union|insert|delete|update|drop|script)")


def suspicious_text(text: str) -> bool:
    """Return True if text contains characters or patterns suggestive of an attack."""
    if not text:
        return False
    # Check for common injection metacharacters
    if any(c in text for c in "<>'\";"):
        return True
    return bool(SUSPICIOUS_PATTERN.search(text))


# ---------------- Statistics ---------------- #

class Stats:
    """Thread‑safe counters for request handling."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_requests: int = 0
        self.allowed_requests: int = 0
        self.blocked_requests: int = 0
        self.ddos_blocks: int = 0
        self.ai_based_blocks: int = 0
        self.network_blocks: int = 0

    def _inc(self, field: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def total(self) -> None:
        self._inc("total_requests")

    def allowed(self) -> None:
        self._inc("allowed_requests")

    def blocked(self) -> None:
        self._inc("blocked_requests")

    def bump(self, field: str) -> None:
        self._inc(field)

    def to_dict(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "allowed_requests": self.allowed_requests,
                "blocked_requests": self.blocked_requests,
                "ddos_blocks": self.ddos_blocks,
                "ai_based_blocks": self.ai_based_blocks,
                "network_blocks": self.network_blocks,
            }


# ---------------- DDoS Limiter ---------------- #

class DDoSRateLimiter:
    """Simple sliding window rate limiter for IP addresses."""

    def __init__(self, window: int, max_requests: int) -> None:
        self.time_window = window
        self.max_requests = max_requests
        self._log: Dict[str, deque[float]] = defaultdict(deque)

    def is_ddos(self, ip: str) -> bool:
        now = time.time()
        dq = self._log[ip]
        # purge timestamps outside the window
        while dq and dq[0] < now - self.time_window:
            dq.popleft()
        if len(dq) >= self.max_requests:
            return True
        dq.append(now)
        return False


# ---------------- OS Enforcement ---------------- #

def have(cmd: str) -> bool:
    """Return True if the given command exists on the system."""
    return shutil.which(cmd) is not None


OS_METHOD = "off"  # Set in setup_os_enforcement()


def setup_os_enforcement(ttl_seconds: int) -> None:
    """Initialise OS firewall backend (nftables or ipset) and configure a set for blocking IPs."""
    global OS_METHOD
    mode = OS_MODE
    if mode == "off":
        OS_METHOD = "off"
        logging.info("OS enforcement disabled (FW_OS_MODE=off).")
        return

    # auto‑detect best available
    chosen = mode
    if mode == "auto":
        if have("nft"):
            chosen = "nft"
        elif have("ipset") and have("iptables"):
            chosen = "ipset"
        else:
            chosen = "off"

    if chosen == "nft":
        if not have("nft"):
            logging.warning("nft not available; falling back to ipset if present.")
        else:
            # Create nftables table, set and chain with per‑IP timeout
            script = f"""
            add table inet filter
            add set inet filter fw_blocked {{ type ipv4_addr; timeout {ttl_seconds}s; flags timeout; }}
            add chain inet filter input {{ type filter hook input priority 0; policy accept; }}
            add rule inet filter input ip saddr @fw_blocked drop
            """
            subprocess.run(["nft", "-f", "-"], input=script.encode(), check=False)
            OS_METHOD = "nft"
            logging.info(f"OS enforcement: nftables set fw_blocked with timeout {ttl_seconds}s")
            return

    if chosen == "ipset":
        if not (have("ipset") and have("iptables")):
            logging.warning("ipset/iptables not available; OS enforcement disabled.")
            OS_METHOD = "off"
            return
        # Create ipset and iptables rule if not exists
        subprocess.run(["ipset", "create", "fw_blocked", "hash:ip", "timeout", str(ttl_seconds), "-exist"], check=False)
        # ensure iptables drop rule exists
        probe = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"])
        if probe.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"], check=False)
        OS_METHOD = "ipset"
        logging.info(f"OS enforcement: ipset+iptables with timeout {ttl_seconds}s")
        return

    OS_METHOD = "off"
    logging.info("OS enforcement not enabled (no supported backend found).")


def os_enforce_add(ip: str, ttl_seconds: int) -> None:
    """Add an IP to the OS firewall set with an expiry."""
    if not ip:
        return
    if OS_METHOD == "nft" and have("nft"):
        # nft syntax requires the element be wrapped in braces
        element = f"{{ {ip} timeout {ttl_seconds}s }}"
        subprocess.run(["nft", "add", "element", "inet", "filter", "fw_blocked", element], check=False)
    elif OS_METHOD == "ipset" and have("ipset"):
        subprocess.run(["ipset", "add", "fw_blocked", ip, "timeout", str(ttl_seconds), "-exist"], check=False)
    # If OS_METHOD is off or unsupported, do nothing


# ---------------- Client IP Handling ---------------- #

def get_client_ip() -> str:
    """Determine the true client IP address considering proxy headers.

    If USE_REMOTE_ADDR_ONLY is set, proxy headers are ignored.
    Otherwise, check CF‑Connecting‑IP, then first entry in X‑Forwarded‑For,
    then X‑Real‑IP, then remote_addr as a fallback.
    """
    if USE_REMOTE_ADDR_ONLY:
        return request.remote_addr or "unknown"
    # Cloudflare header has highest priority
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf
    # X‑Forwarded‑For may contain multiple addresses separated by commas
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        for part in xff.split(","):
            ip = part.strip()
            if ip:
                return ip
    # X‑Real‑IP header
    xr = request.headers.get("X-Real-IP")
    if xr:
        return xr
    return request.remote_addr or "unknown"


# ---------------- AI Inspection ---------------- #

def ai_inspect(text: str) -> int:
    """Wrapper for the AI classifier. Returns a class code (0=benign,1=SQLi,2=XSS,3=DDoS)."""
    try:
        code = detect_attack(text)
        logging.info(f"ai_detector returned {code}")
        return int(code) if code is not None else 0
    except Exception as e:
        logging.error(f"ai_detector error: {e}")
        return 0


def should_block_request(client_ip: str, body: str) -> Tuple[bool, Optional[str]]:
    """Inspect the current request using AI classification and decide whether to block.

    Returns a tuple (block: bool, reason: Optional[str]). If block is True, reason describes the
    type of attack; otherwise reason is None.
    AI inspection can be disabled or fine‑tuned via environment variables.
    """
    if not AI_DETECTION_ENABLED:
        return False, None

    malicious_count = 0
    detected_code: Optional[int] = None

    # Inspect path
    if AI_DETECTION_PATH:
        path = request.path or "/"
        if suspicious_text(path):
            code = ai_inspect(path)
            if code != 0:
                malicious_count += 1
                detected_code = code

    # Inspect query string
    if AI_DETECTION_QUERY:
        query = request.query_string.decode("utf-8", errors="ignore")
        if query and suspicious_text(query):
            code = ai_inspect(query)
            if code != 0:
                malicious_count += 1
                detected_code = code

    # Inspect body
    if AI_DETECTION_BODY:
        if body and suspicious_text(body):
            code = ai_inspect(body)
            if code != 0:
                malicious_count += 1
                detected_code = code

    # Inspect selected headers
    if AI_DETECTION_HEADERS:
        for header_name in ["User-Agent", "Referer", "X-Forwarded-For"]:
            header_val = request.headers.get(header_name, "")
            if header_val and suspicious_text(header_val):
                code = ai_inspect(header_val)
                if code != 0:
                    malicious_count += 1
                    detected_code = code

    if malicious_count >= AI_BLOCK_THRESHOLD:
        # Map classification to human‑readable reason; default if unknown
        reason_map = {1: "SQL injection (AI)", 2: "Cross‑site scripting (AI)", 3: "DDoS payload (AI)"}
        reason = reason_map.get(detected_code or 0, "Malicious content (AI)")
        return True, reason
    return False, None


# ---------------- Flask App and Globals ---------------- #

# Create the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "fallback_secret")
app.config.update(
    SESSION_COOKIE_NAME="fw_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# Trust at most one proxy hop if enabled
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Global objects
stats = Stats()

# Track total requests per IP and blocked IPs separately
ip_request_count: Dict[str, int] = defaultdict(int)
blocked_ip_count: Dict[str, int] = defaultdict(int)
ipcount_lock = threading.Lock()

# Instantiate MySQL-backed blocker
db_blocker = MySQLIPBlocker(default_ttl_seconds=BLOCK_TTL_SECONDS, sync_interval_sec=30)
db_blocker.start_background_sync()

# Setup OS enforcement
setup_os_enforcement(BLOCK_TTL_SECONDS)

# Initialise the DDoS limiter or a no‑op based on configuration
if DDOS_ENABLED:
    ddos = DDoSRateLimiter(DDOS_WINDOW, DDOS_MAX)
else:
    class _NoOpLimiter:
        def __init__(self, window: int, max_requests: int) -> None:
            self.time_window = window
            self.max_requests = max_requests
        def is_ddos(self, ip: str) -> bool:
            return False
    ddos = _NoOpLimiter(DDOS_WINDOW, DDOS_MAX)


# ---------------- Helper Functions ---------------- #

def log_request(ip: str, data: str, result: str) -> None:
    """Append a line to the firewall log."""
    try:
        with open("firewall.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {result} - {data}\n")
    except Exception as e:
        logging.error(f"log write error: {e}")


def format_uptime(seconds: int) -> str:
    """Return a human‑readable uptime string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes, secs = divmod(seconds, 60)
        return f"{minutes}m {secs}s"
    elif seconds < 86400:
        hours, rem = divmod(seconds, 3600)
        minutes = rem // 60
        return f"{hours}h {minutes}m"
    days, rem = divmod(seconds, 86400)
    hours = rem // 3600
    return f"{days}d {hours}h"


def get_cpu() -> Dict[str, Any]:
    """Return CPU usage information."""
    return {"total": psutil.cpu_percent(interval=None), "cores": psutil.cpu_count(logical=True)}


def get_ram() -> Dict[str, float]:
    """Return RAM usage information in gigabytes."""
    m = psutil.virtual_memory()
    return {
        "total": round(m.total / (1024**3), 2),
        "used": round(m.used / (1024**3), 2),
        "free": round(m.available / (1024**3), 2),
        "percent": m.percent,
    }


def get_disk() -> List[Dict[str, float]]:
    """Return disk usage for the root filesystem."""
    try:
        u = psutil.disk_usage("/")
        return [{
            "device": "root",
            "mountpoint": "/",
            "total": round(u.total / (1024**3), 2),
            "used": round(u.used / (1024**3), 2),
            "free": round(u.free / (1024**3), 2),
            "percent": u.percent,
        }]
    except Exception:
        return []


def get_uptime() -> Dict[str, Any]:
    """Return uptime information including a formatted string."""
    bt = psutil.boot_time()
    uptime_secs = int(time.time() - bt)
    return {
        "uptime_seconds": uptime_secs,
        "formatted": format_uptime(uptime_secs),
    }


# ---------------- Flask Request Hooks ---------------- #

@app.before_request
def before_every_request() -> None:
    """Executed before each request. Counts requests and blocks DB‑blacklisted IPs."""
    path = request.path or "/"
    client_ip = get_client_ip()
    g.allowed_counted = False  # flag to ensure allowed counting only once

    # Skip counting for excluded paths
    if not (path in EXCLUDED_PATHS or path.startswith("/static/")):
        stats.total()
        # track per‑IP requests under lock
        with ipcount_lock:
            ip_request_count[client_ip] += 1

    # Fetch active DB blocks once per request
    try:
        active_ips = {ip for ip, _, _ in db_blocker.get_active_blocks()}
    except Exception as e:
        logging.error(f"DB error reading active blocks: {e}")
        active_ips = set()

    # If client_ip is in DB blocked list, deny immediately
    if client_ip in active_ips:
        stats.blocked()
        with ipcount_lock:
            blocked_ip_count[client_ip] += 1
        log_request(client_ip, "<BLOCKED>", "denied (in DB)")
        abort(403)


@app.after_request
def classify_allowed(response) -> Any:
    """Executed after each request. Marks allowed requests exactly once for non‑excluded paths."""
    path = request.path or "/"
    if not (path in EXCLUDED_PATHS or path.startswith("/static/")):
        sc = response.status_code
        if (200 <= sc < 300 or sc == 304) and not g.get("allowed_counted"):
            stats.allowed()
            g.allowed_counted = True
    return response


# ---------------- Routes ---------------- #

@app.route("/metrics")
def metrics() -> Any:
    """Return system metrics and uptime."""
    up = get_uptime()
    cpu = get_cpu()
    ram = get_ram()
    disk = get_disk()
    # Provide both snake_case and camelCase keys for legacy front‑ends
    return jsonify({
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "uptime": up,
        "uptime_seconds": up["uptime_seconds"],
        "uptimeSeconds": up["uptime_seconds"],
        "ts": time.time(),
    })


@app.route("/stats")
def stats_json() -> Any:
    """Return firewall statistics including aliases for compatibility."""
    s = stats.to_dict()
    up = get_uptime()
    s["uptime"] = up
    s["uptime_seconds"] = up["uptime_seconds"]
    # Provide multiple alias keys
    ddos_count = s.get("ddos_blocks", 0)
    s.update({
        "ddos_blocks": ddos_count,
        "ddosBlocks": ddos_count,
        "DDoSBlocks": ddos_count,
    })
    ai_count = s.get("ai_based_blocks", 0)
    s.update({
        "ai_based_blocks": ai_count,
        "aiBasedBlocks": ai_count,
        "aiBlocks": ai_count,
        "AIBlocks": ai_count,
        "ai_blocks": ai_count,
    })
    net_count = s.get("network_blocks", 0)
    s.update({
        "network_blocks": net_count,
        "networkBlocks": net_count,
    })
    s["uptimeSeconds"] = up["uptime_seconds"]
    s["uptime_hms"] = f"{up['uptime_seconds']//3600}h {(up['uptime_seconds']%3600)//60}m {up['uptime_seconds']%60}s"
    s["uptime_formatted"] = up["formatted"]
    s["ddosConfig"] = {"window": ddos.time_window, "max": ddos.max_requests}  # type: ignore
    s["osEnforcement"] = {"mode": OS_METHOD, "ttl": BLOCK_TTL_SECONDS}
    return jsonify(s)


@app.route("/top_ips")
def top_ips() -> Any:
    """Return the top 5 blocked IPs by count."""
    with ipcount_lock:
        top5 = sorted(blocked_ip_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5))


@app.route("/top_requesting_ips")
def top_requesting_ips() -> Any:
    """Return the top 5 IPs by total request count (including allowed)."""
    with ipcount_lock:
        top5 = sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Simple login form using secureauth.verify_user."""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if secureauth.verify_user(username, password):
            session["user"] = username
            session.permanent = True
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout() -> Any:
    """Clear session and redirect to login."""
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))


def get_top_blocked(n: int = 5) -> Tuple[List[str], List[str]]:
    """Return the top n blocked IPs and their reasons from the DB."""
    try:
        active = db_blocker.get_active_blocks()
        # Sort by expiry descending (most recently blocked first)
        recent = sorted(active, key=lambda x: x[2], reverse=True)[:n]
        ips = [ip for ip, _, _ in recent]
        reasons = [reason for _, reason, _ in recent]
        return ips, reasons
    except Exception as e:
        logging.error(f"read top blocked error: {e}")
        return [], []


@app.route("/dashboard")
def dashboard() -> Any:
    """Render a simple dashboard showing recently blocked IPs."""
    if "user" not in session:
        flash("Login required", "error")
        return redirect(url_for("login"))
    ips, reasons = get_top_blocked(n=5)
    return render_template("dashboard.html", top_ips=ips, top_reasons=reasons)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def firewall_route(path: str) -> Any:
    """Catch‑all route that applies rate limiting, AI inspection and IP blocking."""
    client_ip = get_client_ip()
    body = request.get_data(cache=False, as_text=True) or ""
    referer = request.headers.get("Referer", "") or ""

    # Apply DDoS limiter for non‑excluded paths
    if not (request.path in EXCLUDED_PATHS or request.path.startswith("/static/")):
        if ddos.is_ddos(client_ip):
            stats.blocked()
            stats.bump("ddos_blocks")
            with ipcount_lock:
                blocked_ip_count[client_ip] += 1
            reason = "Rate limit exceeded"
            # Block in DB and OS
            try:
                db_blocker.block_ip(client_ip, reason=reason, ttl_seconds=BLOCK_TTL_SECONDS)
                os_enforce_add(client_ip, BLOCK_TTL_SECONDS)
            except Exception as e:
                logging.error(f"DDoS block OS/DB error for {client_ip}: {e}")
            log_request(client_ip, "<rate-limited>", reason)
            return jsonify({"status": "blocked", "reason": reason}), 429

    # Allow empty GET refreshes from dashboard or admin without inspection
    if (("user" in session) or ("/dashboard" in referer)) and request.method == "GET" and not body.strip():
        log_request(client_ip, body, "allowed (refresh)")
        return jsonify({"status": "allowed", "echo": body})

    # Perform AI inspection on all request components
    block, reason = should_block_request(client_ip, body)
    if block:
        stats.blocked()
        stats.bump("ai_based_blocks")
        with ipcount_lock:
            blocked_ip_count[client_ip] += 1
        try:
            db_blocker.block_ip(client_ip, reason=reason or "Malicious content", ttl_seconds=BLOCK_TTL_SECONDS)
            os_enforce_add(client_ip, BLOCK_TTL_SECONDS)
        except Exception as e:
            logging.error(f"AI block OS/DB error for {client_ip}: {e}")
        log_request(client_ip, body, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    # No rule triggered; allow
    log_request(client_ip, body, "allowed")
    return jsonify({"status": "allowed", "echo": body})


# ---------------- Network Sniffer ---------------- #

def ai_predict_packet(packet) -> bool:
    """Use AI classifier on raw packet payload to decide if it is malicious."""
    if packet and Raw and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            return ai_inspect(payload) != 0
        except Exception as e:
            logging.error(f"payload decode error: {e}")
    return False


def network_enforce_block(ip: str, reason: str) -> None:
    """Block an IP at DB and OS level due to network‑level detection."""
    try:
        db_blocker.block_ip(ip, reason=reason, ttl_seconds=BLOCK_TTL_SECONDS)
        os_enforce_add(ip, BLOCK_TTL_SECONDS)
        stats.bump("network_blocks")
        with ipcount_lock:
            blocked_ip_count[ip] += 1
    except Exception as e:
        logging.error(f"OS/DB block error for {ip}: {e}")


def process_packet(packet) -> None:
    """Callback for each sniffed packet. Applies AI classification on payload."""
    if not packet or not IP or not packet.haslayer(IP):
        return
    if ai_predict_packet(packet):
        src = packet[IP].src  # type: ignore
        logging.warning(f"Network AI detected malicious packet from {src}")
        network_enforce_block(src, "Network-level AI detection")


def start_sniffer() -> None:
    """Start a background thread to sniff IP packets using scapy, if available."""
    if not sniff:
        logging.warning("Scapy unavailable; network sniffing disabled.")
        return
    try:
        sniff(filter="ip", prn=process_packet, store=0)  # type: ignore
    except Exception as e:
        logging.error(f"sniffing error: {e}")


# ---------------- Main ---------------- #

if __name__ == "__main__":
    # Start network sniffer in background
    threading.Thread(target=start_sniffer, daemon=True).start()
    # Run the Flask app
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
