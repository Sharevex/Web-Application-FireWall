#!/usr/bin/env python3
"""
firewall.py
-----------
- Precise request counters (dashboard refreshes INCLUDED)
- DDoS limiter (env-tunable), AI inspection for ALL attacks
- Network IPS/IDS via Scapy (soft fallback)
- MySQL-backed IP blocking (MySQLIPBlocker) + OS-level auto-expiring blocks
- JSON endpoints: /stats, /top_ips, /metrics

ENV knobs (optional):
  FW_BLOCK_TTL=300            # default block TTL in seconds (DB + OS set) [default 300 = 5 min]
  FW_DDOS_WINDOW=60           # seconds window for DDoS rate limiter
  FW_DDOS_MAX=20              # max requests per window per IP
  FW_TRUST_PROXY=1            # 1 to trust one proxy hop via ProxyFix; 0 to disable
  FW_OS_MODE=auto             # 'auto' | 'nft' | 'ipset' | 'off'
"""

import os
import re
import time
import logging
import threading
import shutil
import subprocess
from datetime import timedelta
from collections import defaultdict, deque
from threading import Lock

import psutil
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash, session, abort, g
)
from werkzeug.middleware.proxy_fix import ProxyFix

# ---------------- Config ---------------- #
BLOCK_TTL_SECONDS = int(os.environ.get("FW_BLOCK_TTL", "300"))  # 5 minutes default
OS_MODE = os.environ.get("FW_OS_MODE", "auto").lower()          # auto | nft | ipset | off

# -------- Exclusions (not counted in totals) --------
EXCLUDED_PATHS = {
    "/favicon.ico",
    "/robots.txt",
    "/health",
    "/healthz",
    "/metrics",
    "/stats",
    "/top_ips",
    "/login",  # keep login out of totals; remove if you want it counted
    "/logout",  # Add logout to excluded paths
}
def is_excluded_path(path: str) -> bool:
    if path in EXCLUDED_PATHS:
        return True
    if path.startswith("/static/"):
        return True
    return False

# -------- Scapy (soft fallback) --------
try:
    from scapy.all import sniff, IP, Raw
except Exception as e:
    sniff = None
    IP = Raw = None
    print("[firewall] ⚠ Scapy not available:", e)

# -------- Local deps --------
from ip_blocker_db import MySQLIPBlocker
from ai_detector import detect_attack
import secureauth
from os_detection import detect_os

# -------- Logging --------
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# -------- Helpers: real client IP behind proxies/Cloudflare --------
def get_client_ip() -> str:
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    xr = request.headers.get("X-Real-IP")
    if xr:
        return xr
    return request.remote_addr or "unknown"

# -------- DDoS limiter (env-tunable) --------
class DDoSRateLimiter:
    def __init__(self, time_window=None, max_requests=None):
        time_window = time_window or int(os.environ.get("FW_DDOS_WINDOW", "60"))
        max_requests = max_requests or int(os.environ.get("FW_DDOS_MAX", "20"))
        self.time_window = time_window
        self.max_requests = max_requests
        self._log = defaultdict(deque)  # ip -> deque[timestamps]

    def is_ddos(self, ip: str) -> bool:
        now = time.time()
        dq = self._log[ip]
        while dq and dq[0] < now - self.time_window:
            dq.popleft()
        if len(dq) >= self.max_requests:
            return True
        dq.append(now)
        return False

# -------- Stats (thread-safe) - REMOVED rule_based_blocks --------
class Stats:
    def __init__(self):
        self._lock = Lock()
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0
        self.ddos_blocks = 0
        self.ai_based_blocks = 0
        self.network_blocks = 0

    def _inc(self, field: str, n: int = 1):
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def total(self):   self._inc("total_requests")
    def allowed(self): self._inc("allowed_requests")
    def blocked(self): self._inc("blocked_requests")
    def bump(self, field: str): self._inc(field)

    def to_dict(self):
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "allowed_requests": self.allowed_requests,
                "blocked_requests": self.blocked_requests,
                "ddos_blocks": self.ddos_blocks,
                "ai_based_blocks": self.ai_based_blocks,
                "network_blocks": self.network_blocks,
            }

# -------- Helper function to format uptime --------
def format_uptime(seconds):
    """Format uptime seconds into human readable string"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m {secs}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"

# -------- Globals --------
current_os = detect_os()
ddos = DDoSRateLimiter()
stats = Stats()

# FIXED: Separate tracking for blocked IPs vs all requests
ip_request_count = defaultdict(int)      # All IP requests (for general stats)
blocked_ip_count = defaultdict(int)      # Only blocked IPs (for top blocked display)
ipcount_lock = Lock()

# MySQL-backed blocker
db_blocker = MySQLIPBlocker(default_ttl_seconds=BLOCK_TTL_SECONDS, sync_interval_sec=30)
db_blocker.start_background_sync()

# -------- Flask --------
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "fallback_secret")
app.config.update(
    SESSION_COOKIE_NAME="fw_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,     # set True behind HTTPS/terminator
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# Trust one proxy hop by default (disable with FW_TRUST_PROXY=0)
if os.environ.get("FW_TRUST_PROXY", "1") != "0":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# -------- OS-level enforcement (ipset/nft) --------
OS_METHOD = "off"  # resolved at runtime: 'nft', 'ipset', 'off'

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def setup_os_enforcement(ttl_seconds: int):
    """Pick and prepare an OS enforcement backend with per-entry auto-expiry."""
    global OS_METHOD
    mode = OS_MODE
    if mode == "off":
        OS_METHOD = "off"
        logging.info("OS enforcement disabled (FW_OS_MODE=off).")
        return

    # auto-detect
    if mode == "auto":
        if have("nft"):
            mode = "nft"
        elif have("ipset") and have("iptables"):
            mode = "ipset"
        else:
            mode = "off"

    if mode == "nft":
        if not have("nft"):
            logging.warning("nft not available; falling back to ipset/iptables if present.")
        else:
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

    if mode == "ipset":
        if not (have("ipset") and have("iptables")):
            logging.warning("ipset/iptables not available; OS enforcement disabled.")
            OS_METHOD = "off"
            return
        subprocess.run(["ipset", "create", "fw_blocked", "hash:ip", "timeout", str(ttl_seconds), "-exist"], check=False)
        # ensure iptables rule exists
        probe = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"])
        if probe.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "fw_blocked", "src", "-j", "DROP"], check=False)
        OS_METHOD = "ipset"
        logging.info(f"OS enforcement: ipset+iptables with timeout {ttl_seconds}s")
        return

    OS_METHOD = "off"
    logging.info("OS enforcement not enabled (no supported backend found).")

def os_enforce_add(ip: str, ttl_seconds: int):
    """Add IP to the OS-level block set with TTL."""
    if OS_METHOD == "nft" and have("nft"):
        # add element with per-entry timeout
        cmd = ["nft", "add", "element", "inet", "filter", "fw_blocked", f"{ip} timeout {ttl_seconds}s"]
        subprocess.run(cmd, check=False)
    elif OS_METHOD == "ipset" and have("ipset"):
        subprocess.run(["ipset", "add", "fw_blocked", ip, "timeout", str(ttl_seconds), "-exist"], check=False)
    else:
        # OS enforcement off or unavailable
        pass

# FIXED: Helper function to track blocked IPs
def track_blocked_ip(ip: str):
    """Track an IP that was blocked (separate from general request tracking)"""
    with ipcount_lock:
        blocked_ip_count[ip] += 1

# Initialize OS enforcement with the same TTL as DB
setup_os_enforcement(BLOCK_TTL_SECONDS)

# -------- Before-request: COUNT ONCE + DB block --------
@app.before_request
def before_every_request():
    path = request.path or "/"
    client_ip = get_client_ip()

    g.allowed_counted = False  # prevent double-bumps

    # 1) Count every non-excluded request exactly once
    if not is_excluded_path(path):
        stats.total()
        with ipcount_lock:
            ip_request_count[client_ip] += 1

    # 2) Deny if IP is DB-blocked
    try:
        active_ips = {ip for ip, _, _ in db_blocker.get_active_blocks()}
    except Exception as e:
        logging.error(f"DB error reading active blocks: {e}")
        active_ips = set()

    if client_ip in active_ips:
        stats.blocked()
        track_blocked_ip(client_ip)  # FIXED: Track as blocked IP
        log_request(client_ip, "<BLOCKED>", "denied (in DB)")
        abort(403)

# -------- After-request: classify allowed exactly once --------
@app.after_request
def classify_allowed(response):
    if not is_excluded_path(request.path or "/"):
        sc = response.status_code
        if (200 <= sc < 300 or sc == 304) and not g.allowed_counted:
            stats.allowed()
            g.allowed_counted = True
    return response

# -------- AI detection wrapper (safer logging) --------
def ai_inspect(text: str) -> int:
    try:
        code = detect_attack(text)
        logging.info(f"ai_detector returned {code}")
        return int(code) if code is not None else 0
    except Exception as e:
        logging.error(f"ai_detector error: {e}")
        return 0

# -------- AI inspection for ALL endpoints --------
def ai_inspect_all_content(client_ip: str, request_data: str) -> bool:
    """
    Use AI detector for ALL content inspection.
    Returns True if should block, False if should allow.
    """
    # Check URL path
    path = request.path or "/"
    if ai_inspect(path) != 0:
        logging.warning(f"AI detected malicious path from {client_ip}: {path}")
        return True
    
    # Check query parameters
    query_string = request.query_string.decode('utf-8', errors='ignore')
    if query_string and ai_inspect(query_string) != 0:
        logging.warning(f"AI detected malicious query from {client_ip}: {query_string}")
        return True
    
    # Check request body/data
    if request_data and ai_inspect(request_data) != 0:
        logging.warning(f"AI detected malicious body from {client_ip}: {request_data[:100]}...")
        return True
    
    # Check headers for common attack vectors
    suspicious_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
    for header_name in suspicious_headers:
        header_value = request.headers.get(header_name, '')
        if header_value and ai_inspect(header_value) != 0:
            logging.warning(f"AI detected malicious {header_name} from {client_ip}: {header_value}")
            return True
    
    return False

# -------- Network IPS/IDS (Scapy) - UPDATED to use AI --------
def ai_predict_packet(packet) -> bool:
    """Use AI detector for packet inspection"""
    if packet and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            return ai_inspect(payload) != 0
        except Exception as e:
            logging.error(f"payload decode error: {e}")
    return False

def network_enforce_block(ip: str, reason: str):
    try:
        db_blocker.block_ip(ip, reason=reason)
        os_enforce_add(ip, BLOCK_TTL_SECONDS)
        track_blocked_ip(ip)  # FIXED: Track as blocked IP
        stats.bump("network_blocks")
    except Exception as e:
        logging.error(f"OS/DB block error for {ip}: {e}")

def process_packet(packet):
    if not (packet and IP and packet.haslayer(IP)):
        return
    if ai_predict_packet(packet):
        src = packet[IP].src
        logging.warning(f"Network AI detected malicious packet from {src}")
        network_enforce_block(src, "Network-level AI detection")

def start_sniffer():
    if not sniff:
        logging.warning("Scapy unavailable; disabling sniffing.")
        return
    try:
        sniff(filter="ip", prn=process_packet, store=0)
    except Exception as e:
        logging.error(f"sniffing error: {e}")

# -------- System metrics --------
psutil.cpu_percent(None)  # prime so interval=None is non-blocking

def get_cpu():
    return {"total": psutil.cpu_percent(interval=None), "cores": psutil.cpu_count(logical=True)}

def get_ram():
    m = psutil.virtual_memory()
    return {
        "total": round(m.total/(1024**3), 2),
        "used":  round(m.used /(1024**3), 2),
        "free":  round(m.free /(1024**3), 2),
        "percent": m.percent,
    }

def get_disk():
    try:
        u = psutil.disk_usage("/")
        return [{
            "device": "root", "mountpoint": "/",
            "total": round(u.total/(1024**3), 2),
            "used":  round(u.used /(1024**3), 2),
            "free":  round(u.free /(1024**3), 2),
            "percent": u.percent,
        }]
    except Exception:
        return []

def get_uptime():
    bt = psutil.boot_time()
    uptime_secs = int(time.time() - bt)
    return {
        "uptime_seconds": uptime_secs,
        "formatted": format_uptime(uptime_secs)  # Add formatted version
    }

# -------- Routes --------
@app.route("/metrics")
def metrics():
    up = get_uptime()
    cpu = get_cpu()
    ram = get_ram()
    disk = get_disk()
    # Include snake_case and camelCase keys for UI compatibility
    return jsonify({
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "uptime": up,  # This now includes both uptime_seconds and formatted
        "uptime_seconds": up["uptime_seconds"],
        "uptimeSeconds": up["uptime_seconds"],  # alias
        "ts": time.time(),
    })

@app.route("/stats")
def stats_json():
    s = stats.to_dict()
    up = get_uptime()
    s["uptime"] = up
    s["uptime_seconds"] = up["uptime_seconds"]
    
    # COMPREHENSIVE ALIASES for frontend compatibility
    # DDoS blocks
    ddos_count = s.get("ddos_blocks", 0)
    s["ddosBlocks"] = ddos_count
    s["ddos_blocks"] = ddos_count
    s["DDoSBlocks"] = ddos_count
    
    # AI-based blocks  
    ai_count = s.get("ai_based_blocks", 0)
    s["aiBasedBlocks"] = ai_count
    s["ai_based_blocks"] = ai_count  
    s["aiBlocks"] = ai_count
    s["AIBlocks"] = ai_count
    s["ai_blocks"] = ai_count
    
    # Network blocks
    net_count = s.get("network_blocks", 0)
    s["networkBlocks"] = net_count
    s["network_blocks"] = net_count
    
    s["uptimeSeconds"] = up["uptime_seconds"]
    s["uptime_hms"] = f"{up['uptime_seconds']//3600}h {(up['uptime_seconds']%3600)//60}m {up['uptime_seconds']%60}s"
    s["uptime_formatted"] = up["formatted"]  # Add formatted version
    
    # Config info
    s["ddosConfig"] = {"window": ddos.time_window, "max": ddos.max_requests}
    s["osEnforcement"] = {"mode": OS_METHOD, "ttl": BLOCK_TTL_SECONDS}
    
    return jsonify(s)

# FIXED: Return actual blocked IPs instead of all request IPs
@app.route("/top_ips")
def top_ips():
    with ipcount_lock:
        # Return top 5 BLOCKED IPs, not all requesting IPs
        top5_blocked = sorted(blocked_ip_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5_blocked))

# OPTIONAL: Add endpoint for general request statistics
@app.route("/top_requesting_ips")
def top_requesting_ips():
    """Show top requesting IPs (including legitimate ones)"""
    with ipcount_lock:
        top5_requests = sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5_requests))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if secureauth.verify_user(u, p):
            session["user"] = u
            session.permanent = True
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")

# ADD MISSING LOGOUT ROUTE
@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Login required", "error")
        return redirect(url_for("login"))
    ips, reasons = get_top_blocked(n=5)
    return render_template("dashboard.html", top_ips=ips, top_reasons=reasons)

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def firewall_route(path):
    client_ip = get_client_ip()
    body = request.get_data(cache=False, as_text=True) or ""
    referer = request.headers.get("Referer", "") or ""

    # DDoS limiter applies to all non-excluded hits (already counted in before_request)
    if not is_excluded_path(request.path or "/") and ddos.is_ddos(client_ip):
        stats.blocked()
        stats.bump("ddos_blocks")
        track_blocked_ip(client_ip)  # FIXED: Track as blocked IP
        reason = "DDoS rate-limit"
        # block at DB + OS with same TTL
        try:
            db_blocker.block_ip(client_ip, reason=reason)
            os_enforce_add(client_ip, BLOCK_TTL_SECONDS)
        except Exception as e:
            logging.error(f"DDoS block OS/DB error for {client_ip}: {e}")
        log_request(client_ip, "<rate-limited>", reason)
        return jsonify({"status": "blocked", "reason": reason}), 429

    # Allow only empty GET refreshes from the dashboard without inspection
    if ("user" in session or "/dashboard" in referer) and request.method == "GET" and not body.strip():
        log_request(client_ip, body, "allowed (admin/refresh GET)")
        return jsonify({"status": "allowed", "echo": body})

    # AI inspection for ALL content (path, query, body, headers)
    if ai_inspect_all_content(client_ip, body):
        stats.blocked()
        stats.bump("ai_based_blocks")
        track_blocked_ip(client_ip)  # FIXED: Track as blocked IP
        
        # Determine the specific type of attack detected
        ai_code = ai_inspect(body) or ai_inspect(request.path or "/") or ai_inspect(request.query_string.decode('utf-8', errors='ignore'))
        reason = {1: "SQLi (AI)", 2: "XSS (AI)", 3: "DDoS (AI)"}.get(ai_code, "Malicious Content (AI)")
        
        try:
            db_blocker.block_ip(client_ip, reason=reason)
            os_enforce_add(client_ip, BLOCK_TTL_SECONDS)
        except Exception as e:
            logging.error(f"AI block OS/DB error for {client_ip}: {e}")
        log_request(client_ip, body, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    # Allowed (normal pass)
    log_request(client_ip, body, "allowed")
    return jsonify({"status": "allowed", "echo": body})

# -------- Helpers --------
def log_request(ip: str, data: str, result: str):
    try:
        with open("firewall.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {result} - {data}\n")
    except Exception as e:
        logging.error(f"log write error: {e}")

def get_top_blocked(n=5):
    try:
        active = db_blocker.get_active_blocks()  # [(ip, reason, expires_at), ...]
        recent = sorted(active, key=lambda x: x[2], reverse=True)[:n]
        ips = [ip for ip, _, _ in recent]
        reasons = [reason for _, reason, _ in recent]
        return ips, reasons
    except Exception as e:
        logging.error(f"read top blocked error: {e}")
        return [], []

# -------- Main --------
if __name__ == "__main__":
    threading.Thread(target=start_sniffer, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
