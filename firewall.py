#!/usr/bin/env python3
"""
firewall.py
-----------
Combined Firewall:
- Web firewall (Flask) with DDoS prevention, AI/rule-based detection
- Network IPS/IDS using Scapy (safe-fallback if unavailable)
- Blocked IPs persisted in MySQL (via MySQLIPBlocker)
- Live dashboard & metrics
"""

import os
import sys
import re
import time
import threading
import logging
from collections import defaultdict, deque
from datetime import timedelta
from threading import Lock

import psutil
import numpy as np
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, session, flash, abort
)

# Paths we don't want to count as "requests" on the dashboard
EXCLUDED_PATHS = {
    "/favicon.ico",
    "/metrics",
    "/stats",
    "/top_ips",
    "/login",
    "/dashboard",
}
def _is_excluded_path(path: str) -> bool:
    """Exclude static assets and known system/dashboard endpoints from counting."""
    if path in EXCLUDED_PATHS:
        return True
    if path.startswith("/static/"):
        return True
    return False

# Scapy soft-fallback
try:
    from scapy.all import sniff, IP, TCP, Raw
except Exception as e:
    sniff = None
    IP = TCP = Raw = None
    print("[firewall] ⚠ Scapy not available:", e)

import secureauth
from ai_detector import detect_attack
from ip_blocker_db import MySQLIPBlocker
from os_detection import detect_os

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
current_os = detect_os()
ip_request_count = defaultdict(int)
stats_lock = Lock()

class DDoSRateLimiter:
    def __init__(self, time_window=60, max_requests=20):
        self.time_window = time_window
        self.max_requests = max_requests
        self.requests_log = defaultdict(deque)

    def is_ddos(self, ip: str) -> bool:
        now = time.time()
        dq = self.requests_log[ip]
        while dq and dq[0] < now - self.time_window:
            dq.popleft()
        if len(dq) >= self.max_requests:
            return True
        dq.append(now)
        return False

class FirewallStats:
    def __init__(self):
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0
        self.ddos_blocks = 0
        self.rule_based_blocks = 0
        self.ai_based_blocks = 0
        self.network_blocks = 0
    def to_dict(self):
        return self.__dict__

ddos_limiter = DDoSRateLimiter()
stats = FirewallStats()

# DB-backed IP blocker (MySQL)
db_blocker = MySQLIPBlocker(default_ttl_seconds=86400, sync_interval_sec=30)
db_blocker.start_background_sync()

# ---------------------------------------------------------------------------
# Flask app & session config
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY", "fallback_secret")

app.config.update(
    SESSION_COOKIE_NAME="fw_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,       # True if HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# ---------------------------------------------------------------------------
# Before-request: count + DB block
# ---------------------------------------------------------------------------
@app.before_request
def global_request_check():
    client_ip = request.remote_addr or "unknown"
    path = request.path

    # Count non-excluded requests here (works for allowed & blocked)
    if not _is_excluded_path(path):
        with stats_lock:
            stats.total_requests += 1
            ip_request_count[client_ip] += 1

    # DB-based blocking
    try:
        active_ips = {ip for ip, _, _ in db_blocker.get_active_blocks()}
    except Exception as e:
        logging.error(f"DB error reading active blocks: {e}")
        active_ips = set()

    if client_ip in active_ips:
        with stats_lock:
            stats.blocked_requests += 1
        log_request_details(client_ip, "<BLOCKED>", "denied (in DB)")
        abort(403)

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
attack_patterns = {
    "sql_injection": r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bOR\s+1=1\b|--)",
    "xss":           r"(<script>|alert\(|onerror=)",
    "path_traversal": r"(\.\./|\b/etc/passwd\b)",
}
def rule_based_detect(data: str):
    for attack, pattern in attack_patterns.items():
        if re.search(pattern, data, re.IGNORECASE):
            return True, attack
    return False, None

# ---------------------------------------------------------------------------
# Network IPS/IDS
# ---------------------------------------------------------------------------
def ml_predict(packet) -> bool:
    if packet and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            if any(kw in payload.upper() for kw in ("DROP TABLE", "SELECT * FROM", "OR 1=1")):
                return True
        except Exception as exc:
            logging.error(f"Payload decode error: {exc}")
    return False

def block_ip(ip: str, reason="Network-level IPS/IDS"):
    try:
        db_blocker.block_ip(ip, reason=reason)
        with stats_lock:
            stats.network_blocks += 1
    except Exception as e:
        logging.error(f"Error blocking IP {ip} at OS/DB level: {e}")

def process_packet(packet):
    if not (packet and packet.haslayer(IP)):
        return
    src_ip = packet[IP].src
    if ml_predict(packet):
        logging.warning(f"Network malicious packet from {src_ip}")
        block_ip(src_ip)

def start_packet_sniffing():
    if not sniff:
        logging.warning("Scapy not available – sniffing disabled.")
        return
    try:
        sniff(filter="ip", prn=process_packet, store=0)
    except Exception as e:
        logging.error(f"Sniffing failed: {e}")

# ---------------------------------------------------------------------------
# System Metrics
# ---------------------------------------------------------------------------
def get_cpu_usage():
    return {"total": psutil.cpu_percent(interval=1), "cores": psutil.cpu_count(logical=True)}

def get_ram_usage():
    m = psutil.virtual_memory()
    return {"total": round(m.total/(1024**3),2), "used": round(m.used/(1024**3),2),
            "free": round(m.free/(1024**3),2), "percent": m.percent}

def get_disk_usage():
    try:
        u = psutil.disk_usage('/')
        return [{"device":"root","mountpoint":"/","total":round(u.total/(1024**3),2),
                 "used": round(u.used /(1024**3),2), "free": round(u.free /(1024**3),2),
                 "percent":u.percent}]
    except Exception:
        return []

def get_uptime():
    boot = psutil.boot_time()
    secs = int(time.time() - boot)
    return {"uptime_seconds": secs}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/metrics")
def metrics():
    return jsonify({"cpu": get_cpu_usage(), "ram": get_ram_usage(), "disk": get_disk_usage(),
                    "uptime": get_uptime(), "timestamp": time.time()})

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username","")
        pw   = request.form.get("password","")
        if secureauth.verify_user(user, pw):
            session["user"] = user
            session.permanent = True
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "error")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    logging.info(f"[dashboard] session keys: {list(session.keys())}")
    if "user" not in session:
        flash("Login required", "error")
        return redirect(url_for("login"))
    top_ips, top_reasons = get_top_blocked_ips_and_reasons()
    return render_template("dashboard.html", top_ips=top_ips, top_reasons=top_reasons)

@app.route("/stats")
def stats_endpoint():
    try:
        return jsonify(stats.to_dict())
    except Exception as e:
        logging.error(f"/stats error: {e}")
        return jsonify({"error": "stats unavailable"}), 500

@app.route("/top_ips")
def top_ips():
    try:
        top5 = sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return jsonify(dict(top5))
    except Exception as e:
        logging.error(f"/top_ips error: {e}")
        return jsonify({"error": "top_ips unavailable"}), 500

@app.route("/", defaults={"path":""}, methods=["GET","POST"])
@app.route("/<path:path>", methods=["GET","POST"])
def firewall_route(path):
    client_ip = request.remote_addr or "unknown"

    # DDoS limiter
    if ddos_limiter.is_ddos(client_ip):
        with stats_lock:
            stats.blocked_requests += 1
            stats.ddos_blocks += 1
        reason = "DDoS rate-limit"
        try:
            db_blocker.block_ip(client_ip, reason)
        except Exception as e:
            logging.error(f"Error adding rate-limited IP {client_ip} to DB: {e}")
        log_request_details(client_ip, "<rate-limited>", reason)
        return jsonify({"status":"blocked","reason":reason}), 429

    data = request.get_data(as_text=True) or ""
    referer = request.headers.get("Referer","")

    if ('user' in session) or (referer and ('/dashboard' in referer or path in referer)):
        with stats_lock:
            stats.allowed_requests += 1
        log_request_details(client_ip, data, "allowed (session/refresh)")
        return jsonify({"status":"allowed","echo":data})

    if request.method == "GET" and not data.strip():
        with stats_lock:
            stats.allowed_requests += 1
        log_request_details(client_ip, data, "allowed (empty GET)")
        return jsonify({"status":"allowed","echo":data})

    rb, attack = rule_based_detect(data)
    if rb:
        with stats_lock:
            stats.blocked_requests += 1
            stats.rule_based_blocks += 1
        try:
            db_blocker.block_ip(client_ip, attack)
        except Exception as e:
            logging.error(f"Error blocking IP {client_ip} (rule): {e}")
        log_request_details(client_ip, data, f"blocked – {attack}")
        return jsonify({"status":"blocked","reason":attack}), 403

    ai_label = detect_attack(data)
    if ai_label != 0:
        with stats_lock:
            stats.blocked_requests += 1
            stats.ai_based_blocks += 1
        reason = {1:"SQLi (AI)", 2:"XSS (AI)", 3:"DDoS (AI)"}.get(ai_label, "Anomaly (AI)")
        try:
            db_blocker.block_ip(client_ip, reason)
        except Exception as e:
            logging.error(f"Error blocking IP {client_ip} (AI): {e}")
        log_request_details(client_ip, data, f"blocked – {reason}")
        return jsonify({"status":"blocked","reason":reason}), 403

    with stats_lock:
        stats.allowed_requests += 1
    log_request_details(client_ip, data, "allowed")
    return jsonify({"status":"allowed","echo":data})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def log_request_details(ip, data, result):
    try:
        with open("firewall.log","a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {result} - {data}\n")
    except Exception as e:
        logging.error(f"Log write error: {e}")

def get_top_blocked_ips_and_reasons(n=5):
    try:
        active = db_blocker.get_active_blocks()
        recent = sorted(active, key=lambda x: x[2], reverse=True)[:n]
        return [ip for ip, _, _ in recent], [reason for _, reason, _ in recent]
    except Exception as e:
        logging.error(f"Error reading top blocked IPs: {e}")
        return [], []

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_packet_sniffing, daemon=True)
    sniff_thread.start()
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
