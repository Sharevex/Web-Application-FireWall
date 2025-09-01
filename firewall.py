
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI-Powered Web Application Firewall (final)
- DDoS limiter
- AI inspection (path/query/body/headers)
- MySQL-backed TTL blocks + optional OS enforcement
- Admin login + dashboard + admin block/unblock
- Network sniffer hardened (HTTP-only, TLS ignored, escalation)
"""

from __future__ import annotations

import os
import sys
import time
import logging
import shutil
import subprocess
from datetime import timedelta, datetime
from collections import defaultdict, deque
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, Tuple

import psutil
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session

try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    _PROXY = True
except Exception:
    _PROXY = False

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

# Local deps
from ai_detector import detect_attack
from ip_blocker_db import MySQLIPBlocker
import secureauth


# =========================
# Config
# =========================

class FirewallConfig:
    BLOCK_TTL = int(os.getenv("FW_BLOCK_TTL", "300"))
    DDOS_WINDOW = int(os.getenv("FW_DDOS_WINDOW", "60"))
    DDOS_MAX_REQUESTS = int(os.getenv("FW_DDOS_MAX", "20"))
    TRUST_PROXY = os.getenv("FW_TRUST_PROXY", "1") == "1"
    OS_MODE = os.getenv("FW_OS_MODE", "auto").lower()
    DEBUG = os.getenv("FW_DEBUG", "0") == "1"
    SECRET_KEY = os.getenv("APP_SECRET_KEY") or os.urandom(32).hex()
    SESSION_HOURS = 12

    ENABLE_NET = _SCAPY and os.getenv("FW_NETWORK_MONITOR", "1") == "1"
    DB_APPLIES_OS = os.getenv("DB_APPLIES_OS", "1") == "1"

    ADMIN_ALLOWLIST = {ip.strip() for ip in os.getenv("FW_ADMIN_ALLOWLIST", "").split(",") if ip.strip()}

    ADMIN_RATE_WINDOW = int(os.getenv("FW_ADMIN_RATE_WINDOW", "300"))
    ADMIN_RATE_MAX = int(os.getenv("FW_ADMIN_RATE_MAX", "10"))

    EXCLUDED = {
        "/favicon.ico", "/robots.txt", "/health", "/healthz", "/ping",
        "/metrics", "/stats", "/top_ips", "/top_requesting_ips",
        "/login", "/logout", "/dashboard"
    }

    @staticmethod
    def excluded(path: str) -> bool:
        if not path:
            return True
        if path in FirewallConfig.EXCLUDED:
            return True
        return any(path.startswith(p) for p in ("/static/", "/assets/", "/css/", "/js/", "/images/", "/img/", "/fonts/"))

LOG = logging.getLogger("firewall")
if not LOG.handlers:
    logging.basicConfig(level=logging.DEBUG if FirewallConfig.DEBUG else logging.INFO,
                        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

# =========================
# Stats & limiters
# =========================

class Stats:
    def __init__(self):
        self._lock = Lock()
        self._t0 = time.time()
        self.total = 0
        self.allowed = 0
        self.blocked = 0
        self.ddos_blocks = 0
        self.ai_blocks = 0
        self.net_blocks = 0
        self.ip_hits = defaultdict(int)
        self.ip_block_hits = defaultdict(int)
        self._rts = deque(maxlen=1000)
        self.avg_rt = 0.0
    def inc(self, field, n=1):
        with self._lock:
            setattr(self, field, getattr(self, field, 0)+n)
    def hit(self, ip):
        with self._lock:
            self.ip_hits[ip]+=1
    def hit_block(self, ip):
        with self._lock:
            self.ip_block_hits[ip]+=1
    def rt(self, sec):
        with self._lock:
            self._rts.append(sec)
            self.avg_rt = sum(self._rts)/len(self._rts)
    def uptime(self):
        return int(time.time()-self._t0)
    def top_hits(self, k=5):
        with self._lock:
            return sorted(self.ip_hits.items(), key=lambda x:x[1], reverse=True)[:k]
    def to_dict(self):
        return {
            "total_requests": self.total, "allowed_requests": self.allowed, "blocked_requests": self.blocked,
            "ddos_blocks": self.ddos_blocks, "ai_blocks": self.ai_blocks, "network_blocks": self.net_blocks,
            "avg_response_time": round(self.avg_rt, 4), "uptime_seconds": self.uptime(),
            "config": {
                "block_ttl": FirewallConfig.BLOCK_TTL,
                "ddos": [FirewallConfig.DDOS_MAX_REQUESTS, FirewallConfig.DDOS_WINDOW],
                "network_monitor": FirewallConfig.ENABLE_NET,
                "db_applies_os": FirewallConfig.DB_APPLIES_OS
            }
        }

class SlidingWindow:
    def __init__(self, window_s: int, max_hits: int):
        self.w = window_s; self.m = max_hits
        self.d = defaultdict(deque); self._lock = Lock()
    def _prune(self, dq, now):
        while dq and now - dq[0] >= self.w: dq.popleft()
    def hit(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            dq = self.d[key]; self._prune(dq, now)
            if len(dq) >= self.m: return True
            dq.append(now); return False
    def count(self, key: str) -> int:
        now = time.time()
        with self._lock:
            dq = self.d[key]; self._prune(dq, now); return len(dq)

stats = Stats()
ddos = SlidingWindow(FirewallConfig.DDOS_WINDOW, FirewallConfig.DDOS_MAX_REQUESTS)
admin_limit = SlidingWindow(FirewallConfig.ADMIN_RATE_WINDOW, FirewallConfig.ADMIN_RATE_MAX)

# Network escalation
NET_ESCALATE_WINDOW = int(os.getenv("FW_NET_ESCALATE_WINDOW", "30"))
NET_ESCALATE_HITS = int(os.getenv("FW_NET_ESCALATE_HITS", "3"))
net_escalate = SlidingWindow(NET_ESCALATE_WINDOW, NET_ESCALATE_HITS)

# =========================
# Helpers
# =========================

def client_ip() -> str:
    cf = request.headers.get("CF-Connecting-IP", "").strip()
    if cf: return cf
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff: return xff.split(",")[0].strip()
    xr = request.headers.get("X-Real-IP", "").strip()
    if xr: return xr
    return request.remote_addr or "unknown"

def is_allowlisted(ip: str) -> bool:
    return ip in FirewallConfig.ADMIN_ALLOWLIST

def sys_metrics() -> Dict[str, Any]:
    mem = psutil.virtual_memory(); disk = psutil.disk_usage("/")
    cpu = psutil.cpu_percent(interval=0.1)
    data = {
        "time": time.time(),
        "cpu": {"percent": round(cpu,1), "cores": psutil.cpu_count()},
        "memory": {"total_gb": round(mem.total/2**30,2), "used_gb": round(mem.used/2**30,2), "percent": round(mem.percent,1)},
        "disk": {"total_gb": round(disk.total/2**30,2), "used_gb": round(disk.used/2**30,2), "percent": round(disk.used/disk.total*100,1)},
    }
    try:
        net = psutil.net_io_counters()
        data["network"] = {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv}
    except Exception:
        pass
    return data

# HTTP/TLS heuristics for sniffer
def _looks_like_tls(payload: bytes) -> bool:
    if not payload or len(payload) < 3: return False
    return payload[0] == 0x16 and payload[1] == 0x03

def _ascii_ratio(s: str) -> float:
    if not s: return 1.0
    printable = sum(1 for ch in s if 32 <= ord(ch) <= 126 or ch in "\r\n\t")
    return printable / max(1, len(s))

def _looks_like_http_text(text: str) -> bool:
    if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/")):
        return True
    return _ascii_ratio(text) > 0.85

# =========================
# DB blocker
# =========================

db_blocker = MySQLIPBlocker(default_ttl_seconds=FirewallConfig.BLOCK_TTL, sync_interval_sec=30)
db_blocker.start_background_sync()

# =========================
# Flask app
# =========================

app = Flask(__name__)
app.secret_key = FirewallConfig.SECRET_KEY
app.config.update(
    SESSION_COOKIE_NAME="firewall_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=FirewallConfig.SESSION_HOURS),
    JSON_SORT_KEYS=False,
)
if FirewallConfig.TRUST_PROXY and _PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
if _TALISMAN:
    Talisman(app, content_security_policy=None)

# =========================
# Middleware
# =========================

@app.before_request
def _inbound():
    request._t0 = time.time()
    path = request.path or "/"
    if FirewallConfig.excluded(path):
        return None
    ip = client_ip()
    request._ip = ip
    # Allowlist bypass
    if is_allowlisted(ip):
        return None
    stats.inc("total"); stats.hit(ip)
    # DB block check
    try:
        active = {ip for (ip, _, _) in db_blocker.get_active_blocks()}
        if ip in active:
            stats.inc("blocked"); stats.hit_block(ip)
            return jsonify({"status":"blocked","reason":"IP on blocklist","ip":ip}), 403
    except Exception as e:
        LOG.error("DB check error: %s", e)

@app.after_request
def _outbound(resp):
    try:
        if hasattr(request, "_t0"):
            stats.rt(time.time()-request._t0)
    except Exception:
        pass
    resp.headers.setdefault("X-Content-Type-Options","nosniff")
    resp.headers.setdefault("X-Frame-Options","DENY")
    resp.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin")
    resp.headers.setdefault("X-XSS-Protection","1; mode=block")
    if not FirewallConfig.excluded(request.path or "/"):
        if 200 <= resp.status_code < 400:
            stats.inc("allowed")
    return resp

# =========================
# Routes
# =========================

@app.get("/stats")
def api_stats(): return jsonify(stats.to_dict())

@app.get("/metrics")
def api_metrics(): return jsonify(sys_metrics())

@app.get("/top_ips")
def api_top_ips():
    try: limit = min(int(request.args.get("limit",10)), 50)
    except Exception: limit = 10
    rows = sorted(db_blocker.get_active_blocks(), key=lambda x:x[2], reverse=True)[:limit]
    now = datetime.now()
    out = []
    for ip, reason, expires_at in rows:
        out.append({"ip": ip, "reason": reason, "expires_at": expires_at.isoformat(),
                    "expires_in": max(0, int((expires_at-now).total_seconds()))})
    return jsonify(out)

@app.get("/top_requesting_ips")
def api_top_req():
    try: limit = min(int(request.args.get("limit",10)), 50)
    except Exception: limit = 10
    return jsonify([{"ip": ip, "request_count": c} for ip, c in stats.top_hits(limit)])

@app.get("/health")
def health(): return jsonify({"status":"healthy","time": time.time(),"uptime": stats.uptime()})

# Auth & dashboard
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        if admin_limit.hit(ip):
            flash("Too many attempts. Try later.", "error")
            return render_template("login.html"), 429
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "").strip()
        if u and p and secureauth.verify_user(u,p):
            session["user"]=u; session["login_at"]=time.time(); session.permanent=True
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")

@app.get("/logout")
@app.post("/logout")
def logout():
    session.clear(); flash("Logged out.","info")
    return redirect(url_for("login"))

def require_login():
    if "user" not in session:
        flash("Please log in.", "error")
        return False
    return True

@app.get("/dashboard")
def dashboard():
    if not require_login(): return redirect(url_for("login"))
    try:
        return render_template("dashboard.html",
            stats=stats.to_dict(), metrics=sys_metrics(),
            top_blocked=sorted(db_blocker.get_active_blocks(), key=lambda x:x[2], reverse=True)[:5],
            top_requesting=stats.top_hits(5), user=session.get("user"))
    except Exception as e:
        flash(f"Dashboard error: {e}", "error")
        return render_template("dashboard.html", error=str(e))

# Admin actions
@app.post("/admin/block/<ip>")
def admin_block(ip: str):
    if not require_login(): return redirect(url_for("login"))
    if is_allowlisted(ip):
        flash(f"{ip} is allowlisted; skipped.", "info")
        return redirect(url_for("dashboard"))
    reason = request.form.get("reason","manual block")
    ttl = request.form.get("ttl")
    ttl_i = int(ttl) if ttl and ttl.isdigit() else FirewallConfig.BLOCK_TTL
    try:
        db_blocker.block_ip(ip, reason=reason, ttl_seconds=ttl_i)
        flash(f"Blocked {ip}", "success")
    except Exception as e:
        flash(f"Failed to block {ip}: {e}", "error")
    return redirect(url_for("dashboard"))

@app.post("/admin/unblock/<ip>")
def admin_unblock(ip: str):
    if not require_login(): return redirect(url_for("login"))
    if is_allowlisted(ip):
        flash(f"{ip} is allowlisted; skipped.", "info")
        return redirect(url_for("dashboard"))
    try:
        db_blocker.unblock_ip(ip); flash(f"Unblocked {ip}","success")
    except Exception as e:
        flash(f"Failed to unblock {ip}: {e}", "error")
    return redirect(url_for("dashboard"))

# Main WAF handler
@app.route("/", defaults={"subpath": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
@app.route("/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
def waf(subpath: str):
    path = f"/{subpath}" if subpath else "/"
    if FirewallConfig.excluded(path):
        return jsonify({"status":"allowed","reason":"excluded","path":path})
    ip = getattr(request, "_ip", None) or client_ip()
    if is_allowlisted(ip):
        return jsonify({"status":"allowed","reason":"allowlisted","path":path,"ip":ip})
    # DDoS limiter
    if ddos.hit(ip):
        stats.inc("blocked"); stats.inc("ddos_blocks"); stats.hit_block(ip)
        reason = f"Rate limit exceeded ({FirewallConfig.DDOS_MAX_REQUESTS}/{FirewallConfig.DDOS_WINDOW}s)"
        try: db_blocker.block_ip(ip, reason=reason, ttl_seconds=FirewallConfig.BLOCK_TTL)
        except Exception as e: LOG.error("ddos block fail %s", e)
        return jsonify({"status":"blocked","reason":reason,"ip":ip,"count":ddos.count(ip)}), 429
    # AI
    try:
        # Analyze path, query, body, headers
        def analyze(txt: str) -> int:
            try: return int(detect_attack(txt))
            except Exception: return 0
        # path
        if analyze(path): raise ValueError("path")
        # query
        qs = request.query_string.decode("utf-8","ignore")
        if qs and analyze(qs): raise ValueError("query")
        # body
        body = request.get_data(as_text=True, cache=False) or ""
        if body and analyze(body): raise ValueError("body")
        # headers
        for h in ("User-Agent","Referer","X-Forwarded-For","Cookie"):
            v = request.headers.get(h,"")
            if v and analyze(v): raise ValueError(f"header:{h}")
    except ValueError as where:
        stats.inc("blocked"); stats.inc("ai_blocks"); stats.hit_block(ip)
        reason = f"AI detected threat in {where}"
        try: db_blocker.block_ip(ip, reason=reason, ttl_seconds=FirewallConfig.BLOCK_TTL)
        except Exception as e: LOG.error("ai block fail %s", e)
        return jsonify({"status":"blocked","reason":reason,"ip":ip}), 403

    # Allowed
    echo = (body[:200]+"...") if body and len(body)>200 else (body or "")
    return jsonify({"status":"allowed","method":request.method,"path":path,"ip":ip,"timestamp": time.time(),"echo": echo})

# =========================
# Network monitor (hardened)
# =========================

class NetMon:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.running = False
        self.t: Optional[Thread] = None
    def start(self):
        if not self.enabled or self.running: return
        self.running = True
        self.t = Thread(target=self.loop, daemon=True); self.t.start()
        LOG.info("[net] monitor started")
    def stop(self):
        self.running = False
    def loop(self):
        try:
            sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080",
                  prn=self.on_packet, store=False, stop_filter=lambda p: not self.running)
        except Exception as e:
            LOG.error("[net] sniff error: %s", e)
    def on_packet(self, p):
        try:
            if not p.haslayer(IP) or not p.haslayer(Raw): return
            src = p[IP].src
            if is_allowlisted(src): return
            raw = p[Raw].load
            if not raw or len(raw) < 10: return
            if _looks_like_tls(raw): return
            try: text = raw.decode("utf-8","ignore")
            except Exception: return
            if not _looks_like_http_text(text): return
            # AI
            try: code = int(detect_attack(text))
            except Exception: code = 0
            if not code: return
            # Escalation
            if not net_escalate.hit(src):
                LOG.info(f"[net] suspicious {src} -> code={code} ({net_escalate.count(src)}/{NET_ESCALATE_HITS})")
                return
            stats.inc("blocked"); stats.inc("net_blocks"); stats.hit_block(src)
            reason = "Network threat"
            try: db_blocker.block_ip(src, reason=reason, ttl_seconds=FirewallConfig.BLOCK_TTL)
            except Exception as e: LOG.error("[net] block fail %s", e)
            LOG.warning(f"[net] {src} blocked -> {reason}")
        except Exception as e:
            LOG.debug("[net] analyze error: %s", e)

netmon = NetMon(FirewallConfig.ENABLE_NET)

# =========================
# Main
# =========================

def main():
    LOG.info("Starting AI WAF (final)")
    netmon.start()
    try:
        app.run(host="0.0.0.0", port=8080, debug=FirewallConfig.DEBUG, use_reloader=False, threaded=True)
    finally:
        netmon.stop()

if __name__ == "__main__":
    main()
