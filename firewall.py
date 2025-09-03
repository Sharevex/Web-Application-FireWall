#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Firewall (final, hardened)
--------------------------
- Network IPS/IDS (Scapy heuristic)
- App-layer WAF: DDoS limiter (thread-safe token bucket), rule + AI checks
- Live JSON endpoints + settings/dashboard/statistics pages
- MySQL-backed blocklist with OS sync (via MySQLIPBlocker; MSSQL alias kept for back-compat)
- Self-DDoS protections: limiter FIRST; smaller limiter for safe endpoints; admin-IP bypass
- SQLite-backed request/event history + Traffic Tap (/api/traffic/usage)

Env toggles (all optional):
  FW_BLOCK_TTL=300
  FW_DDOS_BLOCK_TTL=300
  FW_NET_BLOCK_TTL=600
  FW_DDOS_WINDOW=60
  FW_DDOS_MAX=20                  # baseline limit for unauthenticated
  FW_DDOS_AUTH_MAX=120            # higher per-minute limit for logged-in admins
  FW_DDOS_HARD_BLOCK_FACTOR=0     # 0=disabled; if >0, hard block when extreme bursts persist
  FW_TRUST_PROXY=1                # trust proxy headers (set to 0 if directly exposed)
  FW_TRUST_CLOUDFLARE=0           # only honor CF-Connecting-IP if traffic actually comes via CF
  FW_BLOCK_CACHE_SECS=10
  FW_LISTEN_HOST=0.0.0.0
  FW_LISTEN_PORT=8080
  FW_TICK_SECS=10                 # background ticker interval
  SAFE_GET_PATHS=metrics,stats,top_ips,top_blocked
  ADMIN_IPS=                      # comma-separated IPs or CIDRs (e.g., 203.0.113.10,10.0.0.0/8)
  FIREWALL_STATS_DB=firewall_stats.db
  FW_SECRET_KEY=change-this-in-prod
"""

import os
import sys
import re
import time
import threading
import logging
import sqlite3
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, List
from datetime import datetime, timezone

import psutil
from flask import (
    Flask, render_template, request, jsonify, session, flash, redirect, url_for, abort, g
)

# Optional Scapy
try:
    from scapy.all import sniff, IP, Raw
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# External modules (project-local)
import secureauth
from ai_detector import detect_attack
from os_detection import detect_os

# ---- DB blocker import with MySQL alias/back-compat ----
try:
    # Preferred
    from ip_blocker_db import MySQLIPBlocker as MSSQLIPBlocker  # alias name retained for minimal diff usage
except ImportError:
    # Fallback if module still exposes MSSQLIPBlocker old name
    from ip_blocker_db import MSSQLIPBlocker

# ----------------------------- Config -----------------------------
FW_BLOCK_TTL              = int(os.getenv("FW_BLOCK_TTL", "300"))
FW_DDOS_BLOCK_TTL         = int(os.getenv("FW_DDOS_BLOCK_TTL", "300"))
FW_NET_BLOCK_TTL          = int(os.getenv("FW_NET_BLOCK_TTL", "600"))
FW_DDOS_WINDOW            = int(os.getenv("FW_DDOS_WINDOW", "60"))
FW_DDOS_MAX               = int(os.getenv("FW_DDOS_MAX", "20"))
FW_DDOS_AUTH_MAX          = int(os.getenv("FW_DDOS_AUTH_MAX", "120"))
FW_DDOS_HARD_BLOCK_FACTOR = int(os.getenv("FW_DDOS_HARD_BLOCK_FACTOR", "0"))  # 0 disables hard block
FW_TRUST_PROXY            = os.getenv("FW_TRUST_PROXY", "1") == "1"
FW_TRUST_CLOUDFLARE       = os.getenv("FW_TRUST_CLOUDFLARE", "0") == "1"
FW_BLOCK_CACHE_SECS       = int(os.getenv("FW_BLOCK_CACHE_SECS", "10"))
FW_LISTEN_HOST            = os.getenv("FW_LISTEN_HOST", "0.0.0.0")
FW_LISTEN_PORT            = int(os.getenv("FW_LISTEN_PORT", "8080"))
FW_TICK_SECS              = int(os.getenv("FW_TICK_SECS", "10"))

SAFE_GET_PATHS            = set([p.strip() for p in os.getenv("SAFE_GET_PATHS", "metrics,stats,top_ips,top_blocked").split(",") if p.strip()])
ADMIN_IPS_RAW             = os.getenv("ADMIN_IPS", "").strip()

# SQLite stats DB path
DB_PATH                   = os.environ.get("FIREWALL_STATS_DB", "firewall_stats.db")

# ----------------------------- Logging -----------------------------
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("firewall")

# ----------------------------- IP/CIDR utils -----------------------------
def _parse_admin_ips(raw: str):
    items = []
    if not raw:
        return items
    for token in raw.split(","):
        t = token.strip()
        if not t:
            continue
        items.append(t)
    return items

def _ip_in_cidr(ip: str, cidr: str) -> bool:
    # very small helper to avoid extra deps; supports /8.. /32 ipv4
    try:
        if "/" not in cidr:
            return ip == cidr
        net, bits = cidr.split("/", 1)
        bits = int(bits)
        def ip2int(s): return sum(int(o) << (24 - 8*i) for i, o in enumerate(s.split(".")))
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (ip2int(ip) & mask) == (ip2int(net) & mask)
    except Exception:
        return False

ADMIN_IPS = _parse_admin_ips(ADMIN_IPS_RAW)

# ----------------------------- Globals -----------------------------
current_os = detect_os()
ip_request_count: Dict[str, int] = defaultdict(int)
blocked_ips: set = set()
blocked_event_count: Dict[str, int] = defaultdict(int)

db_blocker = MSSQLIPBlocker(default_ttl_seconds=FW_BLOCK_TTL, sync_interval_sec=30)

# Flask app
app = Flask(__name__)
app.config["DEBUG"] = False
app.secret_key = os.getenv("FW_SECRET_KEY", "change-this-in-prod")

if FW_TRUST_PROXY:
    try:
        from werkzeug.middleware.proxy_fix import ProxyFix
        # if you have CF->nginx->app, you may want x_for=2
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
        logger.info("ProxyFix enabled.")
    except Exception as e:
        logger.warning(f"ProxyFix not applied: {e}")

# Hardened client IP resolver
def get_client_ip() -> str:
    if not FW_TRUST_PROXY:
        return request.remote_addr or "unknown"

    if FW_TRUST_CLOUDFLARE:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip

    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()

    return request.remote_addr or "unknown"

# ---------------------- Block cache refresher ----------------------
_last_block_refresh = 0.0
def refresh_block_cache(force: bool = False) -> None:
    global _last_block_refresh, blocked_ips
    now = time.time()
    if not force and (now - _last_block_refresh) < FW_BLOCK_CACHE_SECS:
        return
    try:
        rows = db_blocker.get_active_blocks()  # [(ip, reason, expires_at)]
        blocked_ips = {ip for (ip, _, _) in rows}
        _last_block_refresh = now
        logger.debug(f"Block cache refreshed: {len(blocked_ips)} active")
    except Exception as e:
        logger.error(f"Block cache refresh failed: {e}")

db_blocker.start_background_sync()
refresh_block_cache(force=True)

# ------------------------------ Stats DB ---------------------------
def init_stats_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,              -- unix seconds
            ip TEXT,
            action TEXT CHECK (action IN ('allowed','blocked')) NOT NULL,
            reason TEXT,
            bytes_in INTEGER DEFAULT 0,
            bytes_out INTEGER DEFAULT 0,
            user_agent TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_reason ON events(reason)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")
    db.commit()
    db.close()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

# ------------------------------ Traffic Tap ------------------------------
def _ensure_traffic_tables(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         INTEGER NOT NULL,
            ip         TEXT,
            method     TEXT,
            path       TEXT,
            status     INTEGER,
            action     TEXT,
            bytes_in   INTEGER DEFAULT 0,
            bytes_out  INTEGER DEFAULT 0,
            user_agent TEXT
        )
    """)
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_log(ts);""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_traffic_ip ON traffic_log(ip);""")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_totals (
            ip         TEXT PRIMARY KEY,
            hits       INTEGER NOT NULL DEFAULT 0,
            total_in   INTEGER NOT NULL DEFAULT 0,
            total_out  INTEGER NOT NULL DEFAULT 0,
            first_seen INTEGER,
            last_seen  INTEGER
        )
    """)
    conn.commit()

def record_traffic(ip: str, method: str, path: str, status: int, action: str,
                   bytes_in: int, bytes_out: int, user_agent: str = "") -> None:
    ts = int(time.time())
    try:
        conn = sqlite3.connect(DB_PATH)
        _ensure_traffic_tables(conn)
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO traffic_log(ts, ip, method, path, status, action, bytes_in, bytes_out, user_agent) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, ip, method, path, int(status), action, int(bytes_in or 0), int(bytes_out or 0), user_agent or "")
        )

        cur.execute("""
            INSERT INTO ip_totals(ip, hits, total_in, total_out, first_seen, last_seen)
            VALUES(?, 1, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              hits      = hits + 1,
              total_in  = total_in  + excluded.total_in,
              total_out = total_out + excluded.total_out,
              last_seen = excluded.last_seen
        """, (ip, int(bytes_in or 0), int(bytes_out or 0), ts, ts))

        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug(f"record_traffic failed: {e}")

def get_traffic_usage(hours: int | None = None, top: int = 10) -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _ensure_traffic_tables(conn)
    cur = conn.cursor()

    if hours and hours > 0:
        since = int(time.time()) - hours * 3600
        row = cur.execute("""
            SELECT COALESCE(SUM(bytes_in),0) AS tin,
                   COALESCE(SUM(bytes_out),0) AS tout,
                   COUNT(*) AS hits
            FROM traffic_log WHERE ts >= ?
        """, (since,)).fetchone()
        top_rows = cur.execute("""
            SELECT ip,
                   COALESCE(SUM(bytes_in),0)  AS tin,
                   COALESCE(SUM(bytes_out),0) AS tout,
                   COUNT(*) AS hits
            FROM traffic_log
            WHERE ts >= ?
            GROUP BY ip
            ORDER BY (tin+tout) DESC
            LIMIT ?
        """, (since, top)).fetchall()
    else:
        row = cur.execute("""
            SELECT COALESCE(SUM(total_in),0)  AS tin,
                   COALESCE(SUM(total_out),0) AS tout,
                   COALESCE(SUM(hits),0)      AS hits
            FROM ip_totals
        """).fetchone()
        top_rows = cur.execute("""
            SELECT ip, total_in AS tin, total_out AS tout, hits
            FROM ip_totals
            ORDER BY (total_in+total_out) DESC
            LIMIT ?
        """, (top,)).fetchall()

    out = {
        "bytes_in": int(row["tin"] or 0),
        "bytes_out": int(row["tout"] or 0),
        "bytes_total": int((row["tin"] or 0) + (row["tout"] or 0)),
        "hits": int(row["hits"] or 0),
        "top": [{"ip": r["ip"], "bytes_in": int(r["tin"] or 0), "bytes_out": int(r["tout"] or 0),
                 "bytes_total": int((r["tin"] or 0) + (r["tout"] or 0)), "hits": int(r["hits"] or 0)} for r in top_rows]
    }
    conn.close()
    return out

@app.after_request
def traffic_tap(response):
    """Transparent tap: runs for *every* request."""
    try:
        ip      = get_client_ip()
        method  = request.method
        path    = request.path
        status  = response.status_code
        ua      = request.headers.get("User-Agent", "")

        # inbound bytes
        bytes_in = request.content_length or 0
        if not bytes_in:
            try:
                raw = request.get_data(cache=False, as_text=False)
                bytes_in = len(raw or b"")
            except Exception:
                bytes_in = 0

        # outbound bytes
        bytes_out = response.calculate_content_length()
        if bytes_out is None:
            try:
                bytes_out = len(response.get_data())
            except Exception:
                bytes_out = 0

        action = 'blocked' if status in (403, 429) else 'allowed'
        record_traffic(ip, method, path, status, action, bytes_in, bytes_out, ua)
    except Exception as e:
        logger.debug(f"traffic_tap error: {e}")
    return response

@app.get("/api/traffic/usage")
def api_traffic_usage():
    hours = request.args.get("hours")
    try:
        hours_i = int(hours) if hours is not None else None
    except Exception:
        hours_i = None
    return jsonify(get_traffic_usage(hours_i))

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def _insert_event(conn, ts: int, action: str, ip: str, reason: str,
                  bytes_in: int, bytes_out: int, user_agent: str):
    conn.execute(
        "INSERT INTO events(ts, ip, action, reason, bytes_in, bytes_out, user_agent) VALUES(?,?,?,?,?,?,?)",
        (ts, ip, action, reason, int(bytes_in or 0), int(bytes_out or 0), user_agent)
    )
    conn.commit()

def log_event(action: str, ip: str, reason: str = None,
              bytes_in: int = 0, bytes_out: int = 0, user_agent: str = None):
    """Works in request context (uses Flask g)."""
    ts = int(time.time())
    try:
        try:
            conn = get_db()
            _insert_event(conn, ts, action, ip, reason, bytes_in, bytes_out, user_agent)
        except RuntimeError:
            conn = sqlite3.connect(DB_PATH)
            _insert_event(conn, ts, action, ip, reason, bytes_in, bytes_out, user_agent)
            conn.close()
    except Exception as e:
        logger.debug(f"log_event failed: {e}")

def log_event_bg(action: str, ip: str, reason: str = None,
                 bytes_in: int = 0, bytes_out: int = 0, user_agent: str = None):
    """Background-thread safe logger (no Flask g)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        _insert_event(conn, int(time.time()), action, ip, reason, bytes_in, bytes_out, user_agent)
        conn.close()
    except Exception as e:
        logger.debug(f"log_event_bg failed: {e}")

# --------------------------- DDoS limiter (token bucket) --------------------------
import threading as _threading

class TokenBucketLimiter:
    """
    Thread-safe per-IP (and optional per-path) token bucket.
    - capacity tokens per window seconds (~max burst)
    - refill at capacity/window tokens per second (~sustained RPS)
    """
    def __init__(self, capacity: int, window_sec: int, per_path: bool = True):
        self.capacity = max(1, capacity)
        self.window = max(1, window_sec)
        self.rate = self.capacity / self.window
        self.per_path = per_path
        self._state = defaultdict(lambda: {"tokens": self.capacity, "ts": time.monotonic()})
        self._locks = defaultdict(_threading.Lock)

    def _key(self, ip: str, path: str) -> str:
        return f"{ip}|{path}" if self.per_path else ip

    def allow(self, ip: str, path: str = "/") -> tuple[bool, int]:
        k = self._key(ip, path)
        lock = self._locks[k]
        with lock:
            now = time.monotonic()
            s = self._state[k]
            elapsed = max(0.0, now - s["ts"])
            s["ts"] = now
            # refill
            s["tokens"] = min(self.capacity, s["tokens"] + elapsed * self.rate)
            if s["tokens"] >= 1.0:
                s["tokens"] -= 1.0
                return True, int(s["tokens"])
            # negative remaining encodes how far below zero we are (useful for "extreme burst" heuristics)
            return False, int(s["tokens"])  # will be <= 0

# Two limiters: general + stricter for safe endpoints
ddos_limiter = TokenBucketLimiter(capacity=FW_DDOS_MAX, window_sec=FW_DDOS_WINDOW, per_path=True)
safe_limiter = TokenBucketLimiter(capacity=max(5, FW_DDOS_MAX // 4), window_sec=FW_DDOS_WINDOW, per_path=True)

# ------------------------------ Stats (in-memory quick) ------------------------------
class FirewallStats:
    def __init__(self) -> None:
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0
        self.ddos_blocks = 0
        self.rule_based_blocks = 0
        self.ai_based_blocks = 0
        self.network_blocks = 0
    def to_dict(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "allowed_requests": self.allowed_requests,
            "blocked_requests": self.blocked_requests,
            "ddos_blocks": self.ddos_blocks,
            "rule_based_blocks": self.rule_based_blocks,
            "ai_based_blocks": self.ai_based_blocks,
            "network_blocks": self.network_blocks,
        }

stats = FirewallStats()

# ------------------------- Rule-based detect -----------------------
attack_patterns = {
    "sql_injection":  r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bOR\s+1=1\b|\bWHERE\s+1=1\b|--)",
    "xss":            r"(<\s*script\b|alert\s*\(|onerror\s*=)",
    "path_traversal": r"(\.\./|\b/etc/passwd\b)",
}
def rule_based_detect(data: str) -> Tuple[bool, str]:
    if not data:
        return False, ""
    for attack, pattern in attack_patterns.items():
        if re.search(pattern, data, re.IGNORECASE):
            return True, attack
    return False, ""

# ---------------------- Network IPS/IDS (light) --------------------
def ml_predict_packet(packet) -> bool:
    if packet and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore").upper()
            if ("DROP TABLE" in payload) or ("SELECT * FROM" in payload) or (" OR 1=1" in payload):
                return True
        except Exception as exc:
            logger.debug(f"Payload decode error: {exc}")
    return False

def _apply_block(ip: str, reason: str, ttl: int) -> None:
    try:
        if ip in blocked_ips:
            return
        db_blocker.block_ip(ip, reason, ttl_seconds=ttl)
        blocked_ips.add(ip)
        blocked_event_count[ip] += 1
        logger.info(f"Blocked {ip} ({reason}) for {ttl}s")
    except Exception as e:
        logger.error(f"Failed to block {ip}: {e}")

def process_packet(packet):
    if not SCAPY_OK or not packet:
        return
    try:
        if not packet.haslayer(IP):
            return
        src_ip = packet[IP].src
        if ml_predict_packet(packet):
            _apply_block(src_ip, "Network-level malicious packet", FW_NET_BLOCK_TTL)
            stats.network_blocks += 1
            log_event_bg('blocked', src_ip, reason='network_packet')
    except Exception as e:
        logger.debug(f"process_packet error: {e}")

def start_packet_sniffing():
    if not SCAPY_OK:
        logger.warning("Scapy not available; network IPS/IDS disabled.")
        return
    try:
        logger.info("Starting Scapy sniffing thread…")
        sniff(filter="ip", prn=process_packet, store=0)
    except Exception as e:
        logger.error(f"Sniffer stopped: {e}")

# --------------------------- System metrics ------------------------
def get_cpu_usage():
    return {"total": psutil.cpu_percent(interval=0.5), "cores": psutil.cpu_count(logical=True)}

def get_uptime():
    boot = psutil.boot_time()
    up = int(time.time() - boot)
    d, r = divmod(up, 86400); h, r = divmod(r, 3600); m, s = divmod(r, 60)
    return {"uptime_seconds": up, "formatted": f"{d}d {h}h {m}m {s}s"}

def get_ram_usage():
    mem = psutil.virtual_memory()
    return {
        "total": round(mem.total / (1024**3), 2),
        "used": round(mem.used / (1024**3), 2),
        "free": round(mem.available / (1024**3), 2),
        "percent": mem.percent,
    }

def get_disk_usage():
    try:
        u = psutil.disk_usage('/')
        return [{
            "device": "root", "mountpoint": "/", "total": round(u.total/(1024**3),2),
            "used": round(u.used/(1024**3),2), "free": round(u.free/(1024**3),2), "percent": u.percent
        }]
    except Exception:
        return []

# ------------------------------ Routes -----------------------------
@app.before_request
def deny_blocked_ips():
    refresh_block_cache(force=False)
    client_ip = get_client_ip()
    if client_ip in blocked_ips:
        ua = request.headers.get("User-Agent", "")
        log_event('blocked', client_ip, reason='db_active_block', bytes_in=(request.content_length or 0), user_agent=ua)
        log_request_details(client_ip, "<BLOCKED>", "denied (active in DB)")
        abort(403)

@app.route("/metrics")
def metrics():
    return jsonify({
        "cpu": get_cpu_usage(),
        "ram": get_ram_usage(),
        "disk": get_disk_usage(),
        "uptime": get_uptime(),
        "timestamp": time.time()
    })

@app.route("/settings")
def settings_page():
    if "user" not in session:
        flash("You must be logged in to access settings.", "error")
        return redirect(url_for("login"))
    return render_template("settings.html")

# ---------- Blocks/Admins APIs ----------
@app.route("/api/blocks", methods=["GET"])
def api_list_blocks():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    rows = db_blocker.get_active_blocks()
    blocks = []
    for ip, reason, expires_at in rows:
        if isinstance(expires_at, datetime):
            expires = expires_at.replace(tzinfo=timezone.utc).isoformat()
        else:
            expires = str(expires_at)
        blocks.append({"ip": ip, "reason": reason or "", "expires_at": expires})
    return jsonify({"blocks": blocks})

@app.route("/api/blocks", methods=["POST"])
def api_add_block():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = (data.get("reason") or "Manual block").strip()
    ttl = int(data.get("ttl") or 300)
    if not ip:
        return jsonify({"error": "ip required"}), 400
    db_blocker.block_ip(ip, reason, ttl_seconds=ttl)
    refresh_block_cache(force=True)
    log_event('blocked', ip, reason='manual_block', user_agent=request.headers.get("User-Agent", ""))
    return jsonify({"status": "ok"})

@app.route("/api/blocks/<ip>", methods=["DELETE"])
def api_del_block(ip):
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    db_blocker.unblock_ip(ip)
    refresh_block_cache(force=True)
    return jsonify({"status": "ok"})

@app.route("/api/blocks/<ip>", methods=["PUT"])
def api_update_block(ip):
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    new_reason = (data.get("reason") or "").strip()
    try:
        if hasattr(db_blocker, "update_reason"):
            db_blocker.update_reason(ip, new_reason)
        else:
            db_blocker.unblock_ip(ip)
            db_blocker.block_ip(ip, new_reason, ttl_seconds=300)
        refresh_block_cache(force=True)
        return jsonify({"status": "ok"})
    except Exception as e:
        logging.error(f"update block for {ip} failed: {e}")
        return jsonify({"error": "update failed"}), 500

@app.route("/api/admins", methods=["GET"])
def api_list_admins():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    try:
        admins = secureauth.list_admins()
        normalized = []
        for a in admins or []:
            if isinstance(a, dict):
                normalized.append({"username": a.get("username"), "created_at": a.get("created_at")})
            else:
                username = a[0]
                created_at = a[1] if len(a) > 1 else None
                normalized.append({"username": username, "created_at": created_at})
        return jsonify({"admins": normalized})
    except AttributeError:
        return jsonify({"admins": []})

@app.route("/api/admins", methods=["POST"])
def api_add_admin():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    try:
        ok = getattr(secureauth, "create_admin")(username, password)
        if not ok:
            return jsonify({"error": "create_admin failed"}), 500
        return jsonify({"status": "ok"})
    except Exception as e:
        logging.error(f"create_admin failed: {e}")
        return jsonify({"error": "create_admin failed"}), 500

@app.route("/api/admins/<username>", methods=["DELETE"])
def api_del_admin(username):
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    try:
        secureauth.delete_admin(username)
        return jsonify({"status": "ok"})
    except Exception as e:
        logging.error(f"delete_admin failed: {e}")
        return jsonify({"error": "delete_admin failed"}), 500

@app.route("/api/admins/<username>/password", methods=["PUT"])
def api_admin_reset_password(username):
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    password = (data.get("password") or "").strip()
    if not password or len(password) < 6:
        return jsonify({"error": "password too short"}), 400

    try:
        if hasattr(secureauth, "set_password"):
            ok = secureauth.set_password(username, password)
            if not ok:
                return jsonify({"error": "set_password failed"}), 500
        elif hasattr(secureauth, "reset_password"):
            ok = secureauth.reset_password(username, password)
            if not ok:
                return jsonify({"error": "reset_password failed"}), 500
        elif hasattr(secureauth, "update_admin_password"):
            ok = secureauth.update_admin_password(username, password)
            if not ok:
                return jsonify({"error": "update_admin_password failed"}), 500
        else:
            try:
                secureauth.delete_admin(username)
            except Exception:
                pass
            ok = secureauth.create_admin(username, password)
            if not ok:
                return jsonify({"error": "recreate admin failed"}), 500

        logger.info(f"Admin password updated for {username}")
        return jsonify({"status": "ok"})
    except Exception as e:
        logging.error(f"reset password failed for {username}: {e}")
        return jsonify({"error": "reset failed"}), 500

# ---------- Quick stats JSON ----------
@app.route("/stats")
def stats_endpoint():
    return jsonify(stats.to_dict())

@app.route("/top_ips")
def top_ips():
    top5 = sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5))

@app.route("/top_blocked")
def top_blocked():
    top5 = sorted(blocked_event_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5))

# ---------- Auth ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if secureauth.verify_user(username, password):
                session["user"] = username
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password", "error")
        except Exception as exc:
            flash(f"Login error: {exc}", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    accepts_html = request.accept_mimetypes.accept_html and \
                   request.accept_mimetypes['text/html'] >= request.accept_mimetypes['application/json']
    if accepts_html and request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return redirect(url_for("login"))
    return jsonify({"status": "ok"})

# ---------- Pages ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("You must be logged in to access the dashboard.", "error")
        return redirect(url_for("login"))
    ips, reasons = get_top_blocked_ips_and_reasons()
    try:
        return render_template("dashboard.html", top_ips=ips, top_reasons=reasons)
    except Exception:
        return jsonify({
            "message": "Dashboard template not found – create templates/dashboard.html to enable the UI.",
            "stats": stats.to_dict(),
            "top_ips": dict(sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5])
        })

@app.get("/statistics")
def statistics_page():
    if "user" not in session:
        flash("You must be logged in to access statistics.", "error")
        return redirect(url_for("login"))
    return render_template("statistics.html", page_title="Statistics")

# ---------- Statistics APIs ----------
@app.get("/api/statistics/summary")
def api_statistics_summary():
    db = get_db()
    now = int(time.time())
    since_24h = now - 24*3600

    total = db.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    allowed = db.execute("SELECT COUNT(*) AS c FROM events WHERE action='allowed'").fetchone()["c"]
    blocked = total - allowed

    total_24 = db.execute("SELECT COUNT(*) AS c FROM events WHERE ts>=?", (since_24h,)).fetchone()["c"]
    allowed_24 = db.execute("SELECT COUNT(*) AS c FROM events WHERE ts>=? AND action='allowed'", (since_24h,)).fetchone()["c"]
    blocked_24 = total_24 - allowed_24

    row = db.execute("""
        SELECT COALESCE(reason,'(none)') AS reason, COUNT(*) AS c
        FROM events
        WHERE ts>=? AND action='blocked'
        GROUP BY reason
        ORDER BY c DESC
        LIMIT 1
    """, (since_24h,)).fetchone()
    top_reason_24 = (row["reason"], row["c"]) if row else (None, 0)

    return jsonify({
        "overall": {"total": total, "allowed": allowed, "blocked": blocked},
        "last_24h": {"total": total_24, "allowed": allowed_24, "blocked": blocked_24},
        "top_reason_24h": {"reason": top_reason_24[0], "count": top_reason_24[1]}
    })

@app.get("/api/statistics/timeseries")
def api_statistics_timeseries():
    try:
        hours = max(1, int(request.args.get("hours", 24)))
        bucket = max(10, min(int(request.args.get("bucket_sec", 60)), 3600))  # 10s..1h
    except Exception:
        hours, bucket = 24, 60

    now = int(time.time())
    since = now - hours*3600

    db = get_db()
    rows = db.execute("""
        SELECT CAST(ts / ? AS INTEGER) * ? AS t,
               COUNT(*) AS total,
               SUM(CASE WHEN action='allowed' THEN 1 ELSE 0 END) AS allowed,
               SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked,
               SUM(bytes_in)  AS bytes_in,
               SUM(bytes_out) AS bytes_out
        FROM events
        WHERE ts >= ?
        GROUP BY CAST(ts / ? AS INTEGER)
        ORDER BY t ASC
    """, (bucket, bucket, since, bucket)).fetchall()

    data = [{
        "t": int(r["t"]),
        "total": int(r["total"]),
        "allowed": int(r["allowed"] or 0),
        "blocked": int(r["blocked"] or 0),
        "bytes_in": int(r["bytes_in"] or 0),
        "bytes_out": int(r["bytes_out"] or 0)
    } for r in rows]

    return jsonify({"since": since, "now": now, "bucket_sec": bucket, "points": data})

@app.get("/api/statistics/top")
def api_statistics_top():
    what = request.args.get("what", "ips")
    try:
        limit = min(50, max(1, int(request.args.get("limit", 10))))
    except Exception:
        limit = 10
    hours = request.args.get("hours")

    since_clause = ""
    params = []
    if hours:
        try:
            hours_int = max(1, int(hours))
            since = int(time.time()) - hours_int*3600
            since_clause = " AND ts>=? "
            params.append(since)
        except Exception:
            pass

    db = get_db()
    if what == "reasons":
        q = f"""
            SELECT COALESCE(reason,'(none)') AS key, COUNT(*) AS c
            FROM events
            WHERE action='blocked' {since_clause}
            GROUP BY reason
            ORDER BY c DESC
            LIMIT ?
        """
    else:
        q = f"""
            SELECT COALESCE(ip,'(unknown)') AS key, COUNT(*) AS c
            FROM events
            WHERE action='blocked' {since_clause}
            GROUP BY ip
            ORDER BY c DESC
            LIMIT ?
        """
    params.append(limit)
    rows = db.execute(q, tuple(params)).fetchall()
    out = [{"key": r["key"], "count": r["c"]} for r in rows]
    return jsonify({"what": what, "items": out})

# ------------------- Core firewall route (WAF) ---------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def firewall_route(path):
    client_ip = get_client_ip()
    stats.total_requests += 1
    ip_request_count[client_ip] += 1

    ua = request.headers.get("User-Agent", "")
    data = request.get_data(as_text=True) or ""
    bytes_in = request.content_length or len(data.encode("utf-8"))

    # 1) admin IPs: always allow
    if any(_ip_in_cidr(client_ip, cidr) for cidr in ADMIN_IPS):
        stats.allowed_requests += 1
        log_event('allowed', client_ip, reason='admin_ip', bytes_in=bytes_in, user_agent=ua)
        log_request_details(client_ip, data, "allowed (admin IP)")
        return jsonify({"status": "allowed", "echo": data})

    # 2) global limiter FIRST (strict)
    ok, remaining = ddos_limiter.allow(client_ip, request.path)
    if not ok:
        stats.blocked_requests += 1
        stats.ddos_blocks += 1
        # optional hard block if over extreme factor (interpret remaining <= -factor as sustained drain)
        if FW_DDOS_HARD_BLOCK_FACTOR > 0 and remaining <= -(FW_DDOS_HARD_BLOCK_FACTOR):
            _apply_block(client_ip, "DDoS (extreme burst)", FW_DDOS_BLOCK_TTL)
            log_event('blocked', client_ip, reason='ddos_hard', bytes_in=bytes_in, user_agent=ua)
            log_request_details(client_ip, "<rate-limited>", "hard-blocked (extreme burst)")
            return jsonify({"status": "blocked", "reason": "DDoS hard block"}), 403
        log_event('blocked', client_ip, reason='rate_limit', bytes_in=bytes_in, user_agent=ua)
        log_request_details(client_ip, "<rate-limited>", "throttled (soft)")
        return jsonify({"status": "throttled", "reason": "rate limit"}), 429

    # 3) authenticated users: allow (after one token was consumed)
    if "user" in session:
        stats.allowed_requests += 1
        log_event('allowed', client_ip, reason='authenticated', bytes_in=bytes_in, user_agent=ua)
        log_request_details(client_ip, data, "allowed (authenticated)")
        return jsonify({"status": "allowed", "echo": data})

    # 4) safe GETs: allow but under a *smaller* limiter (prevents dashboard/metrics floods)
    if request.method == "GET":
        p = request.path.lstrip("/")
        if (p in SAFE_GET_PATHS) or (not data.strip()):
            ok2, _ = safe_limiter.allow(client_ip, request.path)
            if not ok2:
                stats.blocked_requests += 1
                stats.ddos_blocks += 1
                log_event('blocked', client_ip, reason='safe_path_rate_limit', bytes_in=bytes_in, user_agent=ua)
                log_request_details(client_ip, "<rate-limited>", "throttled (safe path)")
                return jsonify({"status": "throttled", "reason": "rate limit (safe path)"}), 429
            stats.allowed_requests += 1
            log_event('allowed', client_ip, reason='safe_get', bytes_in=bytes_in, user_agent=ua)
            log_request_details(client_ip, data, "allowed (safe GET)")
            return jsonify({"status": "allowed", "echo": data})

    # Rule-based & AI checks (after limiter)
    rule_flag, attack_type = rule_based_detect(data)
    ai_label = 0
    try:
        ai_label = detect_attack(data)  # 0=benign, 1=SQLi, 2=XSS, 3=DDoS, etc.
    except Exception as e:
        logger.error(f"AI detect_attack error: {e}")

    if ai_label != 0:
        stats.blocked_requests += 1
        stats.ai_based_blocks += 1
        reason = {1: "SQLi (AI)", 2: "XSS (AI)", 3: "DDoS (AI)"}.get(ai_label, "Anomaly (AI)")
        _apply_block(client_ip, reason, FW_BLOCK_TTL)
        log_event('blocked', client_ip, reason=f'ai:{reason}', bytes_in=bytes_in, user_agent=ua)
        log_request_details(client_ip, data, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    if rule_flag:
        stats.blocked_requests += 1
        stats.rule_based_blocks += 1
        reason = attack_type
        _apply_block(client_ip, reason, FW_BLOCK_TTL)
        log_event('blocked', client_ip, reason=f'rule:{reason}', bytes_in=bytes_in, user_agent=ua)
        log_request_details(client_ip, data, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    # Allowed
    stats.allowed_requests += 1
    log_event('allowed', client_ip, reason='passed', bytes_in=bytes_in, user_agent=ua)
    log_request_details(client_ip, data, "allowed")
    return jsonify({"status": "allowed", "echo": data})

# ---------------------------- Helpers ------------------------------
def log_request_details(ip: str, data: str, result: str) -> None:
    try:
        with open("firewall.log", "a", encoding="utf-8") as f:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            # avoid logging giant payloads
            snippet = data if len(data) <= 2048 else (data[:2048] + "...<truncated>")
            f.write(f"{ts} | {ip} | {result} | {snippet}\n")
    except Exception as exc:
        logger.debug(f"Log write error: {exc}")

def get_top_blocked_ips_and_reasons(n: int = 5) -> Tuple[List[str], List[str]]:
    try:
        rows = db_blocker.get_active_blocks()
        recent = rows[-n:] if len(rows) > n else rows
        ips = [ip for ip, _, _ in recent]
        reasons = [reason or "Unknown" for _, reason, _ in recent]
        return ips, reasons
    except Exception as e:
        logger.error(f"Failed to get top blocked IPs: {e}")
        try:
            with open("blocked.txt", "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            recent = lines[-n:]
            ips = [r.split(",", 1)[0] for r in recent]
            reasons = [r.split(",", 1)[1] if "," in r else "Unknown" for r in recent]
            return ips, reasons
        except FileNotFoundError:
            return [], []

def print_statistics() -> None:
    sep = "-" * 48
    logger.info(f"{sep}\n[DYNAMIC UPDATE @ {time.strftime('%H:%M:%S')}]\n{sep}")
    for k, v in stats.to_dict().items():
        logger.info(f"{k.replace('_', ' ').title():22}: {v}")
    top5 = sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    if top5:
        logger.info("Top 5 requester IPs:")
        for ip, cnt in top5:
            logger.info(f"  {ip:>15} -> {cnt}")
    logger.info(sep)

def dynamic_update() -> None:
    while True:
        time.sleep(FW_TICK_SECS)
        print_statistics()
        refresh_block_cache(force=False)

def run_server() -> None:
    logger.info(f"Starting Flask server on {FW_LISTEN_HOST}:{FW_LISTEN_PORT}")
    # debug False in production; reloader disabled due to threads
    app.run(host=FW_LISTEN_HOST, port=FW_LISTEN_PORT, debug=False, use_reloader=False, threaded=True)

def deployment_helper() -> None:
    print("\n=== Deployment Summary ===")
    print(f"Operating System  : {current_os}")
    print(f"Network IPS/IDS   : {'ACTIVE' if SCAPY_OK else 'DISABLED (Scapy missing)'}")
    print(f"Flask Web Server  : http://{FW_LISTEN_HOST}:{FW_LISTEN_PORT}")
    print("Dashboard         : /dashboard")
    print("Settings          : /settings")
    print("Statistics        : /statistics")
    print("Stats JSON        : /stats")
    print("Metrics JSON      : /metrics")
    print("Top requesters    : /top_ips")
    print("Top blocked       : /top_blocked")
    print("Stats API (sum)   : /api/statistics/summary")
    print("Stats API (series): /api/statistics/timeseries")
    print("Stats API (top)   : /api/statistics/top")
    print("Traffic usage     : /api/traffic/usage")
    print("Log File          : firewall.log")
    print("Blocked IPs DB    : MySQL (with TTL + OS sync)")
    print("SQLite Stats DB   :", DB_PATH)
    print("===========================================\n")

# ------------------------------- Main ------------------------------
if __name__ == "__main__":
    # Initialize stats DB before threads start
    init_stats_db()

    sniff_thread = threading.Thread(target=start_packet_sniffing, daemon=True)
    sniff_thread.start()

    dyn_thread = threading.Thread(
        target=lambda: (time.sleep(2), deployment_helper(), dynamic_update()),
        daemon=True
    )
    dyn_thread.start()

    flask_thread = threading.Thread(target=run_server, daemon=True)
    flask_thread.start()

    print(f"Firewall server running on http://{FW_LISTEN_HOST}:{FW_LISTEN_PORT}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down...")
        try:
            db_blocker.stop_background_sync()
        except Exception:
            pass
        sys.exit(0)
