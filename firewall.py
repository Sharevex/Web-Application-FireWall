#!/usr/bin/env python3
import os
import sys
import time
import json
import shutil
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock, Thread
from typing import Any, Dict, List, Tuple

import psutil
from flask import (
    Flask, request, jsonify, render_template, redirect,
    url_for, flash, session, abort
)

# Optional imports
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    PROXY_FIX = True
except ImportError:
    PROXY_FIX = False

try:
    from scapy.all import sniff, IP, Raw
    SCAPY = True
except ImportError:
    SCAPY = False

# Local modules
try:
    from ai_detector import detect_attack
except ImportError:
    print("❌ ai_detector module not found!")
    sys.exit(1)

try:
    from ip_blocker_db import MySQLIPBlocker
except ImportError:
    print("❌ ip_blocker_db module not found!")
    sys.exit(1)

try:
    import secureauth
except ImportError:
    print("❌ secureauth module not found!")
    sys.exit(1)


class Config:
    BLOCK_TTL       = int(os.getenv("FW_BLOCK_TTL",      "300"))
    DDOS_WINDOW     = int(os.getenv("FW_DDOS_WINDOW",    "60"))
    DDOS_MAX        = int(os.getenv("FW_DDOS_MAX",       "20"))
    TRUST_PROXY     = os.getenv("FW_TRUST_PROXY",       "1") == "1"
    OS_MODE         = os.getenv("FW_OS_MODE",           "auto").lower()
    DEBUG           = os.getenv("FW_DEBUG",             "0") == "1"
    LOG_LEVEL       = logging.DEBUG      if DEBUG else logging.INFO
    SECRET_KEY      = os.getenv("APP_SECRET_KEY", "firewall-secret-key-2025")
    SESSION_HOURS   = 12
    NET_MONITOR     = SCAPY and os.getenv("FW_NETWORK_MONITOR", "1") == "1"
    EXCLUDED_PATHS  = {
        "/favicon.ico","/robots.txt","/health","/healthz","/ping",
        "/metrics","/stats","/top_ips","/top_requesting_ips",
        "/login","/logout"
    }
    STATIC_PREFIXES = ("/static/","/css/","/js/","/images/","/fonts/")

    @classmethod
    def is_excluded(cls, path:str)->bool:
        if not path or path in cls.EXCLUDED_PATHS:
            return True
        return any(path.startswith(p) for p in cls.STATIC_PREFIXES)


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("firewall")
    logger.setLevel(Config.LOG_LEVEL)
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-10s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # File
    try:
        fh = logging.FileHandler("firewall.log", encoding="utf-8")
        fh.setLevel(Config.LOG_LEVEL)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception as e:
        print(f"⚠️ Cannot open log file: {e}")

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger

logger = setup_logger()


class Stats:
    def __init__(self):
        self._lock = Lock()
        self.start = time.time()
        self.total = self.allowed = self.blocked = 0
        self.ddos_blocks = self.ai_blocks = self.net_blocks = 0
        self.ip_requests = defaultdict(int)
        self.ip_blocked  = defaultdict(int)
        self._times = deque(maxlen=1000)
        self.avg_time = 0.0

    def inc(self, field:str, by:int=1):
        with self._lock:
            setattr(self, field, getattr(self, field) + by)

    def track_req(self, ip:str):
        with self._lock:
            self.ip_requests[ip] += 1

    def track_block(self, ip:str):
        with self._lock:
            self.ip_blocked[ip] += 1

    def add_time(self, t:float):
        with self._lock:
            self._times.append(t)
            self.avg_time = sum(self._times)/len(self._times)

    def uptime(self)->int:
        return int(time.time() - self.start)

    def top_requests(self, n=5):
        with self._lock:
            return sorted(self.ip_requests.items(), key=lambda x:-x[1])[:n]

    def top_blocked(self, n=5):
        with self._lock:
            return sorted(self.ip_blocked.items(), key=lambda x:-x[1])[:n]

    def as_dict(self):
        u = self.uptime()
        cfg = {
            "block_ttl": Config.BLOCK_TTL,
            "ddos_window": Config.DDOS_WINDOW,
            "ddos_max": Config.DDOS_MAX,
            "network_monitor": Config.NET_MONITOR,
            "debug": Config.DEBUG
        }
        return {
            "total_requests": self.total,
            "allowed_requests": self.allowed,
            "blocked_requests": self.blocked,
            "ddos_blocks": self.ddos_blocks,
            "ai_blocks": self.ai_blocks,
            "net_blocks": self.net_blocks,
            "avg_response_time": round(self.avg_time,3),
            "uptime_seconds": u,
            "uptime": self._fmt_uptime(u),
            "config": cfg
        }

    @staticmethod
    def _fmt_uptime(sec:int)->str:
        if sec<60: return f"{sec}s"
        if sec<3600:
            m,s=divmod(sec,60)
            return f"{m}m {s}s"
        if sec<86400:
            h,r=divmod(sec,3600)
            m=r//60
            return f"{h}h {m}m"
        d,r=divmod(sec,86400)
        h=r//3600
        return f"{d}d {h}h"


class DDoS:
    def __init__(self, stats:Stats):
        self.win = Config.DDOS_WINDOW
        self.max = Config.DDOS_MAX
        self.map = defaultdict(deque)
        self.lock = Lock()
        self.stats = stats
        logger.info(f"DDoS: {self.max} req/{self.win}s")

    def is_attack(self, ip:str)->bool:
        now = time.time()
        dq = self.map[ip]
        with self.lock:
            # purge
            while dq and dq[0] <= now - self.win:
                dq.popleft()
            if len(dq) >= self.max:
                logger.warning(f"DDoS detected: {ip} ({len(dq)}/{self.win}s)")
                return True
            dq.append(now)
            return False

    def count(self, ip:str)->int:
        now = time.time()
        with self.lock:
            dq = self.map[ip]
            while dq and dq[0] <= now-self.win:
                dq.popleft()
            return len(dq)


class OSBlocker:
    def __init__(self):
        self.method = "off"
        self._init()

    def _init(self):
        mode = Config.OS_MODE
        if mode == "off":
            return
        if mode in ("auto","nft") and self._setup_nft():
            self.method = "nftables"
        elif mode in ("auto","iptables") and self._setup_ipt():
            self.method = "iptables"
        else:
            logger.warning("No OS block tool")
        if self.method != "off":
            logger.info(f"OSBlocker: {self.method}")

    def _setup_nft(self)->bool:
        if not shutil.which("nft"): return False
        cmds = [
            "nft add table inet fw",
            "nft add set inet fw blocked '{ type ipv4_addr; flags timeout; }'",
            "nft add chain inet fw input '{ type filter hook input priority 0; policy accept; }'",
            "nft insert rule inet fw input ip saddr @blocked drop"
        ]
        for c in cmds:
            subprocess.run(c.split(), capture_output=True, text=True)
        return True

    def _setup_ipt(self)->bool:
        if not (shutil.which("iptables") and shutil.which("ipset")):
            return False
        subprocess.run(
            ["ipset","create","fw_block","hash:ip","timeout",str(Config.BLOCK_TTL),"-exist"],
            capture_output=True
        )
        chk = subprocess.run(
            ["iptables","-C","INPUT","-m","set","--match-set","fw_block","src","-j","DROP"],
            capture_output=True
        )
        if chk.returncode!=0:
            subprocess.run(
                ["iptables","-I","INPUT","1","-m","set","--match-set","fw_block","src","-j","DROP"],
                capture_output=True
            )
        return True

    def block(self, ip:str, ttl:int=None)->bool:
        if self.method=="off": return True
        t = ttl or Config.BLOCK_TTL
        try:
            if self.method=="nftables":
                cmd = f"nft add element inet fw blocked {{ {ip} timeout {t}s }}"
                subprocess.run(cmd, shell=True, timeout=5)
            else:
                subprocess.run(
                    ["ipset","add","fw_block",ip,"timeout",str(t),"-exist"],
                    capture_output=True, timeout=5
                )
            logger.debug(f"OS blocked {ip} ({self.method})")
            return True
        except Exception as e:
            logger.error(f"OS block error {ip}: {e}")
            return False


class AI:
    def __init__(self):
        self.names = {
            0:"Benign",
            1:"SQL Injection",
            2:"Cross-Site Scripting (XSS)",
            3:"DDoS Attack"
        }
        # test
        detect_attack("test")
        logger.info("AI detector ready")

    def analyze(self, text:str)->Tuple[int,str]:
        if not text.strip():
            return 0,"Benign"
        code = detect_attack(text)
        if code is None:
            return 0,"Benign"
        try:
            code = int(code)
        except Exception:
            return 0,"Benign"
        desc = self.names.get(code,f"Unknown({code})")
        return code,desc

    def inspect(self, req)->Tuple[bool,str,str]:
        # path
        path = req.path or "/"
        c,d = self.analyze(path)
        if c!=0:
            return True,d,f"Path:{path}"
        qs = req.query_string.decode('utf-8',errors='ignore')
        if qs:
            c,d = self.analyze(qs)
            if c!=0:
                return True,d,f"Query:{qs}"
        try:
            body = req.get_data(as_text=True,cache=False) or ""
            if body:
                c,d = self.analyze(body)
                if c!=0:
                    snippet = (body[:200]+"...") if len(body)>200 else body
                    return True,d,f"Body:{snippet}"
        except Exception:
            pass
        for h in ("User-Agent","Referer","X-Forwarded-For","Cookie"):
            val = req.headers.get(h,"")
            if val:
                c,d = self.analyze(val)
                if c!=0:
                    return True,d,f"Header {h}:{val[:100]}"
        return False,"Benign",""


class NetMonitor:
    def __init__(self, stats:Stats, dbb, osb:OSBlocker):
        self.stats = stats
        self.dbb   = dbb
        self.osb   = osb
        self.ai    = AI()
        self.running = False
        self.thread  = None
        if not Config.NET_MONITOR:
            logger.info("Network monitor disabled")
        else:
            logger.info("Network monitor enabled")

    def start(self):
        if not Config.NET_MONITOR or self.running:
            return
        self.running = True
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("Network monitor started")

    def stop(self):
        self.running = False
        logger.info("Network monitor stopped")

    def _run(self):
        sniff(
            filter="tcp port 80 or tcp port 443 or tcp port 8080",
            prn=self._pkt, store=False,
            stop_filter=lambda x: not self.running
        )

    def _pkt(self, pkt):
        try:
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP].src
            raw = pkt[Raw].load.decode('utf-8',errors='ignore') if pkt.haslayer(Raw) else ""
            if len(raw.strip())<10:
                return
            code,desc = self.ai.analyze(raw)
            if code!=0:
                reason = f"Network {desc}"
                self.stats.inc("net_blocks")
                self.stats.track_block(ip)
                self.dbb.block_ip(ip, reason=reason)
                self.osb.block(ip)
                logger.info(f"Blocked network IP {ip}: {reason}")
        except Exception:
            pass


# UTILITIES
def client_ip():
    cf = request.headers.get("CF-Connecting-IP","").strip()
    if cf: return cf
    xff = request.headers.get("X-Forwarded-For","")
    if xff:
        return xff.split(",")[0].strip()
    xr = request.headers.get("X-Real-IP","").strip()
    if xr: return xr
    return request.remote_addr or "unknown"


def sys_metrics():
    try:
        cpu = psutil.cpu_percent(0.1)
        mem = psutil.virtual_memory()
        disk= psutil.disk_usage('/')
        try:
            net=psutil.net_io_counters()
            netd={"sent":net.bytes_sent,"recv":net.bytes_recv}
        except:
            netd={}
        return {
            "cpu": {"percent":cpu, "cores":psutil.cpu_count()},
            "memory": {
                "total":round(mem.total/1e9,2),
                "used": round(mem.used/1e9,2),
                "perc":mem.percent
            },
            "disk": {
                "total":round(disk.total/1e9,2),
                "used":round(disk.used/1e9,2),
                "perc":round(disk.used/disk.total*100,1)
            },
            "network": netd,
            "timestamp":time.time()
        }
    except Exception as e:
        logger.error(f"Metrics error: {e}")
        return {"error":str(e),"timestamp":time.time()}


# APP SETUP
stats    = Stats()
ddos     = DDoS(stats)
osb      = OSBlocker()
ai_det   = AI()
try:
    dbb = MySQLIPBlocker(default_ttl_seconds=Config.BLOCK_TTL, sync_interval_sec=30)
    dbb.start_background_sync()
    logger.info("DB blocker initialized")
except Exception as e:
    logger.error(f"DB blocker failed: {e}")
    sys.exit(1)

netmon = NetMonitor(stats, dbb, osb)

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config.update({
    "SESSION_COOKIE_NAME": "fw_session",
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SECURE": False,
    "SESSION_COOKIE_SAMESITE":"Lax",
    "PERMANENT_SESSION_LIFETIME": timedelta(hours=Config.SESSION_HOURS),
    "JSON_SORT_KEYS": False
})
if Config.TRUST_PROXY and PROXY_FIX:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    logger.info("Proxy support enabled")


@app.before_request
def before():
    request.start = time.time()
    ip = client_ip()
    request.client_ip = ip
    if Config.is_excluded(request.path):
        return
    stats.inc("total")
    stats.track_req(ip)
    try:
        active = { ip for ip,_,_ in dbb.get_active_blocks() }
        if ip in active:
            stats.inc("blocked")
            stats.track_block(ip)
            return jsonify({
                "status":"blocked",
                "reason":"IP blocked",
                "ip":ip
            }),403
    except Exception as e:
        logger.error(f"Block check error: {e}")


@app.after_request
def after(resp):
    if hasattr(request, "start"):
        stats.add_time(time.time()-request.start)
    if not Config.is_excluded(request.path):
        if 200<=resp.status_code<400:
            stats.inc("allowed")
    # security headers
    resp.headers.update({
        "X-Content-Type-Options":"nosniff",
        "X-Frame-Options":"DENY",
        "X-XSS-Protection":"1; mode=block",
        "Referrer-Policy":"strict-origin-when-cross-origin"
    })
    return resp


# API
@app.route("/stats")
def get_stats():
    return jsonify(stats.as_dict())


@app.route("/metrics")
def get_metrics():
    return jsonify(sys_metrics())


@app.route("/top_ips")
def top_ips():
    try:
        lim = min(int(request.args.get("limit",10)),50)
        blocks = dbb.get_active_blocks()
        # sort by expires descending
        blocks.sort(key=lambda x:x[2], reverse=True)
        result = []
        now = datetime.now()
        for ip,reason,exp in blocks[:lim]:
            sec = max(0,int((exp-now).total_seconds()))
            result.append({
                "ip":ip, "reason":reason,
                "expires_at":exp.isoformat(),
                "expires_in":sec
            })
        return jsonify(result)
    except Exception as e:
        logger.error(f"/top_ips error: {e}")
        return jsonify({"error":str(e)}),500


@app.route("/top_requesting_ips")
def top_req_ips():
    try:
        lim = min(int(request.args.get("limit",10)),50)
        top = stats.top_requests(lim)
        return jsonify([{"ip":ip,"count":c} for ip,c in top])
    except Exception as e:
        logger.error(f"/top_requesting_ips error: {e}")
        return jsonify({"error":str(e)}),500


@app.route("/health")
def health():
    return jsonify({
        "status":"healthy",
        "timestamp":time.time(),
        "uptime":stats.uptime()
    })


# Web UI
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        user = request.form.get("username","").strip()
        pwd  = request.form.get("password","").strip()
        if not user or not pwd:
            flash("Enter username & password","error")
            return render_template("login.html")
        try:
            if secureauth.verify_user(user,pwd):
                session["user"]=user
                session.permanent=True
                logger.info(f"Login success: {user}@{client_ip()}")
                return redirect(url_for("dashboard"))
            else:
                logger.warning(f"Login fail: {user}@{client_ip()}")
                flash("Invalid credentials","error")
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash("Auth system error","error")
    return render_template("login.html")


@app.route("/logout", methods=["GET","POST"])
def logout():
    u = session.get("user","?")
    session.clear()
    logger.info(f"Logout: {u}")
    flash("Logged out","info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Login required","error")
        return redirect(url_for("login"))
    try:
        st = stats.as_dict()
        mt = sys_metrics()
        blocks = dbb.get_active_blocks()
        blocks.sort(key=lambda x:x[2], reverse=True)
        topb = blocks[:5]
        topr = stats.top_requests(5)
        return render_template(
            "dashboard.html",
            stats=st, metrics=mt,
            top_blocked=topb, top_requesting=topr,
            user=session["user"]
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash("Dashboard load error","error")
        return render_template("dashboard.html", error=str(e))


# Main handler
@app.route("/", defaults={"path":""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
def main_handler(path):
    ip = client_ip()
    mth= request.method
    pth= "/" + path if path else "/"

    if Config.is_excluded(pth):
        return jsonify({
            "status":"allowed",
            "reason":"excluded",
            "path":pth,
            "method":mth
        })

    # DDoS
    if ddos.is_attack(ip):
        stats.inc("blocked")
        stats.inc("ddos_blocks")
        stats.track_block(ip)
        reason = f"Rate limit {ddos.max}/{ddos.win}s"
        dbb.block_ip(ip,reason=reason)
        osb.block(ip)
        logger.warning(f"DDoS block {ip}")
        return jsonify({
            "status":"blocked",
            "reason":reason,
            "ip":ip,
            "count":ddos.count(ip)
        }),429

    # AI
    bad,th,where = ai_det.inspect(request)
    if bad:
        stats.inc("blocked")
        stats.inc("ai_blocks")
        stats.track_block(ip)
        reason = f"AI:{th}"
        dbb.block_ip(ip,reason=reason)
        osb.block(ip)
        logger.warning(f"AI block {ip}: {reason}")
        return jsonify({
            "status":"blocked",
            "reason":reason,
            "ip":ip,
            "detected_in":where[:100] + ("..." if len(where)>100 else "")
        }),403

    # allowed
    try:
        body = request.get_data(as_text=True) or ""
    except:
        body = ""
    logger.info(f"Allowed {ip} {mth} {pth}")
    return jsonify({
        "status":"allowed",
        "method":mth,
        "path":pth,
        "ip":ip,
        "timestamp":time.time(),
        "echo":(body[:200] + "...") if len(body)>200 else body
    })


def init_firewall():
    logger.info("Initializing firewall v2.0.0")
    logger.info(f"Block TTL:{Config.BLOCK_TTL}s, DDoS:{Config.DDOS_MAX}/{Config.DDOS_WINDOW}s, OS:{osb.method}, NetMon:{Config.NET_MONITOR}, Debug:{Config.DEBUG}")
    netmon.start()
    logger.info("Initialization complete")


def shutdown_firewall():
    logger.info("Shutting down firewall")
    netmon.stop()
    logger.info("Shutdown complete")


def main():
    try:
        init_firewall()
        app.run(
            host="0.0.0.0",
            port=8080,
            debug=Config.DEBUG,
            use_reloader=False,
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("SIGINT received")
        shutdown_firewall()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        shutdown_firewall()
        sys.exit(1)


if __name__ == "__main__":
    main()
