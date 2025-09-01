#!/usr/bin/env python3
"""
Firewall Application
====================

This module implements a self-contained firewall and intrusion detection
service in Python. It is written from scratch and designed to run on
Linux or Windows with minimal external dependencies. The firewall
monitors incoming HTTP requests, applies a simple rate-based DDoS
limiter, performs AI-based inspection of all request components, and
blocks malicious IPs both at the database level and optionally via
operating-system enforced block lists. The service exposes several
JSON endpoints for health checks, statistics and metrics.

Key features:

* **Precise request counting:** Every request not explicitly excluded
  from stats is counted exactly once. Excluded paths include common
  assets (e.g. `/static/`), health endpoints and administrative pages.

* **DDoS limiter:** A sliding window rate limiter (default window 60s,
  maximum 20 requests per IP) rejects traffic that exceeds the
  configured threshold. Limits are fully configurable via environment
  variables.

* **AI inspection:** All request components (path, query, body and
  select headers) are analysed using an external detector. If any
  component is flagged as malicious, the IP is blocked and the request
  aborted. A network sniffer (using scapy when available) performs
  similar inspection on raw packets.

* **Database-backed IP blocking:** IPs are recorded in a MySQL table
  via the `MySQLIPBlocker` helper. Blocks persist across restarts and
  expire automatically after the configured TTL. A background thread
  keeps the in-memory view synchronised with the database.

* **Operating-system enforcement:** When supported, blocked IPs are
  added to an OS-level firewall using either `nftables` or `ipset`.
  This enforces automatic expiry without requiring explicit cleanup.

* **Web interface:** A Flask application exposes JSON APIs for
  statistics (`/stats`), metrics (`/metrics`), and leaderboards of
  blocked/requesting IPs. A simple login/logout flow protects the
  dashboard page, which lists the top blocked IPs and reasons for
  blocking.

This script is self-contained and can be run directly. It uses
environment variables for configuration (prefixed with `FW_`). Where
external dependencies are missing (e.g. scapy, ip_blocker_db or
secureauth), the service will degrade gracefully and log
appropriate warnings.
"""

from __future__ import annotations

import os
import time
import logging
import threading
import subprocess
import shutil
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - psutil is strongly recommended
    psutil = None  # type: ignore

try:
    # Flask and Werkzeug imports
    from flask import (
        Flask,
        request,
        jsonify,
        render_template,
        redirect,
        url_for,
        flash,
        session,
        abort,
        g,
    )
    from werkzeug.middleware.proxy_fix import ProxyFix  # type: ignore
except ImportError as exc:
    raise SystemExit(
        "Flask and Werkzeug are required to run this firewall."
    ) from exc

# Attempt to import optional modules. If they are missing, fallback
# implementations are provided further down.
try:
    from scapy.all import sniff, IP, Raw  # type: ignore
except Exception:
    sniff = None
    IP = None  # type: ignore
    Raw = None  # type: ignore
    logging.getLogger(__name__).warning("scapy could not be imported; network sniffing disabled")

try:
    from ip_blocker_db import MySQLIPBlocker  # type: ignore
except Exception:
    MySQLIPBlocker = None  # type: ignore
    logging.getLogger(__name__).warning("MySQLIPBlocker import failed; DB-backed blocking disabled")

try:
    from ai_detector import detect_attack  # type: ignore
except Exception:
    detect_attack = None  # type: ignore
    logging.getLogger(__name__).warning("ai_detector import failed; all AI inspections will allow traffic")

try:
    import secureauth  # type: ignore
except Exception:
    secureauth = None  # type: ignore
    logging.getLogger(__name__).warning("secureauth import failed; login disabled")

try:
    from os_detection import detect_os  # type: ignore
except Exception:
    detect_os = None  # type: ignore


# ---------------------------------------------------------------------------
# Configuration via environment variables
# ---------------------------------------------------------------------------
# TTL (seconds) for blocked IPs, both in the database and OS-level list
BLOCK_TTL_SECONDS: int = int(os.environ.get("FW_BLOCK_TTL", "300"))
assert BLOCK_TTL_SECONDS > 0, "FW_BLOCK_TTL must be positive"

# Rate limiting configuration
DDOS_WINDOW: int = int(os.environ.get("FW_DDOS_WINDOW", "60"))
DDOS_MAX: int = int(os.environ.get("FW_DDOS_MAX", "20"))
assert DDOS_WINDOW > 0 and DDOS_MAX > 0, "FW_DDOS_WINDOW and FW_DDOS_MAX must be positive"

# Trust one proxy hop when determining client IP
TRUST_PROXY: bool = os.environ.get("FW_TRUST_PROXY", "1") != "0"

# OS enforcement mode: auto | nft | ipset | off
OS_MODE_ENV: str = os.environ.get("FW_OS_MODE", "auto").lower()
assert OS_MODE_ENV in {"auto", "nft", "ipset", "off"}, "FW_OS_MODE must be one of auto, nft, ipset, off"

# Logging setup: log to file and standard output at INFO level
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

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

def is_excluded_path(path: str) -> bool:
    """Return True if the request path should be excluded from counting.

    In addition to the explicit exclusions, anything under /static/ is
    ignored for request totals and AI inspection.
    """
    if path in EXCLUDED_PATHS:
        return True
    if path.startswith("/static/"):
        return True
    return False


def get_client_ip() -> str:
    """Determine the real client IP, respecting proxy headers if enabled."""
    # Cloudflare header has highest priority
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    # X-Forwarded-For may contain multiple addresses separated by comma
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    # X-Real-IP if present
    xr = request.headers.get("X-Real-IP")
    if xr:
        return xr
    # Fallback to remote_addr provided by Flask
    return request.remote_addr or "unknown"


# ---------------------------------------------------------------------------
# Rate limiting and statistics
# ---------------------------------------------------------------------------

class DDoSRateLimiter:
    """Sliding window rate limiter keyed by IP address.

    Each IP may make at most `max_requests` requests in `time_window`
    seconds. Older timestamps are discarded to maintain a moving window.
    """

    def __init__(self, time_window: Optional[int] = None, max_requests: Optional[int] = None) -> None:
        self.time_window = time_window if time_window is not None else DDOS_WINDOW
        self.max_requests = max_requests if max_requests is not None else DDOS_MAX
        self._log: Dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_ddos(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            dq = self._log[ip]
            # Remove timestamps outside the current window
            cutoff = now - self.time_window
            while dq and dq[0] < cutoff:
                dq.popleft()
            # Check current count
            if len(dq) >= self.max_requests:
                return True
            dq.append(now)
            return False


class Stats:
    """Thread-safe statistics tracker for request outcomes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0
        self.ddos_blocks = 0
        self.ai_based_blocks = 0
        self.network_blocks = 0

    def _inc(self, field: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def total(self, n: int = 1) -> None:
        self._inc("total_requests", n)

    def allowed(self, n: int = 1) -> None:
        self._inc("allowed_requests", n)

    def blocked(self, n: int = 1) -> None:
        self._inc("blocked_requests", n)

    def bump(self, field: str, n: int = 1) -> None:
        self._inc(field, n)

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


# ---------------------------------------------------------------------------
# OS-level enforcement helpers
# ---------------------------------------------------------------------------

def have(cmd: str) -> bool:
    """Return True if the given command exists in PATH."""
    return shutil.which(cmd) is not None


OS_METHOD: str = "off"  # Will be resolved in setup_os_enforcement()

def setup_os_enforcement(ttl_seconds: int) -> None:
    """Detect and prepare an OS-level IP blocking backend.

    This chooses nftables or ipset+iptables if available and requested via
    environment. It populates the global OS_METHOD variable accordingly.
    """
    global OS_METHOD
    mode = OS_MODE_ENV
    if mode == "off":
        OS_METHOD = "off"
        _logger.info("OS enforcement disabled (FW_OS_MODE=off)")
        return

    # auto-detect first
    if mode == "auto":
        if have("nft"):
            mode = "nft"
        elif have("ipset") and have("iptables"):
            mode = "ipset"
        else:
            mode = "off"

    # Try nftables
    if mode == "nft":
        if not have("nft"):
            _logger.warning("Requested nftables but 'nft' command not found; falling back")
        else:
            # Create table, set and chain if not already present. Use per-entry
            # timeout equal to ttl_seconds. These commands are idempotent.
            script = f"""
            add table inet filter
            add set inet filter fw_blocked {{ type ipv4_addr; timeout {ttl_seconds}s; flags timeout; }}
            add chain inet filter input {{ type filter hook input priority 0; policy accept; }}
            add rule inet filter input ip saddr @fw_blocked drop
            """
            try:
                subprocess.run(["nft", "-f", "-"], input=script.encode(), check=False)
                OS_METHOD = "nft"
                _logger.info(f"OS enforcement: nftables enabled with timeout {ttl_seconds}s")
                return
            except Exception as e:
                _logger.error(f"Failed to set up nftables: {e}")

    # Try ipset + iptables
    if mode == "ipset":
        if not (have("ipset") and have("iptables")):
            _logger.warning("Requested ipset but required commands not found; OS enforcement disabled")
        else:
            try:
                # Create set if not exists
                subprocess.run([
                    "ipset",
                    "create",
                    "fw_blocked",
                    "hash:ip",
                    "timeout",
                    str(ttl_seconds),
                    "-exist",
                ], check=False)
                # Ensure iptables rule exists
                probe = subprocess.run([
                    "iptables",
                    "-C",
                    "INPUT",
                    "-m",
                    "set",
                    "--match-set",
                    "fw_blocked",
                    "src",
                    "-j",
                    "DROP",
                ])
                if probe.returncode != 0:
                    subprocess.run([
                        "iptables",
                        "-I",
                        "INPUT",
                        "1",
                        "-m",
                        "set",
                        "--match-set",
                        "fw_blocked",
                        "src",
                        "-j",
                        "DROP",
                    ], check=False)
                OS_METHOD = "ipset"
                _logger.info(f"OS enforcement: ipset+iptables enabled with timeout {ttl_seconds}s")
                return
            except Exception as e:
                _logger.error(f"Failed to set up ipset/iptables: {e}")

    # Default fallback
    OS_METHOD = "off"
    _logger.info("OS enforcement not enabled (no supported backend found)")


def os_enforce_add(ip: str, ttl_seconds: int) -> None:
    """Add an IP to the OS-level block list with a given TTL.

    This function does nothing if OS enforcement is off or the required
    commands are not available. Errors are suppressed to avoid blocking
    request processing. See setup_os_enforcement() for initialisation.
    """
    try:
        if OS_METHOD == "nft" and have("nft"):
            subprocess.run([
                "nft",
                "add",
                "element",
                "inet",
                "filter",
                "fw_blocked",
                f"{ip} timeout {ttl_seconds}s",
            ], check=False)
        elif OS_METHOD == "ipset" and have("ipset"):
            subprocess.run([
                "ipset",
                "add",
                "fw_blocked",
                ip,
                "timeout",
                str(ttl_seconds),
                "-exist",
            ], check=False)
    except Exception as e:
        _logger.error(f"Error adding IP {ip} to OS block list: {e}")


# ---------------------------------------------------------------------------
# Database-backed IP blocking
# ---------------------------------------------------------------------------

class DummyIPBlocker:
    """Fallback IP blocker used when MySQLIPBlocker cannot be imported.

    This implementation simply stores blocks in memory and expires
    entries after the configured TTL. It is not persisted across
    restarts. The API matches the real MySQLIPBlocker as closely as
    possible.
    """

    def __init__(self, default_ttl_seconds: int = BLOCK_TTL_SECONDS, sync_interval_sec: int = 30) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self.sync_interval_sec = sync_interval_sec
        self._blocks: Dict[str, Tuple[str, float]] = {}  # ip -> (reason, expiry)
        self._lock = threading.Lock()

    def start_background_sync(self) -> None:
        # No background sync needed in dummy
        pass

    def block_ip(self, ip: str, reason: str = "unknown") -> None:
        expiry = time.time() + self.default_ttl_seconds
        with self._lock:
            self._blocks[ip] = (reason, expiry)
        _logger.info(f"DummyIPBlocker: blocked {ip} for {self.default_ttl_seconds}s: {reason}")

    def get_active_blocks(self) -> List[Tuple[str, str, float]]:
        now = time.time()
        active: List[Tuple[str, str, float]] = []
        with self._lock:
            # Remove expired entries
            expired = [ip for ip, (_, exp) in self._blocks.items() if exp <= now]
            for ip in expired:
                del self._blocks[ip]
            # Return list of active blocks
            for ip, (reason, expiry) in self._blocks.items():
                active.append((ip, reason, expiry))
        return active


def get_ip_blocker() -> Any:
    """Return an instance of MySQLIPBlocker if available, otherwise fallback."""
    if MySQLIPBlocker is None:
        return DummyIPBlocker(default_ttl_seconds=BLOCK_TTL_SECONDS, sync_interval_sec=30)
    try:
        blocker = MySQLIPBlocker(default_ttl_seconds=BLOCK_TTL_SECONDS, sync_interval_sec=30)
        blocker.start_background_sync()
        return blocker
    except Exception as e:
        _logger.error(f"Failed to initialise MySQLIPBlocker: {e}; using dummy blocker instead")
        return DummyIPBlocker(default_ttl_seconds=BLOCK_TTL_SECONDS, sync_interval_sec=30)


# ---------------------------------------------------------------------------
# AI inspection wrappers
# ---------------------------------------------------------------------------

def ai_inspect(text: str) -> int:
    """Run the AI detector on the given text.

    Returns an integer code indicating the type of attack:
      0 = benign, 1 = SQLi, 2 = XSS, 3 = DDoS (payload-based)

    If the detector is unavailable, always return 0 (allow).
    Errors during detection are logged and treated as benign.
    """
    if detect_attack is None:
        return 0
    try:
        code = detect_attack(text)
        _logger.info(f"ai_detector returned {code} for text of length {len(text)}")
        return int(code) if code is not None else 0
    except Exception as e:
        _logger.error(f"ai_detector error: {e}")
        return 0


def ai_inspect_all_content(client_ip: str, request_data: str) -> bool:
    """Inspect all request components and decide if the request is malicious.

    The following parts are inspected:
      * Path (`request.path`)
      * Query string (`request.query_string`)
      * Request body (`request_data`)
      * Selected headers (User-Agent, Referer, X-Forwarded-For)

    If any part yields a non-zero result from the AI detector, the request
    is considered malicious and True is returned. Otherwise, False.
    """
    # Check URL path
    path = request.path or "/"
    if ai_inspect(path) != 0:
        _logger.warning(f"AI detected malicious path from {client_ip}: {path}")
        return True
    # Check query parameters
    query_string = request.query_string.decode("utf-8", errors="ignore")
    if query_string and ai_inspect(query_string) != 0:
        _logger.warning(f"AI detected malicious query from {client_ip}: {query_string}")
        return True
    # Check request body/data
    if request_data and ai_inspect(request_data) != 0:
        _logger.warning(f"AI detected malicious body from {client_ip}: {request_data[:100]}")
        return True
    # Check headers for common attack vectors
    suspicious_headers = ["User-Agent", "Referer", "X-Forwarded-For"]
    for header_name in suspicious_headers:
        header_value = request.headers.get(header_name, "")
        if header_value and ai_inspect(header_value) != 0:
            _logger.warning(f"AI detected malicious {header_name} from {client_ip}: {header_value}")
            return True
    return False


# ---------------------------------------------------------------------------
# Network-level AI inspection (scapy)
# ---------------------------------------------------------------------------

def ai_predict_packet(packet: Any) -> bool:
    """Return True if the packet payload appears malicious, False otherwise."""
    if packet is None or IP is None or Raw is None:
        return False
    if not packet.haslayer(IP):
        return False
    if not packet.haslayer(Raw):
        return False
    try:
        payload = packet[Raw].load.decode("utf-8", errors="ignore")
        return ai_inspect(payload) != 0
    except Exception as e:
        _logger.error(f"Network payload decode error: {e}")
        return False


def network_enforce_block(ip: str, reason: str) -> None:
    """Block an IP at the DB and OS level due to network-level AI detection."""
    try:
        db_blocker.block_ip(ip, reason=reason)
        os_enforce_add(ip, BLOCK_TTL_SECONDS)
        track_blocked_ip(ip)
        stats.bump("network_blocks")
        _logger.info(f"Network-level block for {ip}: {reason}")
    except Exception as e:
        _logger.error(f"Error blocking IP {ip} due to network AI detection: {e}")


def process_packet(packet: Any) -> None:
    """Callback invoked by scapy's sniff() for each captured packet."""
    if packet is None or IP is None:
        return
    if ai_predict_packet(packet):
        # Get source IP from IP header
        src_ip = packet[IP].src  # type: ignore[attr-defined]
        _logger.warning(f"AI detected malicious packet from {src_ip}")
        network_enforce_block(src_ip, "Network-level AI detection")


def start_sniffer() -> None:
    """Launch a background packet sniffer if scapy is available."""
    if sniff is None:
        _logger.warning("scapy sniffing disabled; skipping network packet inspection")
        return
    try:
        sniff(filter="ip", prn=process_packet, store=0)  # type: ignore[call-arg]
    except Exception as e:
        _logger.error(f"scapy sniffing error: {e}")


# ---------------------------------------------------------------------------
# System metrics helpers
# ---------------------------------------------------------------------------

def format_uptime(seconds: int) -> str:
    """Return a human-readable string for uptime in seconds."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        minutes, secs = divmod(seconds, 60)
        return f"{minutes}m {secs}s"
    if seconds < 86400:
        hours, rem = divmod(seconds, 3600)
        minutes = rem // 60
        return f"{hours}h {minutes}m"
    days, rem = divmod(seconds, 86400)
    hours = rem // 3600
    return f"{days}d {hours}h"


def get_uptime() -> Dict[str, Any]:
    """Return uptime in seconds and formatted string."""
    if psutil is None:
        return {"uptime_seconds": 0, "formatted": "unknown"}
    try:
        boot_time = psutil.boot_time()
        uptime_secs = int(time.time() - boot_time)
        return {
            "uptime_seconds": uptime_secs,
            "formatted": format_uptime(uptime_secs),
        }
    except Exception as e:
        _logger.error(f"Error computing uptime: {e}")
        return {"uptime_seconds": 0, "formatted": "unknown"}


def get_cpu() -> Dict[str, Any]:
    """Return current CPU usage and core count."""
    if psutil is None:
        return {"total": 0.0, "cores": 0}
    try:
        return {
            "total": psutil.cpu_percent(interval=None),
            "cores": psutil.cpu_count(logical=True),
        }
    except Exception as e:
        _logger.error(f"Error retrieving CPU metrics: {e}")
        return {"total": 0.0, "cores": 0}


def get_ram() -> Dict[str, Any]:
    """Return current RAM statistics in GiB."""
    if psutil is None:
        return {"total": 0.0, "used": 0.0, "free": 0.0, "percent": 0.0}
    try:
        m = psutil.virtual_memory()
        return {
            "total": round(m.total / (1024 ** 3), 2),
            "used": round(m.used / (1024 ** 3), 2),
            "free": round(m.free / (1024 ** 3), 2),
            "percent": m.percent,
        }
    except Exception as e:
        _logger.error(f"Error retrieving RAM metrics: {e}")
        return {"total": 0.0, "used": 0.0, "free": 0.0, "percent": 0.0}


def get_disk() -> List[Dict[str, Any]]:
    """Return disk usage for the root filesystem."""
    if psutil is None:
        return []
    try:
        usage = psutil.disk_usage("/")
        return [
            {
                "device": "root",
                "mountpoint": "/",
                "total": round(usage.total / (1024 ** 3), 2),
                "used": round(usage.used / (1024 ** 3), 2),
                "free": round(usage.free / (1024 ** 3), 2),
                "percent": usage.percent,
            }
        ]
    except Exception as e:
        _logger.error(f"Error retrieving disk metrics: {e}")
        return []


# ---------------------------------------------------------------------------
# Request tracking
# ---------------------------------------------------------------------------

stats = Stats()
ddos = DDoSRateLimiter()

ip_request_count: Dict[str, int] = defaultdict(int)
blocked_ip_count: Dict[str, int] = defaultdict(int)
ipcount_lock = threading.Lock()


def track_blocked_ip(ip: str) -> None:
    """Record that an IP was blocked for leaderboards."""
    with ipcount_lock:
        blocked_ip_count[ip] += 1


# ---------------------------------------------------------------------------
# Initialising IP blocker and OS enforcement
# ---------------------------------------------------------------------------

db_blocker = get_ip_blocker()
setup_os_enforcement(BLOCK_TTL_SECONDS)

# Determine OS type if possible
try:
    current_os = detect_os() if detect_os is not None else "unknown"
except Exception as e:
    _logger.error(f"Error detecting OS: {e}")
    current_os = "unknown"


# ---------------------------------------------------------------------------
# Flask application setup
# ---------------------------------------------------------------------------

app = Flask(__name__)

# A secret key is required for session management. If not provided,
# generate a fallback which is sufficient for development but should
# be set to a random value in production.
app.secret_key = os.environ.get("APP_SECRET_KEY", "fallback_secret")

# Configure session cookie properties
app.config.update(
    SESSION_COOKIE_NAME="fw_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # Set True behind HTTPS termination
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# Apply ProxyFix if trusting proxies
if TRUST_PROXY:
    # x_for=1 trusts one hop for X-Forwarded-For, etc.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


# ---------------------------------------------------------------------------
# Request lifecycle hooks
# ---------------------------------------------------------------------------

@app.before_request
def before_every_request() -> None:
    """Executed before every request. Enforce DB blocks and count requests."""
    path = request.path or "/"
    client_ip = get_client_ip()

    # Prevent double counting in after_request
    g.allowed_counted = False

    # Count all non-excluded requests exactly once
    if not is_excluded_path(path):
        stats.total()
        with ipcount_lock:
            ip_request_count[client_ip] += 1

    # Deny immediately if IP is blocked in DB
    try:
        active_blocks = {ip for ip, _, _ in db_blocker.get_active_blocks()}
    except Exception as e:
        _logger.error(f"Error reading active blocks from DB: {e}")
        active_blocks = set()
    if client_ip in active_blocks:
        stats.blocked()
        track_blocked_ip(client_ip)
        log_request(client_ip, "<BLOCKED>", "denied (in DB)")
        abort(403)


@app.after_request
def classify_allowed(response):  # type: ignore[no-redef]
    """Executed after the response is generated. Count successful responses."""
    path = request.path or "/"
    if not is_excluded_path(path):
        sc = response.status_code
        # Consider success 2xx or 304 as allowed
        if (200 <= sc < 300 or sc == 304) and not getattr(g, "allowed_counted", False):
            stats.allowed()
            g.allowed_counted = True
    return response


# ---------------------------------------------------------------------------
# Utility functions for request routing
# ---------------------------------------------------------------------------

def log_request(ip: str, data: str, result: str) -> None:
    """Write a simple log entry to the firewall.log file."""
    try:
        with open("firewall.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {result} - {data}\n")
    except Exception as e:
        _logger.error(f"Error writing to firewall.log: {e}")


def get_top_blocked(n: int = 5) -> Tuple[List[str], List[str]]:
    """Return the top N most recently blocked IPs and their reasons."""
    try:
        active = db_blocker.get_active_blocks()  # type: ignore[attr-defined]
        # Sort by expiry descending (most recently added first)
        recent = sorted(active, key=lambda x: x[2], reverse=True)[:n]
        ips = [ip for ip, _, _ in recent]
        reasons = [reason for _, reason, _ in recent]
        return ips, reasons
    except Exception as e:
        _logger.error(f"Error fetching top blocked IPs: {e}")
        return [], []


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@app.route("/metrics")
def metrics() -> Any:
    """Return system metrics as JSON."""
    up = get_uptime()
    cpu = get_cpu()
    ram = get_ram()
    disk = get_disk()
    ts = time.time()
    return jsonify({
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "uptime": up,
        "uptime_seconds": up.get("uptime_seconds", 0),
        "uptimeSeconds": up.get("uptime_seconds", 0),  # alias for camelCase
        "ts": ts,
    })


@app.route("/stats")
def stats_json() -> Any:
    """Return accumulated statistics and configuration info."""
    s = stats.to_dict()
    up = get_uptime()
    s["uptime"] = up
    s["uptime_seconds"] = up.get("uptime_seconds", 0)
    s["uptimeSeconds"] = up.get("uptime_seconds", 0)
    # Aliases for block counts to satisfy various frontends
    ddos_count = s.get("ddos_blocks", 0)
    s["ddosBlocks"] = ddos_count
    s["DDoSBlocks"] = ddos_count
    ai_count = s.get("ai_based_blocks", 0)
    s["aiBasedBlocks"] = ai_count
    s["aiBlocks"] = ai_count
    s["AIBlocks"] = ai_count
    net_count = s.get("network_blocks", 0)
    s["networkBlocks"] = net_count
    # Uptime formatting
    secs = up.get("uptime_seconds", 0)
    s["uptime_hms"] = f"{secs//3600}h {(secs%3600)//60}m {secs%60}s"
    s["uptime_formatted"] = up.get("formatted", "")
    # Config info
    s["ddosConfig"] = {"window": ddos.time_window, "max": ddos.max_requests}
    s["osEnforcement"] = {"mode": OS_METHOD, "ttl": BLOCK_TTL_SECONDS}
    return jsonify(s)


@app.route("/top_ips")
def top_ips() -> Any:
    """Return the top 5 most frequently blocked IPs."""
    with ipcount_lock:
        top5_blocked = sorted(blocked_ip_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5_blocked))


@app.route("/top_requesting_ips")
def top_requesting_ips() -> Any:
    """Return the top 5 IPs by request count."""
    with ipcount_lock:
        top5_requests = sorted(ip_request_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
    return jsonify(dict(top5_requests))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Render login page and handle authentication."""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # If secureauth is unavailable, always fail
        if secureauth is not None and hasattr(secureauth, "verify_user"):
            if secureauth.verify_user(username, password):  # type: ignore[attr-defined]
                session["user"] = username
                session.permanent = True
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout() -> Any:
    """Clear the user session and redirect to login."""
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard() -> Any:
    """Render the administrative dashboard. Requires login."""
    if "user" not in session:
        flash("Login required", "error")
        return redirect(url_for("login"))
    ips, reasons = get_top_blocked(n=5)
    return render_template("dashboard.html", top_ips=ips, top_reasons=reasons)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def firewall_route(path: str) -> Any:
    """Main catch-all route implementing DDoS and AI checks."""
    client_ip = get_client_ip()
    body = request.get_data(cache=False, as_text=True) or ""
    referer = request.headers.get("Referer", "") or ""

    # DDoS limiter for all non-excluded hits
    if not is_excluded_path(request.path or "/") and ddos.is_ddos(client_ip):
        stats.blocked()
        stats.bump("ddos_blocks")
        track_blocked_ip(client_ip)
        reason = "DDoS rate-limit"
        try:
            db_blocker.block_ip(client_ip, reason=reason)  # type: ignore[attr-defined]
            os_enforce_add(client_ip, BLOCK_TTL_SECONDS)
        except Exception as e:
            _logger.error(f"DDoS block error for {client_ip}: {e}")
        log_request(client_ip, "<rate-limited>", reason)
        return jsonify({"status": "blocked", "reason": reason}), 429

    # Allow admin refreshes from dashboard without inspection
    if ("user" in session or "/dashboard" in referer) and request.method == "GET" and not body.strip():
        log_request(client_ip, body, "allowed (admin/refresh GET)")
        return jsonify({"status": "allowed", "echo": body})

    # AI inspection on all content (path, query, body, headers)
    if ai_inspect_all_content(client_ip, body):
        stats.blocked()
        stats.bump("ai_based_blocks")
        track_blocked_ip(client_ip)
        # Determine specific attack type from AI codes (check body, path, query)
        ai_code = ai_inspect(body) or ai_inspect(request.path or "/") or ai_inspect(
            request.query_string.decode("utf-8", errors="ignore")
        )
        reason_map = {1: "SQLi (AI)", 2: "XSS (AI)", 3: "DDoS (AI)"}
        reason = reason_map.get(ai_code, "Malicious Content (AI)")
        try:
            db_blocker.block_ip(client_ip, reason=reason)  # type: ignore[attr-defined]
            os_enforce_add(client_ip, BLOCK_TTL_SECONDS)
        except Exception as e:
            _logger.error(f"AI block error for {client_ip}: {e}")
        log_request(client_ip, body, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    # Otherwise, allow request and echo back minimal data
    log_request(client_ip, body, "allowed")
    return jsonify({"status": "allowed", "echo": body})


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the network sniffer and run the Flask app."""
    # Launch sniffer thread if scapy is available
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()
    _logger.info("Firewall starting up...")
    # Run the Flask app
    # Bind to all interfaces on port 8080; disable debug and reloader
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
