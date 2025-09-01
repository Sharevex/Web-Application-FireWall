#!/usr/bin/env python3
"""
Modern AI-Powered Web Application Firewall
==========================================

A comprehensive firewall with AI-based threat detection, DDoS protection,
and multi-layer security enforcement.

Author: Claude Sonnet 4
Date: 2025-09-01
Version: 2.0.0
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import shutil
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock, Thread
from typing import Dict, List, Tuple, Optional, Any, Union

# Third-party imports
import psutil
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, abort

# Optional imports with fallbacks
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    PROXY_FIX_AVAILABLE = True
except ImportError:
    PROXY_FIX_AVAILABLE = False

try:
    from scapy.all import sniff, IP, Raw, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Local imports
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

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================

class FirewallConfig:
    """Centralized configuration management"""
    
    # Core settings
    BLOCK_TTL = int(os.environ.get("FW_BLOCK_TTL", "300"))  # 5 minutes
    DDOS_WINDOW = int(os.environ.get("FW_DDOS_WINDOW", "60"))  # 1 minute
    DDOS_MAX_REQUESTS = int(os.environ.get("FW_DDOS_MAX", "20"))  # 20 req/min
    
    # System settings
    TRUST_PROXY = os.environ.get("FW_TRUST_PROXY", "1") == "1"
    OS_MODE = os.environ.get("FW_OS_MODE", "auto").lower()
    DEBUG_MODE = os.environ.get("FW_DEBUG", "0") == "1"
    LOG_LEVEL = logging.DEBUG if DEBUG_MODE else logging.INFO
    
    # Flask settings
    SECRET_KEY = os.environ.get("APP_SECRET_KEY", "firewall-secret-key-2025")
    SESSION_TIMEOUT_HOURS = 12
    
    # Monitoring
    ENABLE_NETWORK_MONITORING = SCAPY_AVAILABLE and os.environ.get("FW_NETWORK_MONITOR", "1") == "1"
    
    # Excluded paths (not monitored)
    EXCLUDED_PATHS = {
        "/favicon.ico", "/robots.txt", "/health", "/healthz", "/ping",
        "/metrics", "/stats", "/top_ips", "/top_requesting_ips",
        "/login", "/logout"
    }
    
    @staticmethod
    def is_excluded_path(path: str) -> bool:
        """Check if path should be excluded from monitoring"""
        if not path:
            return True
            
        # Exact matches
        if path in FirewallConfig.EXCLUDED_PATHS:
            return True
            
        # Static resources
        static_prefixes = ["/static/", "/css/", "/js/", "/images/", "/fonts/"]
        return any(path.startswith(prefix) for prefix in static_prefixes)

# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configure comprehensive logging"""
    
    # Create logger
    logger = logging.getLogger("firewall")
    logger.setLevel(FirewallConfig.LOG_LEVEL)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler
    try:
        file_handler = logging.FileHandler("firewall.log", encoding='utf-8')
        file_handler.setLevel(FirewallConfig.LOG_LEVEL)
    except Exception as e:
        print(f"⚠️  Could not create log file: {e}")
        file_handler = None
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)-10s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add handlers
    if file_handler:
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# =============================================================================
# STATISTICS & METRICS
# =============================================================================

class FirewallStats:
    """Thread-safe statistics tracking"""
    
    def __init__(self):
        self._lock = Lock()
        self._start_time = time.time()
        
        # Request counters
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0
        
        # Block type counters
        self.ddos_blocks = 0
        self.ai_based_blocks = 0
        self.network_blocks = 0
        
        # IP tracking
        self.ip_request_counts = defaultdict(int)
        self.blocked_ip_counts = defaultdict(int)
        
        # Performance tracking
        self.avg_response_time = 0.0
        self._response_times = deque(maxlen=1000)
    
    def increment(self, counter: str, amount: int = 1) -> None:
        """Thread-safe counter increment"""
        with self._lock:
            current_value = getattr(self, counter, 0)
            setattr(self, counter, current_value + amount)
    
    def track_ip_request(self, ip: str) -> None:
        """Track request from IP"""
        with self._lock:
            self.ip_request_counts[ip] += 1
    
    def track_blocked_ip(self, ip: str) -> None:
        """Track blocked IP"""
        with self._lock:
            self.blocked_ip_counts[ip] += 1
    
    def add_response_time(self, response_time: float) -> None:
        """Track response time for performance metrics"""
        with self._lock:
            self._response_times.append(response_time)
            if self._response_times:
                self.avg_response_time = sum(self._response_times) / len(self._response_times)
    
    def get_uptime_seconds(self) -> int:
        """Get uptime in seconds"""
        return int(time.time() - self._start_time)
    
    def get_top_requesting_ips(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get top requesting IPs"""
        with self._lock:
            return sorted(
                self.ip_request_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:limit]
    
    def get_top_blocked_ips(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get top blocked IPs"""
        with self._lock:
            return sorted(
                self.blocked_ip_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]
    
    def to_dict(self) -> Dict[str, Any]:
        """Export stats as dictionary"""
        uptime_seconds = self.get_uptime_seconds()
        
        with self._lock:
            return {
                # Request stats
                "total_requests": self.total_requests,
                "allowed_requests": self.allowed_requests,
                "blocked_requests": self.blocked_requests,
                
                # Block type stats
                "ddos_blocks": self.ddos_blocks,
                "ai_based_blocks": self.ai_based_blocks,
                "network_blocks": self.network_blocks,
                
                # Performance
                "avg_response_time": round(self.avg_response_time, 3),
                
                # Uptime
                "uptime_seconds": uptime_seconds,
                "uptime_formatted": self._format_uptime(uptime_seconds),
                
                # Configuration
                "config": {
                    "block_ttl": FirewallConfig.BLOCK_TTL,
                    "ddos_window": FirewallConfig.DDOS_WINDOW,
                    "ddos_max_requests": FirewallConfig.DDOS_MAX_REQUESTS,
                    "network_monitoring": FirewallConfig.ENABLE_NETWORK_MONITORING,
                    "debug_mode": FirewallConfig.DEBUG_MODE
                }
            }
    
    @staticmethod
    def _format_uptime(seconds: int) -> str:
        """Format uptime in human readable format"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            minutes, secs = divmod(seconds, 60)
            return f"{minutes}m {secs}s"
        elif seconds < 86400:
            hours, remainder = divmod(seconds, 3600)
            minutes = remainder // 60
            return f"{hours}h {minutes}m"
        else:
            days, remainder = divmod(seconds, 86400)
            hours = remainder // 3600
            return f"{days}d {hours}h"

# =============================================================================
# DDOS PROTECTION
# =============================================================================

class DDoSProtector:
    """Advanced DDoS protection with sliding window"""
    
    def __init__(self):
        self.window_seconds = FirewallConfig.DDOS_WINDOW
        self.max_requests = FirewallConfig.DDOS_MAX_REQUESTS
        self._ip_requests = defaultdict(deque)
        self._lock = Lock()
        
        logger.info(f"🛡️  DDoS protection: max {self.max_requests} requests per {self.window_seconds}s window")
    
    def is_ddos_attack(self, ip: str) -> bool:
        """Check if IP is performing DDoS attack"""
        current_time = time.time()
        
        with self._lock:
            ip_requests = self._ip_requests[ip]
            
            # Remove old requests outside window
            while ip_requests and ip_requests[0] <= current_time - self.window_seconds:
                ip_requests.popleft()
            
            # Check if limit exceeded
            if len(ip_requests) >= self.max_requests:
                logger.warning(f"🚨 DDoS attack detected from {ip}: {len(ip_requests)} requests in {self.window_seconds}s")
                return True
            
            # Add current request timestamp
            ip_requests.append(current_time)
            return False
    
    def get_request_count(self, ip: str) -> int:
        """Get current request count for IP in window"""
        current_time = time.time()
        
        with self._lock:
            ip_requests = self._ip_requests[ip]
            # Remove old requests
            while ip_requests and ip_requests[0] <= current_time - self.window_seconds:
                ip_requests.popleft()
            return len(ip_requests)

# =============================================================================
# OS-LEVEL ENFORCEMENT
# =============================================================================

class OSLevelEnforcer:
    """OS-level IP blocking using nftables or iptables"""
    
    def __init__(self):
        self.method = "off"
        self.initialized = False
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize OS enforcement method"""
        if FirewallConfig.OS_MODE == "off":
            self.method = "off"
            logger.info("🔓 OS enforcement disabled")
            return
        
        # Auto-detect or use specified method
        if FirewallConfig.OS_MODE == "auto":
            if self._setup_nftables():
                self.method = "nftables"
            elif self._setup_iptables():
                self.method = "iptables"
            else:
                self.method = "off"
                logger.warning("⚠️  No OS enforcement tools available")
        elif FirewallConfig.OS_MODE == "nft":
            if self._setup_nftables():
                self.method = "nftables"
            else:
                logger.error("❌ nftables requested but not available")
        elif FirewallConfig.OS_MODE == "iptables":
            if self._setup_iptables():
                self.method = "iptables"
            else:
                logger.error("❌ iptables requested but not available")
        
        if self.method != "off":
            logger.info(f"🔒 OS enforcement initialized: {self.method}")
            self.initialized = True
    
    def _setup_nftables(self) -> bool:
        """Setup nftables for IP blocking"""
        if not shutil.which("nft"):
            return False
        
        try:
            # Create table and set
            commands = [
                "nft add table inet firewall",
                "nft add set inet firewall blocked_ips '{ type ipv4_addr; flags timeout; }'",
                "nft add chain inet firewall input '{ type filter hook input priority 0; policy accept; }'",
                "nft insert rule inet firewall input ip saddr @blocked_ips drop"
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd.split(), 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                # Ignore "already exists" errors
                if result.returncode != 0 and "already exists" not in result.stderr.lower():
                    logger.debug(f"nftables setup warning: {result.stderr.strip()}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ nftables setup failed: {e}")
            return False
    
    def _setup_iptables(self) -> bool:
        """Setup iptables with ipset for IP blocking"""
        if not (shutil.which("iptables") and shutil.which("ipset")):
            return False
        
        try:
            # Create ipset
            subprocess.run([
                "ipset", "create", "firewall_blocked", "hash:ip",
                "timeout", str(FirewallConfig.BLOCK_TTL), "-exist"
            ], capture_output=True, timeout=10)
            
            # Add iptables rule if not exists
            check_result = subprocess.run([
                "iptables", "-C", "INPUT", "-m", "set",
                "--match-set", "firewall_blocked", "src", "-j", "DROP"
            ], capture_output=True)
            
            if check_result.returncode != 0:
                subprocess.run([
                    "iptables", "-I", "INPUT", "1", "-m", "set",
                    "--match-set", "firewall_blocked", "src", "-j", "DROP"
                ], capture_output=True, timeout=10)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ iptables setup failed: {e}")
            return False
    
    def block_ip(self, ip: str, ttl: int = None) -> bool:
        """Block IP at OS level"""
        if not self.initialized or self.method == "off":
            return True  # Silently succeed if OS blocking is disabled
        
        ttl = ttl or FirewallConfig.BLOCK_TTL
        
        try:
            if self.method == "nftables":
                cmd = f"nft add element inet firewall blocked_ips {{ {ip} timeout {ttl}s }}"
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    logger.debug(f"🔒 OS blocked {ip} via nftables ({ttl}s)")
                    return True
                else:
                    logger.error(f"❌ nftables block failed for {ip}: {result.stderr}")
            
            elif self.method == "iptables":
                result = subprocess.run([
                    "ipset", "add", "firewall_blocked", ip,
                    "timeout", str(ttl), "-exist"
                ], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.debug(f"🔒 OS blocked {ip} via iptables ({ttl}s)")
                    return True
                else:
                    logger.error(f"❌ iptables block failed for {ip}: {result.stderr}")
        
        except subprocess.TimeoutExpired:
            logger.error(f"⏰ OS block timeout for {ip}")
        except Exception as e:
            logger.error(f"❌ OS block error for {ip}: {e}")
        
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock IP at OS level"""
        if not self.initialized or self.method == "off":
            return True
        
        try:
            if self.method == "nftables":
                cmd = f"nft delete element inet firewall blocked_ips {{ {ip} }}"
                subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            elif self.method == "iptables":
                subprocess.run([
                    "ipset", "del", "firewall_blocked", ip
                ], capture_output=True, timeout=5)
            
            logger.debug(f"🔓 OS unblocked {ip}")
            return True
            
        except Exception as e:
            logger.error(f"❌ OS unblock error for {ip}: {e}")
            return False
    
    def get_method(self) -> str:
        """Get current enforcement method"""
        return self.method

# =============================================================================
# AI THREAT DETECTION
# =============================================================================

class AIThreatDetector:
    """AI-based threat detection with comprehensive analysis"""
    
    def __init__(self):
        self.threat_names = {
            0: "Benign",
            1: "SQL Injection",
            2: "Cross-Site Scripting (XSS)",
            3: "DDoS Attack"
        }
        
        # Test AI detector availability
        try:
            test_result = detect_attack("test")
            logger.info("🤖 AI threat detector initialized successfully")
        except Exception as e:
            logger.error(f"❌ AI detector initialization failed: {e}")
            raise
    
    def analyze_content(self, content: str) -> Tuple[int, str]:
        """
        Analyze content for threats
        Returns: (threat_code, threat_description)
        """
        try:
            if not content or len(content.strip()) == 0:
                return 0, "Benign"
            
            # Call AI detector
            threat_code = detect_attack(content)
            
            # Handle None or invalid responses
            if threat_code is None:
                logger.debug("AI detector returned None, treating as benign")
                return 0, "Benign"
            
            # Ensure integer
            try:
                threat_code = int(threat_code)
            except (ValueError, TypeError):
                logger.warning(f"AI detector returned invalid code: {threat_code}")
                return 0, "Benign"
            
            # Get threat description
            threat_description = self.threat_names.get(threat_code, f"Unknown Threat ({threat_code})")
            
            if threat_code != 0:
                logger.debug(f"🤖 AI detected {threat_description} in: {content[:100]}{'...' if len(content) > 100 else ''}")
            
            return threat_code, threat_description
        
        except Exception as e:
            logger.error(f"❌ AI analysis error: {e}")
            return 0, "Benign"
    
    def analyze_request(self, request_obj) -> Tuple[bool, str, str]:
        """
        Comprehensive request analysis
        Returns: (is_malicious, threat_type, malicious_part)
        """
        try:
            # Analyze URL path
            path = request_obj.path or "/"
            threat_code, threat_desc = self.analyze_content(path)
            if threat_code != 0:
                return True, threat_desc, f"URL Path: {path}"
            
            # Analyze query parameters
            query_string = request_obj.query_string.decode('utf-8', errors='ignore')
            if query_string:
                threat_code, threat_desc = self.analyze_content(query_string)
                if threat_code != 0:
                    return True, threat_desc, f"Query String: {query_string}"
            
            # Analyze request body
            try:
                body = request_obj.get_data(as_text=True, cache=False) or ""
                if body:
                    threat_code, threat_desc = self.analyze_content(body)
                    if threat_code != 0:
                        truncated_body = body[:200] + ("..." if len(body) > 200 else "")
                        return True, threat_desc, f"Request Body: {truncated_body}"
            except Exception as e:
                logger.debug(f"Could not read request body: {e}")
            
            # Analyze suspicious headers
            suspicious_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'Cookie']
            for header_name in suspicious_headers:
                header_value = request_obj.headers.get(header_name, "")
                if header_value:
                    threat_code, threat_desc = self.analyze_content(header_value)
                    if threat_code != 0:
                        return True, threat_desc, f"Header {header_name}: {header_value[:100]}"
            
            return False, "Benign", ""
        
        except Exception as e:
            logger.error(f"❌ Request analysis error: {e}")
            return False, "Benign", ""

# =============================================================================
# NETWORK MONITORING
# =============================================================================

class NetworkMonitor:
    """Network-level threat monitoring using Scapy"""
    
    def __init__(self, stats: FirewallStats, db_blocker, os_enforcer: OSLevelEnforcer):
        self.stats = stats
        self.db_blocker = db_blocker
        self.os_enforcer = os_enforcer
        self.ai_detector = AIThreatDetector()
        self.running = False
        self.monitor_thread = None
        
        if not FirewallConfig.ENABLE_NETWORK_MONITORING:
            logger.info("📡 Network monitoring disabled")
        elif not SCAPY_AVAILABLE:
            logger.warning("⚠️  Network monitoring disabled (Scapy not available)")
        else:
            logger.info("📡 Network monitoring enabled")
    
    def start(self) -> None:
        """Start network monitoring in background thread"""
        if not FirewallConfig.ENABLE_NETWORK_MONITORING or not SCAPY_AVAILABLE:
            return
        
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("📡 Network monitoring started")
    
    def stop(self) -> None:
        """Stop network monitoring"""
        if self.running:
            self.running = False
            logger.info("📡 Network monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main network monitoring loop"""
        try:
            # Monitor TCP traffic on common ports
            sniff(
                filter="tcp port 80 or tcp port 443 or tcp port 8080",
                prn=self._analyze_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"❌ Network monitoring error: {e}")
    
    def _analyze_packet(self, packet) -> None:
        """Analyze captured network packet"""
        try:
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            
            # Extract payload from packet
            payload = ""
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    return
            
            if not payload or len(payload.strip()) < 10:
                return
            
            # AI analysis of payload
            threat_code, threat_desc = self.ai_detector.analyze_content(payload)
            
            if threat_code != 0:
                logger.warning(f"🚨 Malicious network traffic from {src_ip}: {threat_desc}")
                self._block_malicious_network_ip(src_ip, f"Network {threat_desc}")
        
        except Exception as e:
            logger.debug(f"Packet analysis error: {e}")
    
    def _block_malicious_network_ip(self, ip: str, reason: str) -> None:
        """Block IP detected via network monitoring"""
        try:
            # Update statistics
            self.stats.increment("network_blocks")
            self.stats.track_blocked_ip(ip)
            
            # Block in database
            self.db_blocker.block_ip(ip, reason=reason)
            
            # Block at OS level
            self.os_enforcer.block_ip(ip)
            
            logger.info(f"🔒 Blocked {ip} via network monitoring: {reason}")
        
        except Exception as e:
            logger.error(f"❌ Failed to block network IP {ip}: {e}")

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_real_client_ip() -> str:
    """Extract real client IP from various proxy headers"""
    # Try Cloudflare header first
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()
    
    # Try X-Forwarded-For
    xff = request.headers.get("X-Forwarded-For")
    if xff and xff.strip():
        # Take first IP from comma-separated list
        first_ip = xff.split(",")[0].strip()
        if first_ip:
            return first_ip
    
    # Try X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    
    # Fall back to Flask's remote_addr
    return request.remote_addr or "unknown"

def get_system_metrics() -> Dict[str, Any]:
    """Get comprehensive system metrics"""
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count(logical=True)
        
        # Memory metrics
        memory = psutil.virtual_memory()
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        
        # Network metrics (optional)
        try:
            net_io = psutil.net_io_counters()
            network = {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
        except Exception:
            network = {}
        
        return {
            "timestamp": time.time(),
            "cpu": {
                "percent": round(cpu_percent, 1),
                "cores": cpu_count
            },
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "percent": round(memory.percent, 1)
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "percent": round((disk.used / disk.total) * 100, 1)
            },
            "network": network
        }
    
    except Exception as e:
        logger.error(f"❌ Error collecting system metrics: {e}")
        return {"error": str(e), "timestamp": time.time()}

# =============================================================================
# FLASK APPLICATION
# =============================================================================

# Initialize core components
stats = FirewallStats()
ddos_protector = DDoSProtector()
os_enforcer = OSLevelEnforcer()
ai_detector = AIThreatDetector()

# Initialize database blocker
try:
    db_blocker = MySQLIPBlocker(
        default_ttl_seconds=FirewallConfig.BLOCK_TTL,
        sync_interval_sec=30
    )
    db_blocker.start_background_sync()
    logger.info("💾 Database IP blocker initialized")
except Exception as e:
    logger.error(f"❌ Failed to initialize database blocker: {e}")
    sys.exit(1)

# Initialize network monitor
network_monitor = NetworkMonitor(stats, db_blocker, os_enforcer)

# Create Flask application
app = Flask(__name__)

# Configure Flask
app.secret_key = FirewallConfig.SECRET_KEY
app.config.update({
    'SESSION_COOKIE_NAME': 'firewall_session',
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': False,  # Set to True if using HTTPS
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': timedelta(hours=FirewallConfig.SESSION_TIMEOUT_HOURS),
    'JSON_SORT_KEYS': False
})

# Configure proxy support
if FirewallConfig.TRUST_PROXY and PROXY_FIX_AVAILABLE:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    logger.info("🔧 Proxy support enabled")

# =============================================================================
# REQUEST PROCESSING MIDDLEWARE
# =============================================================================

@app.before_request
def process_incoming_request():
    """Process every incoming request"""
    start_time = time.time()
    request.start_time = start_time
    
    path = request.path or "/"
    client_ip = get_real_client_ip()
    
    # Store client IP in request context
    request.client_ip = client_ip
    
    # Skip processing for excluded paths
    if FirewallConfig.is_excluded_path(path):
        return None
    
    # Increment total request counter and track IP
    stats.increment("total_requests")
    stats.track_ip_request(client_ip)
    
    # Check if IP is blocked in database
    try:
        blocked_ips = {ip for ip, _, _ in db_blocker.get_active_blocks()}
        if client_ip in blocked_ips:
            stats.increment("blocked_requests")
            stats.track_blocked_ip(client_ip)
            logger.info(f"🚫 Request blocked - IP {client_ip} is in database blocklist")
            return jsonify({
                "status": "blocked",
                "reason": "IP address is blocked",
                "ip": client_ip
            }), 403
    except Exception as e:
        logger.error(f"❌ Error checking database blocks: {e}")

@app.after_request
def process_outgoing_response(response):
    """Process every outgoing response"""
    # Calculate response time
    if hasattr(request, 'start_time'):
        response_time = time.time() - request.start_time
        stats.add_response_time(response_time)
    
    # Skip processing for excluded paths
    if FirewallConfig.is_excluded_path(request.path or "/"):
        return response
    
    # Track successful responses
    if 200 <= response.status_code < 400:
        stats.increment("allowed_requests")
    
    # Add security headers
    response.headers.update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    })
    
    return response

# =============================================================================
# API ROUTES
# =============================================================================

@app.route("/stats", methods=["GET"])
def api_get_stats():
    """Get firewall statistics"""
    return jsonify(stats.to_dict())

@app.route("/metrics", methods=["GET"])
def api_get_metrics():
    """Get system metrics"""
    return jsonify(get_system_metrics())

@app.route("/top_ips", methods=["GET"])
def api_get_top_blocked_ips():
    """Get top blocked IPs from database"""
    try:
        limit = min(int(request.args.get('limit', 10)), 50)  # Max 50
        blocked_ips = db_blocker.get_active_blocks()
        
        # Sort by expiration time (most recent blocks first)
        sorted_blocks = sorted(blocked_ips, key=lambda x: x[2], reverse=True)
        
        result = []
        for ip, reason, expires_at in sorted_blocks[:limit]:
            result.append({
                "ip": ip,
                "reason": reason,
                "expires_at": expires_at.isoformat(),
                "expires_in_seconds": max(0, int((expires_at - datetime.now()).total_seconds()))
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"❌ Error getting top blocked IPs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/top_requesting_ips", methods=["GET"])
def api_get_top_requesting_ips():
    """Get top requesting IPs"""
    try:
        limit = min(int(request.args.get('limit', 10)), 50)  # Max 50
        top_ips = stats.get_top_requesting_ips(limit)
        
        result = [{"ip": ip, "request_count": count} for ip, count in top_ips]
        return jsonify(result)
    except Exception as e:
        logger.error(f"❌ Error getting top requesting IPs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def api_health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "uptime_seconds": stats.get_uptime_seconds(),
        "version": "2.0.0"
    })

# =============================================================================
# WEB INTERFACE ROUTES
# =============================================================================

@app.route("/login", methods=["GET", "POST"])
def web_login():
    """Admin login page"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            flash("Please enter both username and password", "error")
            return render_template("login.html")
        
        try:
            if secureauth.verify_user(username, password):
                session["user"] = username
                session["login_time"] = time.time()
                session.permanent = True
                
                logger.info(f"✅ Successful login: {username} from {get_real_client_ip()}")
                flash(f"Welcome, {username}!", "success")
                return redirect(url_for("web_dashboard"))
            else:
                logger.warning(f"❌ Failed login attempt: {username} from {get_real_client_ip()}")
                flash("Invalid username or password", "error")
        except Exception as e:
            logger.error(f"❌ Login error: {e}")
            flash("Login system error. Please try again.", "error")
    
    return render_template("login.html")

@app.route("/logout", methods=["GET", "POST"])
def web_logout():
    """Admin logout"""
    username = session.get("user", "unknown")
    session.clear()
    
    logger.info(f"👋 User logged out: {username}")
    flash("Successfully logged out", "info")
    return redirect(url_for("web_login"))

@app.route("/dashboard")
def web_dashboard():
    """Admin dashboard"""
    if "user" not in session:
        flash("Please log in to access the dashboard", "error")
        return redirect(url_for("web_login"))
    
    try:
        # Get dashboard data
        firewall_stats = stats.to_dict()
        system_metrics = get_system_metrics()
        
        # Get top blocked IPs
        blocked_ips = db_blocker.get_active_blocks()
        top_blocked = sorted(blocked_ips, key=lambda x: x[2], reverse=True)[:5]
        
        # Get top requesting IPs
        top_requesting = stats.get_top_requesting_ips(5)
        
        return render_template("dashboard.html",
                             stats=firewall_stats,
                             metrics=system_metrics,
                             top_blocked=top_blocked,
                             top_requesting=top_requesting,
                             user=session["user"])
    except Exception as e:
        logger.error(f"❌ Dashboard error: {e}")
        flash("Error loading dashboard data", "error")
        return render_template("dashboard.html", error=str(e))

# =============================================================================
# MAIN FIREWALL HANDLER
# =============================================================================

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def firewall_main_handler(path):
    """Main firewall request handler"""
    client_ip = get_real_client_ip()
    method = request.method
    full_path = f"/{path}" if path else "/"
    
    # Skip firewall processing for excluded paths
    if FirewallConfig.is_excluded_path(full_path):
        return jsonify({
            "status": "allowed",
            "reason": "excluded path",
            "path": full_path,
            "method": method
        })
    
    try:
        # DDoS Protection
        if ddos_protector.is_ddos_attack(client_ip):
            stats.increment("blocked_requests")
            stats.increment("ddos_blocks")
            stats.track_blocked_ip(client_ip)
            
            reason = f"DDoS rate limit exceeded ({ddos_protector.max_requests}/{ddos_protector.window_seconds}s)"
            
            # Block the IP
            try:
                db_blocker.block_ip(client_ip, reason=reason)
                os_enforcer.block_ip(client_ip)
            except Exception as e:
                logger.error(f"❌ Failed to block DDoS IP {client_ip}: {e}")
            
            logger.warning(f"🚨 DDoS attack blocked: {client_ip} - {reason}")
            return jsonify({
                "status": "blocked",
                "reason": reason,
                "ip": client_ip,
                "request_count": ddos_protector.get_request_count(client_ip)
            }), 429
        
        # AI Threat Detection
        is_malicious, threat_type, malicious_content = ai_detector.analyze_request(request)
        
        if is_malicious:
            stats.increment("blocked_requests")
            stats.increment("ai_based_blocks")
            stats.track_blocked_ip(client_ip)
            
            reason = f"AI detected: {threat_type}"
            
            # Block the IP
            try:
                db_blocker.block_ip(client_ip, reason=reason)
                os_enforcer.block_ip(client_ip)
            except Exception as e:
                logger.error(f"❌ Failed to block malicious IP {client_ip}: {e}")
            
            logger.warning(f"🤖 AI threat blocked: {client_ip} - {reason}")
            logger.debug(f"🔍 Malicious content: {malicious_content}")
            
            return jsonify({
                "status": "blocked",
                "reason": reason,
                "threat_type": threat_type,
                "ip": client_ip,
                "detected_in": malicious_content[:100] + ("..." if len(malicious_content) > 100 else "")
            }), 403
        
        # Request is allowed
        try:
            request_body = request.get_data(as_text=True) or ""
        except Exception:
            request_body = ""
        
        logger.info(f"✅ Request allowed: {client_ip} - {method} {full_path}")
        
        return jsonify({
            "status": "allowed",
            "method": method,
            "path": full_path,
            "ip": client_ip,
            "timestamp": time.time(),
            "echo": request_body[:200] + ("..." if len(request_body) > 200 else "")
        })
    
    except Exception as e:
        logger.error(f"❌ Firewall handler error: {e}")
        return jsonify({
            "status": "error",
            "reason": "internal server error",
            "message": str(e)
        }), 500

# =============================================================================
# APPLICATION STARTUP & SHUTDOWN
# =============================================================================

def initialize_firewall():
    """Initialize all firewall components"""
    logger.info("🔥 Initializing AI-Powered Firewall v2.0.0")
    logger.info(f"📊 Configuration:")
    logger.info(f"   - Block TTL: {FirewallConfig.BLOCK_TTL}s")
    logger.info(f"   - DDoS Protection: {FirewallConfig.DDOS_MAX_REQUESTS} req/{FirewallConfig.DDOS_WINDOW}s")
    logger.info(f"   - OS Enforcement: {os_enforcer.get_method()}")
    logger.info(f"   - Network Monitoring: {'enabled' if FirewallConfig.ENABLE_NETWORK_MONITORING else 'disabled'}")
    logger.info(f"   - Debug Mode: {'enabled' if FirewallConfig.DEBUG_MODE else 'disabled'}")
    
    # Start network monitoring
    network_monitor.start()
    
    logger.info("🚀 Firewall initialization complete")

def cleanup_firewall():
    """Cleanup firewall resources"""
    logger.info("🛑 Shutting down firewall...")
    
    try:
        network_monitor.stop()
        # Add any other cleanup here
        logger.info("✅ Firewall shutdown complete")
    except Exception as e:
        logger.error(f"❌ Error during shutdown: {e}")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main application entry point"""
    try:
        # Initialize firewall
        initialize_firewall()
        
        # Start Flask application
        app.run(
            host="0.0.0.0",
            port=8080,
            debug=FirewallConfig.DEBUG_MODE,
            use_reloader=False,
            threaded=True
        )
    
    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal")
        cleanup_firewall()
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        cleanup_firewall()
        sys.exit(1)

if __name__ == "__main__":
    main()
