#!/usr/bin/env python3

"""
Combined Dynamic Firewall with:
- Network-level IPS/IDS (packet sniffing with Scapy and ML-based detection)
- Application-level firewall with DDoS prevention, AI- & rule-based detection,
  and a live dashboard (Flask).
"""

import os
import sys
import re
import subprocess
import time
import json
import joblib
import threading
from collections import defaultdict, deque
from flask import Flask, render_template, request, make_response, redirect, url_for , jsonify , session
import logging
import numpy as np
from scapy.all import sniff, IP, TCP, Raw
import psutil
import random
import mysql.connector
import base64
import hashlib
from datetime import datetime, timedelta

# Load database configuration from file
def load_db_config():
    config_file = "/Web-Application-FireWall/database_config.txt"
    config = {}
    try:
        with open(config_file, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        config[key] = value
        
        return {
            'host': config.get('DATABASE_HOST', 'localhost'),
            'user': config.get('DATABASE_USER', 'admin_user'),
            'password': config.get('DATABASE_PASSWORD', ''),
            'database': config.get('DATABASE_NAME', 'admin'),
            'port': int(config.get('DATABASE_PORT', '3306'))
        }
    except FileNotFoundError:
        print(f"Database config file not found: {config_file}")
        return {
            'host': 'localhost',
            'user': 'admin_user',
            'password': 'your_db_password',
            'database': 'admin',
            'port': 3306
        }

DB_CONFIG = load_db_config()

def get_db_connection():
    """Create and return a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

def init_database_tables():
    """Initialize additional tables for temporary storage"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        
        # Create temporary blocked IPs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS temp_blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                reason VARCHAR(255),
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_ip_active (ip_address, is_active),
                INDEX idx_expires (expires_at)
            )
        """)
        
        # Create temporary request logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS temp_request_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                request_data TEXT,
                result VARCHAR(50),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                INDEX idx_ip_timestamp (ip_address, timestamp),
                INDEX idx_expires (expires_at)
            )
        """)
        
        # Create temporary statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS temp_statistics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                stat_key VARCHAR(100) NOT NULL,
                stat_value INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                UNIQUE KEY unique_stat (stat_key)
            )
        """)
        
        # Create temporary IP request counts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS temp_ip_requests (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                request_count INT DEFAULT 1,
                last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                UNIQUE KEY unique_ip (ip_address)
            )
        """)
        
        connection.commit()
        print("Database tables initialized successfully")
        return True
        
    except mysql.connector.Error as err:
        print(f"Database table creation error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def cleanup_expired_data():
    """Clean up expired temporary data from database"""
    connection = get_db_connection()
    if not connection:
        return
    
    try:
        cursor = connection.cursor()
        now = datetime.now()
        
        # Clean up expired blocked IPs
        cursor.execute("DELETE FROM temp_blocked_ips WHERE expires_at < %s", (now,))
        
        # Clean up expired request logs
        cursor.execute("DELETE FROM temp_request_logs WHERE expires_at < %s", (now,))
        
        # Clean up expired statistics
        cursor.execute("DELETE FROM temp_statistics WHERE expires_at < %s", (now,))
        
        # Clean up expired IP request counts
        cursor.execute("DELETE FROM temp_ip_requests WHERE expires_at < %s", (now,))
        
        connection.commit()
        
    except mysql.connector.Error as err:
        print(f"Database cleanup error: {err}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def save_blocked_ip_to_db(ip_address, reason, duration_hours=24):
    """Save blocked IP to database temporarily"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        query = """
            INSERT INTO temp_blocked_ips (ip_address, reason, expires_at)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
            reason = VALUES(reason),
            blocked_at = CURRENT_TIMESTAMP,
            expires_at = VALUES(expires_at),
            is_active = TRUE
        """
        
        cursor.execute(query, (ip_address, reason, expires_at))
        connection.commit()
        return True
        
    except mysql.connector.Error as err:
        print(f"Database save blocked IP error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def is_ip_blocked_in_db(ip_address):
    """Check if IP is blocked in database"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        now = datetime.now()
        
        query = """
            SELECT id FROM temp_blocked_ips 
            WHERE ip_address = %s AND is_active = TRUE AND expires_at > %s
        """
        
        cursor.execute(query, (ip_address, now))
        result = cursor.fetchone()
        return result is not None
        
    except mysql.connector.Error as err:
        print(f"Database check blocked IP error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def save_request_log_to_db(ip_address, request_data, result, duration_hours=168):  # 7 days default
    """Save request log to database temporarily"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        query = """
            INSERT INTO temp_request_logs (ip_address, request_data, result, expires_at)
            VALUES (%s, %s, %s, %s)
        """
        
        cursor.execute(query, (ip_address, request_data[:1000], result, expires_at))  # Limit data length
        connection.commit()
        return True
        
    except mysql.connector.Error as err:
        print(f"Database save request log error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def update_ip_request_count_in_db(ip_address, duration_hours=24):
    """Update IP request count in database"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        query = """
            INSERT INTO temp_ip_requests (ip_address, request_count, expires_at)
            VALUES (%s, 1, %s)
            ON DUPLICATE KEY UPDATE
            request_count = request_count + 1,
            last_request = CURRENT_TIMESTAMP,
            expires_at = VALUES(expires_at)
        """
        
        cursor.execute(query, (ip_address, expires_at))
        connection.commit()
        return True
        
    except mysql.connector.Error as err:
        print(f"Database update IP count error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_top_ips_from_db(limit=5):
    """Get top IPs by request count from database"""
    connection = get_db_connection()
    if not connection:
        return []
    
    try:
        cursor = connection.cursor()
        now = datetime.now()
        
        query = """
            SELECT ip_address, request_count 
            FROM temp_ip_requests 
            WHERE expires_at > %s 
            ORDER BY request_count DESC 
            LIMIT %s
        """
        
        cursor.execute(query, (now, limit))
        results = cursor.fetchall()
        return [(ip, count) for ip, count in results]
        
    except mysql.connector.Error as err:
        print(f"Database get top IPs error: {err}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def save_statistics_to_db(stats_dict, duration_hours=24):
    """Save statistics to database temporarily"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        for key, value in stats_dict.items():
            query = """
                INSERT INTO temp_statistics (stat_key, stat_value, expires_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                stat_value = VALUES(stat_value),
                updated_at = CURRENT_TIMESTAMP,
                expires_at = VALUES(expires_at)
            """
            
            cursor.execute(query, (key, value, expires_at))
        
        connection.commit()
        return True
        
    except mysql.connector.Error as err:
        print(f"Database save statistics error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def hash_credential(credential):
    """Hash a credential using SHA256 and return base64 encoded result"""
    hashed = hashlib.sha256(credential.encode('utf-8')).digest()
    return base64.b64encode(hashed).decode('utf-8')

def verify_credentials(username, password):
    """Verify username and password against the database"""
    connection = get_db_connection()
    if not connection:
        return False
    try:
        cursor = connection.cursor()
        
        # Hash the provided credentials
        hashed_username = hash_credential(username)
        hashed_password = hash_credential(password)
        
        # Query to check if user exists with matching credentials
        query = """
        SELECT u.id 
        FROM users u 
        WHERE u.username = %s AND u.password_hash = %s AND u.is_active = TRUE
        """
        
        cursor.execute(query, (username, hashed_password))
        result = cursor.fetchone()
        
        return result is not None
        
    except mysql.connector.Error as err:
        print(f"Database query error: {err}")
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Import the AI detector (must be present in PYTHONPATH)
from ai_detector import detect_attack

# ---- OS DETECTION -------------------
from os_detection import detect_os
current_os = detect_os()  # 'linux', 'windows', 'darwin'
# --------------------------------------

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------------------------------------------------------------
# Environment / globals
# ---------------------------------------------------------------------------
ddos_limiter = None                             # initialised further below
stats = None
ip_request_count = defaultdict(int)             # {ip: hits}
blocked_ips = set()                             # in-memory (also persisted to blocked.txt)

##############################################################################
#                              DDoS Limiter                                  #
##############################################################################
class DDoSRateLimiter:
    def __init__(self, time_window: int = 60, max_requests: int = 20):
        self.time_window = time_window
        self.max_requests = max_requests
        self.requests_log = defaultdict(deque)  # {ip: deque[timestamps]}

    def is_ddos(self, ip: str) -> bool:
        now = time.time()
        dq = self.requests_log[ip]

        # Remove timestamps older than window
        while dq and dq[0] < now - self.time_window:
            dq.popleft()

        # Check current count
        if len(dq) >= self.max_requests:
            return True

        dq.append(now)
        return False

##############################################################################
#                                 Stats                                      #
##############################################################################
class FirewallStats:
    def __init__(self) -> None:
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0
        self.ddos_blocks = 0
        self.rule_based_blocks = 0
        self.ai_based_blocks = 0
        self.network_blocks = 0   # network-level IPS/IDS

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

    def save_to_db(self):
        """Save current statistics to database"""
        save_statistics_to_db(self.to_dict())

# Instantiate globals
ddos_limiter = DDoSRateLimiter(time_window=60, max_requests=20)
stats = FirewallStats()

##############################################################################
#                        Rule-based App-level detection                      #
##############################################################################
attack_patterns = {
    "sql_injection":  r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bOR\s+1=1\b|\bWHERE\s+1=1\b|--)",
    "xss":            r"(<script>|alert\(|onerror=)",
    "path_traversal": r"(\.\./|\b/etc/passwd\b)",
}

def rule_based_detect(data: str):
    for attack, pattern in attack_patterns.items():
        if re.search(pattern, data, re.IGNORECASE):
            return True, attack
    return False, None

##############################################################################
#                       Network-level IPS/IDS helpers                        #
##############################################################################
def extract_features(packet):
    """Simple handcrafted feature vector from a Scapy packet."""
    feats = []

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        feats.extend((ip_layer.len, ip_layer.ttl))

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        feats.extend((int(tcp_layer.flags), tcp_layer.sport, tcp_layer.dport))

    # Raw payload length
    payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
    feats.append(payload_len)

    return np.array(feats).reshape(1, -1)

def ml_predict(packet) -> bool:
    """
    Placeholder ML-style detector. Replace with a real model inference if desired.
    """
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            if any(kw in payload.upper() for kw in ("DROP TABLE", "SELECT * FROM", "OR 1=1")):
                return True
        except Exception as exc:
            logging.error(f"Payload decode error: {exc}")
    return False

def block_ip(ip_address: str) -> None:
    """
    Add an OS-specific firewall rule to block the offending IP.
    """
    if current_os == "linux":
        cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    elif current_os == "windows":
        cmd = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
    elif current_os == "darwin":
        # Example for macOS/darwin (pfctl). You should adjust as needed:
        cmd = f"echo 'block drop from {ip_address} to any' | sudo pfctl -ef -"
    else:
        logging.warning(f"Unsupported OS '{current_os}' – cannot block {ip_address} automatically.")
        return

    logging.info(f"Blocking IP {ip_address} using command:\n  {cmd}")
    os.system(cmd)
    stats.network_blocks += 1
    add_blocked_ip(ip_address, "Network-level threat detected")

def is_ip_blocked(ip: str) -> bool:
    # Check both in-memory and database
    return ip in blocked_ips or is_ip_blocked_in_db(ip)

def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if ml_predict(packet):
        logging.warning(f"Network-level malicious packet detected: {src_ip} → {dst_ip} – blocking.")
        block_ip(src_ip)

def start_packet_sniffing():
    logging.info("Starting Scapy sniffing thread (network-level IPS/IDS)…")
    sniff(filter="ip", prn=process_packet, store=0)

##############################################################################
#                              Flask app                                     #
##############################################################################
app = Flask(__name__)
app.config['DEBUG'] = True
app.secret_key = 'Ja0RSgXjEotzDuPEVP4aS3jyQg3EUaKN'

def get_cpu_usage():
    total_cpu = psutil.cpu_percent(interval=1)
    core_count = psutil.cpu_count(logical=True)
    return {
        "total": total_cpu,
        "cores": core_count
    }

def get_uptime():
    boot_time = psutil.boot_time()
    current_time = time.time()
    uptime_seconds = current_time - boot_time

    uptime_days = int(uptime_seconds // (24 * 3600))
    uptime_hours = int((uptime_seconds % (24 * 3600)) // 3600)
    uptime_minutes = int((uptime_seconds % 3600) // 60)
    uptime_seconds = int(uptime_seconds % 60)

    return {
        "uptime_seconds": int(current_time - boot_time),
        "formatted": f"{uptime_days}d {uptime_hours}h {uptime_minutes}m {uptime_seconds}s"
    }

# Get RAM usage
def get_ram_usage():
    memory = psutil.virtual_memory()
    return {
        "total": round(memory.total / (1024**3), 2),  # GB
        "used": round(memory.used / (1024**3), 2),
        "free": round(memory.free / (1024**3), 2),
        "percent": memory.percent
    }

# Get disk usage
def get_disk_usage():
    try:
        usage = psutil.disk_usage('/')
        disk_data = [{
            "device": "root",
            "mountpoint": "/",
            "total": round(usage.total / (1024**3), 2),  # GB
            "used": round(usage.used / (1024**3), 2),
            "free": round(usage.free / (1024**3), 2),
            "percent": usage.percent
        }]
        return disk_data
    except PermissionError:
        return []  # Return empty list if permission denied

@app.route('/metrics')
def metrics():
    client_ip = request.remote_addr or "unknown"
    if is_ip_blocked(client_ip):
        return jsonify({"status": "blocked", "reason": "IP blacklisted"}), 403
    data = {
        "cpu": get_cpu_usage(),
        "ram": get_ram_usage(),
        "disk": get_disk_usage(),
        "uptime":get_uptime(),
        "timestamp": time.time()
    }
    return jsonify(data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    
    client_ip = request.remote_addr or "unknown"
    if is_ip_blocked(client_ip):
        return jsonify({"status": "blocked", "reason": "IP blacklisted"}), 403
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username or not password:
            error = 'Username and password are required.'
        elif verify_credentials(username, password):
            session['user'] = username  # set session flag
            return redirect('/dashboard')
        else:
            error = 'Invalid username or password.'
    
    return render_template('login.html', error=error)

@app.route("/stats")
def stats_endpoint():
    client_ip = request.remote_addr or "unknown"
    if is_ip_blocked(client_ip):
        return jsonify({"status": "blocked", "reason": "IP blacklisted"}), 403
    return jsonify(stats.to_dict())

@app.route("/top_ips")
def top_ips():
    # Get top IPs from database instead of in-memory
    top_ips_db = get_top_ips_from_db(5)
    return jsonify(dict(top_ips_db))

@app.route("/dashboard")
def dashboard():
    client_ip = request.remote_addr or "unknown"
    
    if is_ip_blocked(client_ip):
        logging.warning(f"Blocked IP {client_ip} attempted dashboard access")
        return jsonify({"status": "blocked", "reason": "IP blacklisted"}), 403

    if session.get('user') != 'sharevex':
        return redirect(url_for('login'))

    top_ips, top_reasons = get_top_blocked_ips_and_reasons()
    try:
        return render_template(
            "dashboard.html",
            top_ips=top_ips,
            top_reasons=top_reasons
        )
    except Exception:
        return jsonify({
            "message": "Dashboard template not found – create templates/dashboard.html to enable the UI.",
            "stats": stats.to_dict(),
            "top_ips": dict(get_top_ips_from_db(5))
        })

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def firewall_route(path):
    client_ip = request.remote_addr or "unknown"
    stats.total_requests += 1
    ip_request_count[client_ip] += 1
    
    # Update IP request count in database
    update_ip_request_count_in_db(client_ip)

    # --- 1) DDoS limiter ----------------------------------------------------
    if ddos_limiter.is_ddos(client_ip):
        stats.blocked_requests += 1
        stats.ddos_blocks += 1
        reason = "DDoS detected (rate limit)"
        add_blocked_ip(client_ip, reason)
        log_request_details(client_ip, "<rate-limited>", f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 429
    
    # --- 2) Payload inspection ---------------------------------------------
    data = request.get_data(as_text=True) or ""
    
    # Skip blocking if the request is a simple page refresh (common pattern in refresh requests)
    referer = request.headers.get('Referer', '')
    is_refresh = referer and ('/dashboard' in referer or path in referer)

    if is_refresh:
        stats.allowed_requests += 1
        log_request_details(client_ip, data, "allowed (refresh)")
        return jsonify({"status": "allowed", "echo": data})

    # Rule-based detection
    rule_flag, attack_type = rule_based_detect(data)
    ai_label = detect_attack(data)

    # AI detector output interpretation
    if ai_label != 0:
        stats.blocked_requests += 1
        stats.ai_based_blocks += 1
        reason = {1: "SQLi (AI)", 2: "XSS (AI)", 3: "DDoS (AI)"}.get(ai_label, "Anomaly (AI)")
        add_blocked_ip(client_ip, reason)
        log_request_details(client_ip, data, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    if rule_flag:
        stats.blocked_requests += 1
        stats.rule_based_blocks += 1
        reason = attack_type
        add_blocked_ip(client_ip, reason)
        log_request_details(client_ip, data, f"blocked – {reason}")
        return jsonify({"status": "blocked", "reason": reason}), 403

    stats.allowed_requests += 1
    log_request_details(client_ip, data, "allowed")
    return jsonify({"status": "allowed", "echo": data})

##############################################################################
#                           Helper functions                                 #
##############################################################################
def log_request_details(ip: str, data: str, result: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {result} - {data}\n"
    try:
        with open("firewall.log", "a") as f:
            f.write(line)
        # Also save to database temporarily
        save_request_log_to_db(ip, data, result)
    except Exception as exc:
        print(f"Log write error: {exc}")

def load_blocked_ips():
    try:
        with open("blocked.txt", "r") as f:
            for line in f:
                if ',' in line:
                    ip, _ = line.strip().split(",", 1)
                    blocked_ips.add(ip)
    except FileNotFoundError:
        pass

def add_blocked_ip(ip: str, reason: str) -> None:
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    try:
        with open("blocked.txt", "a") as f:
            f.write(f"{ip},{reason}\n")
        # Also save to database temporarily (24 hours default)
        save_blocked_ip_to_db(ip, reason, 24)
    except Exception as exc:
        print(f"blocked.txt write error: {exc}")

def get_top_blocked_ips_and_reasons(n: int = 5):
    try:
        with open("blocked.txt", "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        recent_entries = lines[-n:]
        ips = [entry.split(",")[0] for entry in recent_entries]
        reasons = [entry.split(",", 1)[1] if "," in entry else "Unknown" for entry in recent_entries]
        return ips, reasons
    except FileNotFoundError:
        return [], []

def print_statistics() -> None:
    sep = "-" * 48
    print(f"\n{sep}\n[DYNAMIC UPDATE @ {time.strftime('%H:%M:%S')}]\n{sep}")
    for k, v in stats.to_dict().items():
        print(f"{k.replace('_', ' ').title():22}: {v}")
    print("Top 5 IPs:")
    
    # Get top IPs from database
    top_ips_db = get_top_ips_from_db(5)
    for ip, cnt in top_ips_db:
        print(f"  {ip:>15}  -> {cnt}")
    print(sep)
    
    # Save statistics to database
    stats.save_to_db()

def dynamic_update() -> None:
    while True:
        time.sleep(10)
        print_statistics()
        # Clean up expired data every 10 minutes
        if int(time.time()) % 600 == 0:  # Every 10 minutes
            cleanup_expired_data()

def run_server() -> None:
    logging.info("Starting Flask server on 0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)

def deployment_helper() -> None:
    print("\n=== Deployment Summary ===")
    print(f"Operating System  : {current_os}")
    print("Network IPS/IDS   : ACTIVE")
    print("Flask Web Server  : http://0.0.0.0:8080")
    print("Dashboard         : http://0.0.0.0:8080/dashboard")
    print("Top IPs Endpoint  : http://0.0.0.0:8080/top_ips")
    print("Log File          : firewall.log")
    print("Blocked IPs File  : blocked.txt")
    print("Database Storage  : ACTIVE (temporary data)")
    print("===========================================\n")

##############################################################################
#                                Main                                        #
##############################################################################
if __name__ == "__main__":
    # Initialize database tables
    init_database_tables()
    
    # Load existing blocked IPs
    load_blocked_ips()
    
    sniff_thread = threading.Thread(target=start_packet_sniffing, daemon=True)
    sniff_thread.start()

    dyn_thread = threading.Thread(
        target=lambda: (time.sleep(2), deployment_helper(), dynamic_update()),
        daemon=True
    )
    dyn_thread.start()

    flask_thread = threading.Thread(target=run_server, daemon=True)
    flask_thread.start()

    print("Firewall server running on http://0.0.0.0:8080")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Quitting and running in the background…")
        # Re-run the script in the background using setsid
        subprocess.Popen(
            [sys.executable] + sys.argv,
            preexec_fn=os.setsid,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            close_fds=True
        )
        os._exit(0)
