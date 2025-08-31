import mysql.connector
import hashlib
import base64
import traceback

# MySQL connection config
MYSQL_CONN = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "admin",
    "password": "At@1381928",
    "database": "admin",
    "autocommit": True
}

def hash_password(password: str) -> str:
    """Hash the password (SHA-256 → Base64)"""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("utf-8")

def get_user(username: str):
    """Fetch (username, password_hash) from DB"""
    try:
        conn = mysql.connector.connect(**MYSQL_CONN)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, password_hash FROM users WHERE username = %s",
            (username,)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row if row else None
    except Exception:
        print("DB error in get_user:\n", traceback.format_exc())
        return None

def verify_user(username: str, password: str) -> bool:
    """Check if password matches stored hash"""
    user = get_user(username)
    if not user:
        return False
    return hash_password(password) == user[1]
