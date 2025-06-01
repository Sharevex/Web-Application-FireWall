#!/usr/bin/env python3
"""
helper.py - Database setup script for admin database
Identifies OS, installs MySQL if needed, and creates database with users table
Handles auth_socket authentication issue and auto-secures root with root:root
"""

import platform
import sys
import subprocess
import os
import hashlib

def identify_os():
    """Identify the operating system"""
    system = platform.system().lower()
    if system == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content:
                    return 'ubuntu'
                return 'linux'
        except FileNotFoundError:
            return 'linux'
    if system == 'darwin':
        return 'mac'
    if system == 'windows':
        return 'windows'
    return 'unknown'

def run_command(command, use_sudo=False, input_text=None):
    """Run a system command"""
    if use_sudo and os.geteuid() != 0:
        command = f"sudo {command}"
    try:
        print(f"Running: {command}")
        if input_text is not None:
            proc = subprocess.Popen(
                command, shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            out, err = proc.communicate(input=input_text)
            code = proc.returncode
        else:
            proc = subprocess.run(
                command, shell=True,
                capture_output=True, text=True
            )
            out, err, code = proc.stdout, proc.stderr, proc.returncode

        if code == 0:
            print("✓ Command executed successfully")
            if out:
                print(f"Output: {out.strip()}")
            return True, out
        print(f"✗ Command failed (code {code})")
        if err:
            print(f"Error: {err.strip()}")
        return False, err
    except Exception as e:
        print(f"✗ Exception: {e}")
        return False, str(e)

def install_mysql_connector():
    """Install mysql-connector-python"""
    print("Installing mysql-connector-python...")
    ok, _ = run_command("pip3 install mysql-connector-python")
    if not ok:
        ok, _ = run_command("pip install mysql-connector-python")
    return ok

def install_mysql_ubuntu():
    """Install MySQL on Ubuntu"""
    print("Installing MySQL Server on Ubuntu...")
    if not run_command("apt update", use_sudo=True)[0]:
        return False
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    if not run_command("apt install -y mysql-server", use_sudo=True)[0]:
        return False
    if not run_command("systemctl start mysql", use_sudo=True)[0]:
        return False
    ok, _ = run_command("systemctl enable mysql", use_sudo=True)
    if not ok:
        print("Warning: Could not enable MySQL on boot")
    print("✓ MySQL installed and started")
    return True

def fix_mysql_auth_and_secure():
    """Automatically secure MySQL with root:root credentials"""
    print("Configuring MySQL authentication and security...")
    root_password = "root"

    sql = f"""
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{root_password}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SELECT 'MySQL secured with root:root' AS Status;
"""
    tmp = '/tmp/mysql_secure.sql'
    try:
        with open(tmp, 'w') as f:
            f.write(sql)
        ok, _ = run_command(f"mysql < {tmp}", use_sudo=True)
        os.remove(tmp)
        if ok:
            print("✓ MySQL root password set to root")
            return root_password
        print("✗ Failed to secure MySQL")
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        if os.path.exists(tmp):
            os.remove(tmp)
        return None

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_user_credentials():
    """Get username and password for the new user"""
    print("\nCreate New User Account\n" + "-"*25)
    uname = input("Enter username: ").strip()
    while not uname:
        print("Username cannot be empty!")
        uname = input("Enter username: ").strip()
    import getpass
    pw = getpass.getpass("Enter password: ")
    while not pw:
        print("Password cannot be empty!")
        pw = getpass.getpass("Enter password: ")
    confirm = getpass.getpass("Confirm password: ")
    while pw != confirm:
        print("Passwords don't match!")
        pw = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
    return uname, pw

def create_db_user_sudo(uname, upw):
    print("Creating database and user via sudo mysql...")
    ph = hash_password(upw)
    sql = f"""
CREATE DATABASE IF NOT EXISTS admin;
USE admin;
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
INSERT INTO users (username,password_hash,is_active)
VALUES ('{uname}','{ph}',TRUE);
SELECT 'Done' AS Status;
"""
    tmp = '/tmp/create_db_user.sql'
    try:
        with open(tmp, 'w') as f:
            f.write(sql)
        ok, _ = run_command(f"mysql < {tmp}", use_sudo=True)
        os.remove(tmp)
        if ok:
            print("✓ admin DB and user table created")
            print(f"✓ User '{uname}' inserted")
            return True
        print("✗ Failed to create DB/user")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        if os.path.exists(tmp):
            os.remove(tmp)
        return False

def create_db_user_pw(root_pw, uname, upw):
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host='localhost', user='root',
            password=root_pw, auth_plugin='mysql_native_password'
        )
        cur = conn.cursor()
        cur.execute("CREATE DATABASE IF NOT EXISTS admin")
        print("✓ admin DB created")
        cur.execute("USE admin")
        cur.execute("""
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)""")
        print("✓ users table created")
        ph = hash_password(upw)
        cur.execute(
            "INSERT INTO users (username,password_hash,is_active) VALUES (%s,%s,%s)",
            (uname, ph, True)
        )
        conn.commit()
        print(f"✓ User '{uname}' created")
        cur.close()
        conn.close()
        return True
    except mysql.connector.IntegrityError as e:
        if "Duplicate" in str(e):
            print(f"✗ Username '{uname}' exists")
        else:
            print(f"✗ IntegrityError: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_mysql_connection():
    """Test MySQL connection methods"""
    print("Testing MySQL connection methods...")
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host='localhost', user='root', password='', connect_timeout=5
        )
        conn.close()
        print("✓ No-password access")
        return 'no_password', ''
    except:
        pass
    try:
        res = subprocess.run(
            ['sudo','mysql','-e','SELECT 1;'],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode == 0:
            print("✓ Auth_socket access")
            return 'auth_socket', None
    except:
        pass
    print("Password auth required")
    return 'password_required', None

def main():
    print("="*60)
    print("MySQL Database Setup Script with Auth Fix")
    print("="*60)
    if os.geteuid() != 0:
        print("Note: sudo may be required for some operations")

    os_type = identify_os()
    print(f"Detected OS: {os_type.upper()}")

    try:
        import mysql.connector
        print("✓ mysql-connector-python available")
    except ImportError:
        if not install_mysql_connector():
            print("✗ Could not install connector")
            sys.exit(1)
        import mysql.connector

    conn_type, root_pw = test_mysql_connection()

    if conn_type == 'no_password':
        print("Fresh install detected → securing with root:root")
        root_pw = fix_mysql_auth_and_secure()
        if not root_pw:
            sys.exit(1)
        conn_type = 'password'
    elif conn_type == 'auth_socket':
        print("Auth_socket detected → securing with root:root")
        root_pw = fix_mysql_auth_and_secure()
        if not root_pw:
            sys.exit(1)
        conn_type = 'password'
    elif conn_type == 'password_required':
        print("Using default root:root credentials")
        root_pw = "root"
        conn_type = 'password'

    uname, upw = get_user_credentials()

    if conn_type == 'password':
        success = create_db_user_pw(root_pw, uname, upw)
    else:
        success = create_db_user_sudo(uname, upw)

    if success:
        print("\n" + "="*60)
        print("Setup completed successfully!")
        print("="*60)
        print(f"Database: admin")
        print(f"Table: users")
        print(f"User: {uname} (active)")
        if conn_type == 'password':
            print("\nYou can now connect with: mysql -u root -proot")
    else:
        print("\n✗ Setup failed")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)
