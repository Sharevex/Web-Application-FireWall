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
import time
import socket

def identify_os():
    """Identify the operating system"""
    system = platform.system().lower()
    if system == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content or 'debian' in content:
                    return 'ubuntu'
                elif 'centos' in content or 'rhel' in content or 'fedora' in content:
                    return 'centos'
                return 'linux'
        except FileNotFoundError:
            return 'linux'
    elif system == 'darwin':
        return 'mac'
    elif system == 'windows':
        return 'windows'
    return 'unknown'

def check_port_open(host='localhost', port=3306, timeout=5):
    """Check if MySQL port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def run_command(command, use_sudo=False, input_text=None, timeout=300):
    """Run a system command with better error handling"""
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
            out, err = proc.communicate(input=input_text, timeout=timeout)
            code = proc.returncode
        else:
            proc = subprocess.run(
                command, shell=True,
                capture_output=True, text=True, timeout=timeout
            )
            out, err, code = proc.stdout, proc.stderr, proc.returncode

        if code == 0:
            print("✓ Command executed successfully")
            if out and out.strip():
                print(f"Output: {out.strip()}")
            return True, out
        else:
            print(f"✗ Command failed (code {code})")
            if err and err.strip():
                print(f"Error: {err.strip()}")
            return False, err
    except subprocess.TimeoutExpired:
        print(f"✗ Command timed out after {timeout} seconds")
        return False, "Command timeout"
    except Exception as e:
        print(f"✗ Exception: {e}")
        return False, str(e)

def install_mysql_connector():
    """Install mysql-connector-python"""
    print("Installing mysql-connector-python...")
    
    # Try pip3 first
    ok, _ = run_command("pip3 install mysql-connector-python")
    if ok:
        return True
    
    # Try pip
    ok, _ = run_command("pip install mysql-connector-python")
    if ok:
        return True
    
    # Try with --user flag
    ok, _ = run_command("pip3 install --user mysql-connector-python")
    if ok:
        return True
    
    print("✗ Failed to install mysql-connector-python")
    return False

def wait_for_mysql_start(max_wait=30):
    """Wait for MySQL to start and be ready for connections"""
    print("Waiting for MySQL to start...")
    for i in range(max_wait):
        if check_port_open():
            print("✓ MySQL is ready for connections")
            time.sleep(2)  # Give it a bit more time to fully initialize
            return True
        time.sleep(1)
        if i % 5 == 0:
            print(f"Still waiting... ({i}/{max_wait}s)")
    
    print("✗ MySQL did not start within expected time")
    return False

def install_mysql_ubuntu():
    """Install MySQL on Ubuntu/Debian"""
    print("Installing MySQL Server on Ubuntu/Debian...")
    
    # Update package list
    if not run_command("apt update", use_sudo=True)[0]:
        print("✗ Failed to update package list")
        return False
    
    # Set non-interactive mode
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    
    # Install MySQL server
    if not run_command("apt install -y mysql-server", use_sudo=True)[0]:
        print("✗ Failed to install MySQL server")
        return False
    
    # Start MySQL service
    if not run_command("systemctl start mysql", use_sudo=True)[0]:
        print("✗ Failed to start MySQL service")
        return False
    
    # Enable MySQL on boot
    ok, _ = run_command("systemctl enable mysql", use_sudo=True)
    if not ok:
        print("Warning: Could not enable MySQL on boot")
    
    # Wait for MySQL to be ready
    if not wait_for_mysql_start():
        return False
    
    print("✓ MySQL installed and started successfully")
    return True

def install_mysql_centos():
    """Install MySQL on CentOS/RHEL/Fedora"""
    print("Installing MySQL Server on CentOS/RHEL/Fedora...")
    
    # Try different package managers
    package_managers = [
        ("dnf install -y mysql-server", "systemctl start mysqld"),
        ("yum install -y mysql-server", "systemctl start mysqld"),
        ("yum install -y mariadb-server", "systemctl start mariadb")
    ]
    
    for install_cmd, start_cmd in package_managers:
        if run_command(install_cmd, use_sudo=True)[0]:
            if run_command(start_cmd, use_sudo=True)[0]:
                run_command(start_cmd.replace("start", "enable"), use_sudo=True)
                if wait_for_mysql_start():
                    print("✓ MySQL/MariaDB installed and started successfully")
                    return True
            break
    
    print("✗ Failed to install MySQL/MariaDB")
    return False

def install_mysql_mac():
    """Install MySQL on macOS"""
    print("Installing MySQL on macOS...")
    
    # Check if Homebrew is installed
    if not run_command("which brew")[0]:
        print("Homebrew not found. Please install Homebrew first:")
        print("/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
        return False
    
    # Install MySQL via Homebrew
    if not run_command("brew install mysql")[0]:
        print("✗ Failed to install MySQL via Homebrew")
        return False
    
    # Start MySQL service
    if not run_command("brew services start mysql")[0]:
        print("✗ Failed to start MySQL service")
        return False
    
    if wait_for_mysql_start():
        print("✓ MySQL installed and started successfully")
        return True
    
    return False

def fix_mysql_auth_and_secure():
    """Automatically secure MySQL with root:root credentials"""
    print("Configuring MySQL authentication and security...")
    root_password = "root"

    sql_commands = f"""
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{root_password}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SELECT 'MySQL secured with root:root' AS Status;
"""
    
    tmp_file = '/tmp/mysql_secure.sql'
    try:
        with open(tmp_file, 'w') as f:
            f.write(sql_commands)
        
        # Try different methods to execute SQL
        methods = [
            f"mysql < {tmp_file}",
            f"mysql -u root < {tmp_file}",
            f"mysql --defaults-file=/dev/null -u root < {tmp_file}"
        ]
        
        for method in methods:
            ok, output = run_command(method, use_sudo=True)
            if ok:
                print("✓ MySQL root password set to 'root'")
                os.remove(tmp_file)
                return root_password
        
        print("✗ Failed to secure MySQL with all methods")
        os.remove(tmp_file)
        return None
        
    except Exception as e:
        print(f"✗ Error securing MySQL: {e}")
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        return None

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_user_credentials():
    """Get username and password for the new user"""
    print("\nCreate New User Account")
    print("-" * 25)
    
    # Get username
    username = input("Enter username: ").strip()
    while not username or len(username) < 3:
        if not username:
            print("Username cannot be empty!")
        else:
            print("Username must be at least 3 characters long!")
        username = input("Enter username: ").strip()
    
    # Get password
    import getpass
    password = getpass.getpass("Enter password: ")
    while not password or len(password) < 4:
        if not password:
            print("Password cannot be empty!")
        else:
            print("Password must be at least 4 characters long!")
        password = getpass.getpass("Enter password: ")
    
    # Confirm password
    confirm_password = getpass.getpass("Confirm password: ")
    while password != confirm_password:
        print("Passwords don't match!")
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
    
    return username, password

def create_db_user_sudo(username, user_password):
    """Create database and user via sudo mysql"""
    print("Creating database and user via sudo mysql...")
    password_hash = hash_password(user_password)
    
    sql_commands = f"""
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
INSERT INTO users (username, password_hash, is_active)
VALUES ('{username}', '{password_hash}', TRUE)
ON DUPLICATE KEY UPDATE
password_hash = '{password_hash}',
updated_at = CURRENT_TIMESTAMP;
SELECT 'Database and user created successfully' AS Status;
"""
    
    tmp_file = '/tmp/create_db_user.sql'
    try:
        with open(tmp_file, 'w') as f:
            f.write(sql_commands)
        
        ok, output = run_command(f"mysql < {tmp_file}", use_sudo=True)
        os.remove(tmp_file)
        
        if ok:
            print("✓ admin database and users table created")
            print(f"✓ User '{username}' created/updated successfully")
            return True
        else:
            print("✗ Failed to create database/user")
            return False
            
    except Exception as e:
        print(f"✗ Error creating database/user: {e}")
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        return False

def create_db_user_with_password(root_password, username, user_password):
    """Create database and user using root password"""
    try:
        import mysql.connector
        
        # Connect to MySQL
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password=root_password,
            auth_plugin='mysql_native_password',
            connect_timeout=10,
            autocommit=True
        )
        
        cursor = connection.cursor()
        
        # Create database
        cursor.execute("CREATE DATABASE IF NOT EXISTS admin")
        print("✓ admin database created")
        
        # Use the database
        cursor.execute("USE admin")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(64) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        print("✓ users table created")
        
        # Insert user
        password_hash = hash_password(user_password)
        cursor.execute("""
            INSERT INTO users (username, password_hash, is_active) 
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
            password_hash = %s,
            updated_at = CURRENT_TIMESTAMP
        """, (username, password_hash, True, password_hash))
        
        print(f"✓ User '{username}' created/updated successfully")
        
        cursor.close()
        connection.close()
        return True
        
    except mysql.connector.Error as e:
        print(f"✗ MySQL Error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_mysql_connection():
    """Test MySQL connection methods"""
    print("Testing MySQL connection methods...")
    
    # First check if MySQL is running
    if not check_port_open():
        print("✗ MySQL server is not running on port 3306")
        return 'not_running', None
    
    try:
        import mysql.connector
        
        # Test no password access
        try:
            connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',
                connect_timeout=5
            )
            connection.close()
            print("✓ No-password access available")
            return 'no_password', ''
        except mysql.connector.Error:
            pass
        
        # Test with default root password
        try:
            connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password='root',
                connect_timeout=5
            )
            connection.close()
            print("✓ Root password is 'root'")
            return 'password', 'root'
        except mysql.connector.Error:
            pass
        
    except ImportError:
        print("mysql-connector-python not available for testing")
    
    # Test auth_socket via sudo
    try:
        result = subprocess.run(
            ['sudo', 'mysql', '-e', 'SELECT 1;'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print("✓ Auth_socket access available")
            return 'auth_socket', None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("? Password authentication required (unknown password)")
    return 'password_required', None

def ensure_mysql_installed():
    """Ensure MySQL is installed and running"""
    os_type = identify_os()
    
    if not check_port_open():
        print("MySQL not running. Attempting to install/start...")
        
        if os_type == 'ubuntu':
            if not install_mysql_ubuntu():
                return False
        elif os_type == 'centos':
            if not install_mysql_centos():
                return False
        elif os_type == 'mac':
            if not install_mysql_mac():
                return False
        else:
            print(f"✗ Unsupported OS: {os_type}")
            print("Please install MySQL manually and ensure it's running on port 3306")
            return False
    
    return True

def main():
    """Main function"""
    print("=" * 60)
    print("MySQL Database Setup Script with Enhanced Error Handling")
    print("=" * 60)
    
    if os.geteuid() != 0:
        print("Note: sudo may be required for some operations")

    os_type = identify_os()
    print(f"Detected OS: {os_type.upper()}")

    # Install mysql-connector-python if needed
    try:
        import mysql.connector
        print("✓ mysql-connector-python is available")
    except ImportError:
        print("mysql-connector-python not found, installing...")
        if not install_mysql_connector():
            print("✗ Could not install mysql-connector-python")
            sys.exit(1)
        try:
            import mysql.connector
            print("✓ mysql-connector-python installed successfully")
        except ImportError:
            print("✗ mysql-connector-python installation failed")
            sys.exit(1)

    # Ensure MySQL is installed and running
    if not ensure_mysql_installed():
        print("✗ Failed to ensure MySQL is running")
        sys.exit(1)

    # Test connection methods
    connection_type, root_password = test_mysql_connection()
    
    if connection_type == 'not_running':
        print("✗ MySQL server is not running")
        sys.exit(1)
    elif connection_type == 'no_password':
        print("Fresh MySQL installation detected → securing with root:root")
        root_password = fix_mysql_auth_and_secure()
        if not root_password:
            print("✗ Failed to secure MySQL")
            sys.exit(1)
        connection_type = 'password'
    elif connection_type == 'auth_socket':
        print("Auth_socket detected → securing with root:root")
        root_password = fix_mysql_auth_and_secure()
        if not root_password:
            print("✗ Failed to secure MySQL")
            sys.exit(1)
        connection_type = 'password'
    elif connection_type == 'password_required':
        print("Password authentication required")
        root_password = input("Enter MySQL root password (or press Enter for 'root'): ").strip()
        if not root_password:
            root_password = "root"
        connection_type = 'password'

    # Get user credentials
    username, user_password = get_user_credentials()

    # Create database and user
    success = False
    if connection_type == 'password':
        success = create_db_user_with_password(root_password, username, user_password)
    else:
        success = create_db_user_sudo(username, user_password)

    # Final status
    if success:
        print("\n" + "=" * 60)
        print("Setup completed successfully!")
        print("=" * 60)
        print(f"Database: admin")
        print(f"Table: users")
        print(f"User: {username} (active)")
        print(f"MySQL root password: {root_password}")
        print(f"\nYou can now connect with: mysql -u root -p{root_password}")
        print("Or test the connection with the created user account.")
    else:
        print("\n✗ Setup failed")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
