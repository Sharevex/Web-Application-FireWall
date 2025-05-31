#!/usr/bin/env python3
"""
helper.py - Database setup script for admin database
Identifies OS, installs MySQL if needed, and creates database with users table
Handles auth_socket authentication issue
"""

import platform
import sys
import getpass
import subprocess
import time
import os
import hashlib

def identify_os():
    """Identify the operating system"""
    system = platform.system().lower()
    
    if system == 'linux':
        # Check if it's Ubuntu specifically
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content:
                    return 'ubuntu'
                else:
                    return 'linux'
        except FileNotFoundError:
            return 'linux'
    elif system == 'darwin':
        return 'mac'
    elif system == 'windows':
        return 'windows'
    else:
        return 'unknown'

def run_command(command, use_sudo=False, input_text=None):
    """Run a system command"""
    if use_sudo and os.geteuid() != 0:
        command = f"sudo {command}"
    
    try:
        print(f"Running: {command}")
        if input_text:
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=input_text)
        else:
            process = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                check=False
            )
            stdout = process.stdout
            stderr = process.stderr
        
        if process.returncode == 0:
            print("✓ Command executed successfully")
            if stdout:
                print(f"Output: {stdout}")
            return True, stdout
        else:
            print(f"✗ Command failed with return code {process.returncode}")
            if stderr:
                print(f"Error: {stderr}")
            return False, stderr
    except Exception as e:
        print(f"✗ Exception running command: {e}")
        return False, str(e)

def install_mysql_connector():
    """Install mysql-connector-python"""
    print("Installing mysql-connector-python...")
    success, output = run_command("pip3 install mysql-connector-python")
    if not success:
        success, output = run_command("pip install mysql-connector-python")
    return success

def install_mysql_ubuntu():
    """Install MySQL on Ubuntu"""
    print("Installing MySQL Server on Ubuntu...")
    
    # Update package list
    success, _ = run_command("apt update", use_sudo=True)
    if not success:
        return False
    
    # Set non-interactive mode for MySQL installation
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    
    # Install MySQL server
    success, _ = run_command("apt install -y mysql-server", use_sudo=True)
    if not success:
        return False
    
    # Start MySQL service
    success, _ = run_command("systemctl start mysql", use_sudo=True)
    if not success:
        return False
    
    # Enable MySQL to start on boot
    success, _ = run_command("systemctl enable mysql", use_sudo=True)
    if not success:
        print("Warning: Could not enable MySQL to start on boot")
    
    print("✓ MySQL installed and started successfully")
    return True

def fix_mysql_auth_and_secure():
    """Fix MySQL authentication and secure the installation using sudo mysql"""
    print("Configuring MySQL authentication and security...")
    
    # Get the new root password
    root_password = getpass.getpass("Set new MySQL root password: ")
    confirm_password = getpass.getpass("Confirm MySQL root password: ")
    
    while root_password != confirm_password:
        print("Passwords don't match!")
        root_password = getpass.getpass("Set new MySQL root password: ")
        confirm_password = getpass.getpass("Confirm MySQL root password: ")
    
    # Create SQL commands to fix authentication and secure MySQL
    sql_commands = f"""
-- Fix root authentication
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '{root_password}';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root login
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Flush privileges
FLUSH PRIVILEGES;

-- Show that we're done
SELECT 'MySQL secured successfully' as Status;
"""
    
    # Write SQL commands to a temporary file
    temp_sql_file = '/tmp/mysql_secure.sql'
    try:
        with open(temp_sql_file, 'w') as f:
            f.write(sql_commands)
        
        # Execute the SQL commands using sudo mysql
        success, output = run_command(f"mysql < {temp_sql_file}", use_sudo=True)
        
        # Clean up temp file
        os.remove(temp_sql_file)
        
        if success:
            print("✓ MySQL authentication fixed and secured successfully")
            return root_password
        else:
            print("✗ Failed to secure MySQL")
            return None
            
    except Exception as e:
        print(f"✗ Error securing MySQL: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_sql_file):
            os.remove(temp_sql_file)
        return None

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_user_credentials():
    """Get username and password for the new user"""
    print("\nCreate New User Account")
    print("-" * 25)
    username = input("Enter username: ").strip()
    while not username:
        print("Username cannot be empty!")
        username = input("Enter username: ").strip()
    
    password = getpass.getpass("Enter password: ")
    while not password:
        print("Password cannot be empty!")
        password = getpass.getpass("Enter password: ")
    
    confirm_password = getpass.getpass("Confirm password: ")
    while password != confirm_password:
        print("Passwords don't match!")
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
    
    return username, password

def create_database_and_user_with_sudo(username, user_password):
    """Create database and user using sudo mysql (for auth_socket)"""
    print("Creating database and user using sudo mysql...")
    
    # Hash the password
    password_hash = hash_password(user_password)
    
    # Create SQL commands
    sql_commands = f"""
-- Create database
CREATE DATABASE IF NOT EXISTS admin;

-- Use the admin database
USE admin;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert user
INSERT INTO users (username, password_hash, is_active) 
VALUES ('{username}', '{password_hash}', TRUE);

-- Show success
SELECT 'Database and user created successfully' as Status;
SELECT * FROM users WHERE username = '{username}';
"""
    
    # Write SQL commands to a temporary file
    temp_sql_file = '/tmp/create_db_user.sql'
    try:
        with open(temp_sql_file, 'w') as f:
            f.write(sql_commands)
        
        # Execute the SQL commands using sudo mysql
        success, output = run_command(f"mysql < {temp_sql_file}", use_sudo=True)
        
        # Clean up temp file
        os.remove(temp_sql_file)
        
        if success:
            print("✓ Database 'admin' created successfully")
            print("✓ Table 'users' created successfully")
            print(f"✓ User '{username}' created successfully")
            return True
        else:
            print("✗ Failed to create database and user")
            return False
            
    except Exception as e:
        print(f"✗ Error creating database and user: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_sql_file):
            os.remove(temp_sql_file)
        return False

def create_database_and_user_with_password(mysql_password, username, user_password):
    """Create database and user using password authentication"""
    try:
        import mysql.connector
        
        # Connect to MySQL
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password=mysql_password,
            auth_plugin='mysql_native_password'
        )
        
        cursor = connection.cursor()
        
        # Create database
        cursor.execute("CREATE DATABASE IF NOT EXISTS admin")
        print("✓ Database 'admin' created successfully")
        
        # Use the admin database
        cursor.execute("USE admin")
        
        # Create users table
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(64) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
        """
        
        cursor.execute(create_table_query)
        print("✓ Table 'users' created successfully")
        
        # Hash the password and insert user
        password_hash = hash_password(user_password)
        insert_query = """
        INSERT INTO users (username, password_hash, is_active) 
        VALUES (%s, %s, %s)
        """
        
        cursor.execute(insert_query, (username, password_hash, True))
        connection.commit()
        
        print(f"✓ User '{username}' created successfully")
        
        cursor.close()
        connection.close()
        
        return True
        
    except mysql.connector.IntegrityError as e:
        if "Duplicate entry" in str(e):
            print(f"✗ Error: Username '{username}' already exists")
        else:
            print(f"✗ Integrity Error: {e}")
        return False
    
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_mysql_connection():
    """Test MySQL connection methods"""
    print("Testing MySQL connection methods...")
    
    # Method 1: Try connecting with no password (fresh install)
    try:
        import mysql.connector
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            connect_timeout=5
        )
        connection.close()
        print("✓ MySQL accessible with no password")
        return 'no_password', ''
    except mysql.connector.Error:
        pass
    
    # Method 2: Check if we can use sudo mysql (auth_socket)
    try:
        result = subprocess.run(
            ['sudo', 'mysql', '-e', 'SELECT 1;'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print("✓ MySQL accessible via sudo (auth_socket)")
            return 'auth_socket', None
    except:
        pass
    
    # Method 3: Need password
    print("MySQL requires password authentication")
    return 'password_required', None

def main():
    """Main function"""
    print("=" * 60)
    print("MySQL Database Setup Script with Auth Fix")
    print("=" * 60)
    
    # Check if running as root for installation
    if os.geteuid() != 0:
        print("Note: This script may need sudo privileges for MySQL operations")
    
    # Identify OS
    os_type = identify_os()
    print(f"Detected OS: {os_type.upper()}")
    
    # Install mysql-connector-python if not available
    try:
        import mysql.connector
        print("✓ mysql-connector-python is available")
    except ImportError:
        print("Installing mysql-connector-python...")
        if not install_mysql_connector():
            print("✗ Failed to install mysql-connector-python")
            sys.exit(1)
        # Re-import after installation
        import mysql.connector
    
    # Test MySQL connection
    connection_type, mysql_password = test_mysql_connection()
    
    if connection_type == 'no_password':
        print("Fresh MySQL installation detected")
        # Secure MySQL and set password
        mysql_password = fix_mysql_auth_and_secure()
        if mysql_password is None:
            print("✗ Failed to secure MySQL")
            sys.exit(1)
        connection_type = 'password'
    
    elif connection_type == 'auth_socket':
        print("MySQL using auth_socket authentication")
        # Fix authentication and secure MySQL
        mysql_password = fix_mysql_auth_and_secure()
        if mysql_password is None:
            print("Using sudo mysql for database operations...")
            connection_type = 'sudo_mysql'
        else:
            connection_type = 'password'
    
    elif connection_type == 'password_required':
        mysql_password = getpass.getpass("Enter existing MySQL root password: ")
        connection_type = 'password'
    
    # Get user credentials
    username, user_password = get_user_credentials()
    
    # Create database and user based on connection type
    success = False
    
    if connection_type == 'sudo_mysql':
        success = create_database_and_user_with_sudo(username, user_password)
    elif connection_type == 'password':
        success = create_database_and_user_with_password(mysql_password, username, user_password)
    
    if success:
        print("\n" + "=" * 60)
        print("Setup completed successfully!")
        print("=" * 60)
        print(f"Database: admin")
        print(f"Table: users")
        print(f"User created: {username}")
        print(f"User is_active: True")
        
        if connection_type == 'password':
            print(f"\nYou can now connect to MySQL ! :D")
    else:
        print("\n✗ Failed to complete setup")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)
