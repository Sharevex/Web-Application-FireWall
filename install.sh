#!/bin/bash

# Enhanced Web Application Firewall Installer with Helper.py Integration and Virtual Environment Support
# Author: Enhanced version with helper.py execution before firewall.py and proper Python environment handling
# Description: Automated installer for Web Application Firewall with helper.py preprocessing and virtual environment support

set -euo pipefail

# =================================================================
# CONFIGURATION & CONSTANTS
# =================================================================

declare -A COLORS=(
    ["GREEN"]='\e[32m'
    ["BLUE"]='\e[34m'
    ["RED"]='\e[31m'
    ["YELLOW"]='\e[33m'
    ["CYAN"]='\e[36m'
    ["MAGENTA"]='\e[35m'
    ["WHITE"]='\e[37m'
    ["RESET"]='\e[0m'
    ["BOLD"]='\e[1m'
    ["DIM"]='\e[2m'
)

readonly PROJECT_NAME="Web-Application-FireWall"
readonly PROJECT_DIR="/${PROJECT_NAME}"
readonly REPO_URL="https://github.com/Sharevex/Web-Application-FireWall.git"
readonly LOG_FILE="/tmp/waf_installer.log"
readonly BACKUP_DIR="/tmp/waf_backup_$(date +%Y%m%d_%H%M%S)"
readonly PID_FILE="/tmp/waf_project.pid"
readonly HELPER_PID_FILE="/tmp/waf_helper.pid"
readonly BG_LOG_FILE="/tmp/waf_background.log"
readonly HELPER_LOG_FILE="/tmp/waf_helper.log"
readonly VENV_DIR="$PROJECT_DIR/venv"
readonly MYSQL_CONFIG_FILE="/tmp/waf_mysql_config.env"

export DEBIAN_FRONTEND=noninteractive

# Global flags
INTERRUPTIBLE=true
NORMAL_EXIT=false
FORCE_CLEANUP=false
HELPER_RUNNING=false

# MySQL configuration variables - Updated for correct schema
MYSQL_ROOT_PASSWORD=""
MYSQL_DATABASE_NAME="admin"  # Fixed database name
MYSQL_USERNAME="waf_user"
MYSQL_USER_PASSWORD=""
MYSQL_CONFIGURED=false

# =================================================================
# LOGGING FUNCTIONS
# =================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

show_progress() {
    local message="$1"
    local duration="${2:-3}"
    
    echo -n "$message"
    
    if [[ "$INTERRUPTIBLE" == "false" ]]; then
        echo -n "."
    else
        for ((i=0; i<duration; i++)); do
            sleep 1
            echo -n "."
        done
    fi
    
    echo -e "${COLORS[RESET]}"
}

safe_read() {
    local prompt="$1"
    local timeout="${2:-30}"
    local default="${3:-}"

    echo -n "$prompt"
    if read -t "$timeout" REPLY 2>/dev/null; then
        true
    else
        echo -e "\n${COLORS[DIM]}Timeout - using default: ${default:-none}${COLORS[RESET]}"
        REPLY="$default"
    fi
}

# Fixed secure password reading function
safe_read_password() {
    local prompt="$1"
    local timeout="${2:-60}"
    local password=""
    
    echo -n "$prompt"
    
    # Save current terminal settings
    local old_settings=$(stty -g)
    
    # Turn off echo but keep canonical mode for proper Enter handling
    stty -echo
    
    # Use a simpler approach with built-in read timeout
    if read -t "$timeout" -s password 2>/dev/null; then
        # Successfully read password
        true
    else
        # Timeout occurred
        echo -e "\n${COLORS[YELLOW]}Timeout reached - using empty password${COLORS[RESET]}"
        password=""
    fi
    
    # Restore terminal settings
    stty "$old_settings"
    echo
    
    REPLY="$password"
}

# =================================================================
# SIGNAL HANDLERS & CLEANUP
# =================================================================

cleanup() {
    local exit_code=$?
    
    if [[ "$NORMAL_EXIT" == "true" ]]; then
        log "INFO" "Normal exit - performing standard cleanup"
    else
        log "WARN" "Unexpected exit (code: $exit_code) - performing emergency cleanup"
    fi
    
    # Stop helper.py if running
    if [[ "$HELPER_RUNNING" == "true" ]] && [[ -f "$HELPER_PID_FILE" ]]; then
        local helper_pid=$(cat "$HELPER_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
            log "INFO" "Stopping helper.py (PID: $helper_pid)"
            kill -TERM "$helper_pid" 2>/dev/null || true
            sleep 2
            if kill -0 "$helper_pid" 2>/dev/null; then
                kill -KILL "$helper_pid" 2>/dev/null || true
            fi
        fi
        rm -f "$HELPER_PID_FILE"
    fi
    
    # Clean up other processes
    if [[ -f "$PID_FILE" ]]; then
        local main_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$main_pid" ]] && kill -0 "$main_pid" 2>/dev/null; then
            log "INFO" "Stopping main process (PID: $main_pid)"
            kill -TERM "$main_pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
    
    # Reset terminal if needed
    stty sane 2>/dev/null || true
    
    if [[ "$NORMAL_EXIT" != "true" ]]; then
        echo -e "\n${COLORS[YELLOW]}Installation interrupted or failed${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Check logs at: $LOG_FILE${COLORS[RESET]}"
    fi
    
    exit $exit_code
}

interrupt_handler() {
    if [[ "$INTERRUPTIBLE" == "true" ]]; then
        log "WARN" "Installation interrupted by user"
        echo -e "\n${COLORS[YELLOW]}Installation interrupted by user${COLORS[RESET]}"
        NORMAL_EXIT=false
        cleanup
    else
        log "WARN" "Interrupt signal received but ignored (critical section)"
        echo -e "\n${COLORS[YELLOW]}Interrupt received but ignored - in critical section${COLORS[RESET]}"
    fi
}

# Set up signal handlers
trap interrupt_handler SIGINT SIGTERM
trap cleanup EXIT

# =================================================================
# SYSTEM CHECKS & PREREQUISITES
# =================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLORS[RED]}This script must be run as root${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Please run: sudo $0${COLORS[RESET]}"
        exit 1
    fi
}

check_system() {
    log "INFO" "Performing system compatibility checks..."
    echo -e "${COLORS[CYAN]}Checking system compatibility...${COLORS[RESET]}"
    
    # Check OS
    if ! grep -q "Ubuntu\|Debian" /etc/os-release 2>/dev/null; then
        echo -e "${COLORS[RED]}This installer is designed for Ubuntu/Debian systems${COLORS[RESET]}"
        exit 1
    fi
    
    # Check available space (minimum 2GB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then
        echo -e "${COLORS[RED]}Insufficient disk space. At least 2GB required${COLORS[RESET]}"
        exit 1
    fi
    
    # Check internet connectivity
    if ! ping -c 1 google.com &>/dev/null; then
        echo -e "${COLORS[RED]}No internet connection detected${COLORS[RESET]}"
        exit 1
    fi
    
    log "SUCCESS" "System compatibility checks passed"
    echo -e "${COLORS[GREEN]}✓ System compatibility checks passed${COLORS[RESET]}"
}

# =================================================================
# MYSQL CONFIGURATION FUNCTIONS
# =================================================================

create_mysql_config_file() {
    local mysql_password="$1"
    
    log "INFO" "Creating MySQL configuration file for helper.py"
    
    cat > "$MYSQL_CONFIG_FILE" << EOF
# MySQL Configuration for WAF Helper
MYSQL_ROOT_PASSWORD=${mysql_password}
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DATABASE=${MYSQL_DATABASE_NAME}
MYSQL_USER=${MYSQL_USERNAME}
MYSQL_USER_PASSWORD=${MYSQL_USER_PASSWORD}
EOF
    
    chmod 600 "$MYSQL_CONFIG_FILE"
    log "SUCCESS" "MySQL configuration file created: $MYSQL_CONFIG_FILE"
}

configure_mysql_credentials() {
    log "INFO" "Configuring MySQL credentials..."
    echo -e "${COLORS[CYAN]}=== MySQL Configuration ===${COLORS[RESET]}"
    echo -e "${COLORS[YELLOW]}Setting up MySQL for WAF database (admin) with user table...${COLORS[RESET]}"
    
    local attempts=0
    local max_attempts=3
    
    while [[ $attempts -lt $max_attempts ]]; do
        echo -e "${COLORS[CYAN]}Please enter the MySQL root password:${COLORS[RESET]}"
        echo -e "${COLORS[DIM]}(Leave empty if no password is set, or press Ctrl+C to skip MySQL setup)${COLORS[RESET]}"
        
        if safe_read_password "MySQL root password: " 60; then
            MYSQL_ROOT_PASSWORD="$REPLY"
            
            # Test the MySQL connection
            if test_mysql_connection; then
                log "SUCCESS" "MySQL connection successful"
                echo -e "${COLORS[GREEN]}✓ MySQL connection verified${COLORS[RESET]}"
                MYSQL_CONFIGURED=true
                
                # Get WAF user password
                get_waf_user_password
                
                # Create configuration file for helper.py
                create_mysql_config_file "$MYSQL_ROOT_PASSWORD"
                
                return 0
            else
                log "WARN" "MySQL connection failed with provided credentials"
                echo -e "${COLORS[RED]}✗ Failed to connect to MySQL with provided credentials${COLORS[RESET]}"
                
                ((attempts++))
                if [[ $attempts -lt $max_attempts ]]; then
                    echo -e "${COLORS[YELLOW]}Please try again (Attempt $((attempts + 1))/$max_attempts)${COLORS[RESET]}"
                    sleep 2
                fi
            fi
        else
            # Timeout or interrupt
            echo -e "${COLORS[YELLOW]}Skipping MySQL configuration...${COLORS[RESET]}"
            log "WARN" "MySQL configuration skipped by user"
            return 1
        fi
    done
    
    echo -e "${COLORS[RED]}Failed to configure MySQL after $max_attempts attempts${COLORS[RESET]}"
    echo -e "${COLORS[YELLOW]}You can configure MySQL manually later or skip it for now${COLORS[RESET]}"
    
    safe_read "Continue without MySQL configuration? [y/N]: " 30 "n"
    if [[ "${REPLY,,}" == "y" ]]; then
        log "WARN" "Continuing without MySQL configuration"
        return 0
    else
        log "ERROR" "Installation aborted due to MySQL configuration failure"
        return 1
    fi
}

get_waf_user_password() {
    echo -e "${COLORS[CYAN]}WAF Database User Configuration:${COLORS[RESET]}"
    echo -e "${COLORS[DIM]}Database: admin, User: $MYSQL_USERNAME${COLORS[RESET]}"
    
    # Get user password
    safe_read_password "Enter password for MySQL user '$MYSQL_USERNAME': " 60
    MYSQL_USER_PASSWORD="$REPLY"
    
    # Use default password if empty
    if [[ -z "$MYSQL_USER_PASSWORD" ]]; then
        MYSQL_USER_PASSWORD="waf_password_$(date +%s)"
        echo -e "${COLORS[YELLOW]}Using auto-generated password for security${COLORS[RESET]}"
    fi
    
    log "INFO" "MySQL user configuration: DB=$MYSQL_DATABASE_NAME, USER=$MYSQL_USERNAME"
}

test_mysql_connection() {
    log "INFO" "Testing MySQL connection..."
    
    local mysql_cmd="mysql -u root"
    
    # Add password parameter if password is not empty
    if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
        mysql_cmd="mysql -u root -p${MYSQL_ROOT_PASSWORD}"
    fi
    
    # Test connection by running a simple query
    if echo "SELECT 1;" | $mysql_cmd --silent --batch 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# =================================================================
# MYSQL INSTALLATION & SETUP
# =================================================================

install_mysql() {
    log "INFO" "Installing MySQL server..."
    echo -e "${COLORS[CYAN]}Installing MySQL server...${COLORS[RESET]}"
    
    # Update package list
    apt-get update -qq || {
        log "ERROR" "Failed to update package list"
        return 1
    }
    
    # Install MySQL server
    apt-get install -y mysql-server mysql-client || {
        log "ERROR" "Failed to install MySQL server"
        return 1
    }
    
    # Start and enable MySQL service
    systemctl start mysql || {
        log "ERROR" "Failed to start MySQL service"
        return 1
    }
    
    systemctl enable mysql || {
        log "WARN" "Failed to enable MySQL service"
    }
    
    log "SUCCESS" "MySQL server installed successfully"
    echo -e "${COLORS[GREEN]}✓ MySQL server installed successfully${COLORS[RESET]}"
    return 0
}

setup_mysql_database() {
    if [[ "$MYSQL_CONFIGURED" != "true" ]]; then
        log "WARN" "MySQL not configured, skipping database setup"
        echo -e "${COLORS[YELLOW]}Skipping MySQL database setup...${COLORS[RESET]}"
        return 0
    fi
    
    log "INFO" "Setting up WAF database with correct schema..."
    echo -e "${COLORS[CYAN]}Setting up WAF database (admin) with user table...${COLORS[RESET]}"
    
    local mysql_cmd="mysql -u root"
    
    # Add password parameter if password is not empty
    if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
        mysql_cmd="mysql -u root -p${MYSQL_ROOT_PASSWORD}"
    fi
    
    # Create database, user, and table with correct schema
    local sql_commands="
-- Create the admin database
CREATE DATABASE IF NOT EXISTS \`admin\`;

-- Create WAF user
CREATE USER IF NOT EXISTS '${MYSQL_USERNAME}'@'localhost' IDENTIFIED BY '${MYSQL_USER_PASSWORD}';

-- Grant privileges on admin database
GRANT ALL PRIVILEGES ON \`admin\`.* TO '${MYSQL_USERNAME}'@'localhost';

-- Use the admin database
USE \`admin\`;

-- Create the user table with correct schema
CREATE TABLE IF NOT EXISTS \`user\` (
    \`id\` INT AUTO_INCREMENT PRIMARY KEY,
    \`username\` VARCHAR(255) NOT NULL UNIQUE,
    \`password_hash\` VARCHAR(255) NOT NULL,
    \`created_at\` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    \`updated_at\` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create index on username for faster lookups
CREATE INDEX IF NOT EXISTS \`idx_username\` ON \`user\` (\`username\`);

-- Insert a default admin user (password: admin123 - change this!)
INSERT IGNORE INTO \`user\` (\`username\`, \`password_hash\`) 
VALUES ('admin', SHA2('admin123', 256));

-- Flush privileges
FLUSH PRIVILEGES;
"
    
    if echo "$sql_commands" | $mysql_cmd --silent --batch 2>/dev/null; then
        log "SUCCESS" "WAF database setup completed with correct schema"
        echo -e "${COLORS[GREEN]}✓ WAF database setup completed${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Database: admin${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Table: user (columns: username, password_hash)${COLORS[RESET]}"
        echo -e "${COLORS[YELLOW]}Default admin user created (username: admin, password: admin123)${COLORS[RESET]}"
        echo -e "${COLORS[RED]}⚠️  IMPORTANT: Change the default admin password!${COLORS[RESET]}"
        return 0
    else
        log "ERROR" "Failed to setup WAF database"
        echo -e "${COLORS[RED]}✗ Failed to setup WAF database${COLORS[RESET]}"
        return 1
    fi
}

# =================================================================
# PYTHON ENVIRONMENT MANAGEMENT
# =================================================================

get_python_executable() {
    if command -v python3 >/dev/null; then
        echo "python3"
    elif command -v python >/dev/null; then
        echo "python"
    else
        echo ""
    fi
}

setup_python_environment() {
    log "INFO" "Setting up Python virtual environment..."
    echo -e "${COLORS[CYAN]}Setting up Python virtual environment...${COLORS[RESET]}"

    cd "$PROJECT_DIR" || {
        log "ERROR" "Failed to change to project directory"
        return 1
    }

    # Always install python3-venv packages to ensure availability
    log "INFO" "Installing python3-venv packages..."
    echo -e "${COLORS[CYAN]}Installing python3-venv packages...${COLORS[RESET]}"
    apt-get update -qq
    apt-get install -y python3-venv python3.12-venv python3-full python3-pip || {
        log "ERROR" "Failed to install python3-venv packages"
        return 1
    }

    # Remove existing virtual environment if it exists
    if [[ -d "$VENV_DIR" ]]; then
        log "INFO" "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    fi

    # Create new virtual environment
    log "INFO" "Creating virtual environment..."
    python3 -m venv "$VENV_DIR" || {
        log "ERROR" "Failed to create virtual environment"
        return 1
    }

    # Activate virtual environment
    source "$VENV_DIR/bin/activate" || {
        log "ERROR" "Failed to activate virtual environment"
        return 1
    }

    # Upgrade pip
    log "INFO" "Upgrading pip..."
    pip install --upgrade pip || {
        log "WARN" "Failed to upgrade pip"
    }

        # Install mysql-connector-python
    log "INFO" "Installing mysql-connector-python..."
    pip install mysql-connector-python || {
        log "WARN" "Failed to install mysql-connector-python"
    }


    # Install requirements if requirements.txt exists
    if [[ -f "requirements.txt" ]]; then
        log "INFO" "Installing Python requirements..."
        echo -e "${COLORS[CYAN]}Installing Python requirements...${COLORS[RESET]}"
        
        pip install -r requirements.txt -v || {
            log "ERROR" "Failed to install requirements"
            echo -e "${COLORS[RED]}Failed to install Python requirements${COLORS[RESET]}"
            return 1
        }
    fi


    log "SUCCESS" "Python virtual environment setup completed"
    echo -e "${COLORS[GREEN]}✓ Python virtual environment setup completed${COLORS[RESET]}"
    return 0
}

# =================================================================
# PROJECT MANAGEMENT
# =================================================================

clone_project() {
    log "INFO" "Cloning WAF project..."
    echo -e "${COLORS[CYAN]}Cloning Web Application Firewall project...${COLORS[RESET]}"
    
    # Remove existing directory if it exists
    if [[ -d "$PROJECT_DIR" ]]; then
        log "INFO" "Removing existing project directory..."
        rm -rf "$PROJECT_DIR"
    fi
    
    # Clone the repository
    git clone "$REPO_URL" "$PROJECT_DIR" || {
        log "ERROR" "Failed to clone repository"
        return 1
    }
    
    log "SUCCESS" "Project cloned successfully"
    echo -e "${COLORS[GREEN]}✓ Project cloned successfully${COLORS[RESET]}"
    return 0
}

install_dependencies() {
    log "INFO" "Installing system dependencies..."
    echo -e "${COLORS[CYAN]}Installing system dependencies...${COLORS[RESET]}"
    
    # Update package list
    apt-get update -qq || {
        log "ERROR" "Failed to update package list"
        return 1
    }
    
    # Install essential packages
    local packages=(
        "git"
        "curl"
        "wget"
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "libssl-dev"
        "libffi-dev"
        "nginx"
        "ufw"
    )
    
    for package in "${packages[@]}"; do
        log "INFO" "Installing $package..."
        apt-get install -y "$package" || {
            log "WARN" "Failed to install $package"
        }
    done
    
    log "SUCCESS" "System dependencies installed"
    echo -e "${COLORS[GREEN]}✓ System dependencies installed${COLORS[RESET]}"
    return 0
}

# =================================================================
# HELPER.PY MANAGEMENT
# =================================================================

prepare_helper_environment() {
    log "INFO" "Preparing environment variables for helper.py..."
    
    # Export MySQL configuration if available
    if [[ -f "$MYSQL_CONFIG_FILE" ]]; then
        export MYSQL_CONFIG_FILE
        log "INFO" "MySQL configuration file set: $MYSQL_CONFIG_FILE"
    fi
    
    # Set environment variables to prevent interactive prompts
    export WAF_AUTO_MODE=1
    export WAF_SKIP_INTERACTIVE=1
    export DEBIAN_FRONTEND=noninteractive
    
    # Create a configuration directory for helper.py
    local config_dir="$PROJECT_DIR/.waf_config"
    mkdir -p "$config_dir"
    
    # Create a configuration file for helper.py to indicate non-interactive mode
    cat > "$config_dir/auto_config.json" << EOF
{
    "auto_mode": true,
    "skip_interactive": true,
    "mysql_config_file": "${MYSQL_CONFIG_FILE:-}",
    "log_file": "${HELPER_LOG_FILE}",
    "run_mode": "background",
    "database": {
        "name": "admin",
        "table": "user",
        "columns": ["username", "password_hash"]
    }
}
EOF
    
    log "SUCCESS" "Helper environment prepared"
}

run_helper_script() {
    log "INFO" "Running helper.py script..."
    echo -e "${COLORS[CYAN]}Running helper.py preprocessing script...${COLORS[RESET]}"
    
    cd "$PROJECT_DIR" || {
        log "ERROR" "Failed to change to project directory"
        return 1
    }
    
    # Check if helper.py exists
    if [[ ! -f "helper.py" ]]; then
        log "WARN" "helper.py not found in project directory"
        echo -e "${COLORS[YELLOW]}helper.py not found - skipping preprocessing${COLORS[RESET]}"
        return 0
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate" || {
        log "ERROR" "Failed to activate virtual environment"
        return 1
    }
    
    # Get Python executable
    local python_exec=$(get_python_executable)
    if [[ -z "$python_exec" ]]; then
        log "ERROR" "No Python executable found"
        return 1
    fi
    
    # Prepare environment for helper.py
    prepare_helper_environment
    
    # Set MySQL environment variables if configured
    if [[ "$MYSQL_CONFIGURED" == "true" ]] && [[ -f "$MYSQL_CONFIG_FILE" ]]; then
        source "$MYSQL_CONFIG_FILE"
        export MYSQL_ROOT_PASSWORD MYSQL_DATABASE MYSQL_USER MYSQL_USER_PASSWORD
        log "INFO" "MySQL configuration loaded for helper.py"
    fi
    
    # Run helper.py in background and capture PID
    log "INFO" "Starting helper.py in background..."
    "$python_exec" helper.py > "$HELPER_LOG_FILE" 2>&1 &
    local helper_pid=$!
    echo "$helper_pid" > "$HELPER_PID_FILE"
    HELPER_RUNNING=true
    
    log "INFO" "helper.py started with PID: $helper_pid"
    echo -e "${COLORS[GREEN]}✓ helper.py started successfully (PID: $helper_pid)${COLORS[RESET]}"
    
    # Wait for helper.py to complete or timeout
    local timeout=300  # 5 minutes timeout
    local elapsed=0
    
    echo -e "${COLORS[CYAN]}Waiting for helper.py to complete...${COLORS[RESET]}"
    
    while kill -0 "$helper_pid" 2>/dev/null && [[ $elapsed -lt $timeout ]]; do
        sleep 5
        elapsed=$((elapsed + 5))
        echo -n "."
    done
    echo
    
    if kill -0 "$helper_pid" 2>/dev/null; then
        log "WARN" "helper.py still running after timeout - continuing anyway"
        echo -e "${COLORS[YELLOW]}helper.py still running after timeout - continuing with firewall.py${COLORS[RESET]}"
    else
        wait "$helper_pid"
        local exit_code=$?
        HELPER_RUNNING=false
        rm -f "$HELPER_PID_FILE"
        
        if [[ $exit_code -eq 0 ]]; then
            log "SUCCESS" "helper.py completed successfully"
            echo -e "${COLORS[GREEN]}✓ helper.py completed successfully${COLORS[RESET]}"
        else
            log "WARN" "helper.py exited with code: $exit_code"
            echo -e "${COLORS[YELLOW]}helper.py exited with code: $exit_code - continuing anyway${COLORS[RESET]}"
        fi
    fi
    
    return 0
}

# =================================================================
# FIREWALL EXECUTION
# =================================================================

run_firewall_script() {
    log "INFO" "Running firewall.py script..."
    echo -e "${COLORS[CYAN]}Running main firewall.py script...${COLORS[RESET]}"
    
    cd "$PROJECT_DIR" || {
        log "ERROR" "Failed to change to project directory"
        return 1
    }
    
    # Check if firewall.py exists
    if [[ ! -f "firewall.py" ]]; then
        log "ERROR" "firewall.py not found in project directory"
        echo -e "${COLORS[RED]}firewall.py not found - installation incomplete${COLORS[RESET]}"
        return 1
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate" || {
        log "ERROR" "Failed to activate virtual environment"
        return 1
    }
    
    # Get Python executable
    local python_exec=$(get_python_executable)
    if [[ -z "$python_exec" ]]; then
        log "ERROR" "No Python executable found"
        return 1
    fi
    
    # Set MySQL environment variables if configured
    if [[ "$MYSQL_CONFIGURED" == "true" ]] && [[ -f "$MYSQL_CONFIG_FILE" ]]; then
        source "$MYSQL_CONFIG_FILE"
        export MYSQL_ROOT_PASSWORD MYSQL_DATABASE MYSQL_USER MYSQL_USER_PASSWORD
        log "INFO" "MySQL configuration loaded for firewall.py"
    fi
    
    # Run firewall.py interactively to show the menu
    log "INFO" "Starting firewall.py with interactive menu..."
    echo -e "${COLORS[GREEN]}Starting Web Application Firewall with interactive menu...${COLORS[RESET]}"
    echo -e "${COLORS[DIM]}Press Ctrl+C to return to installer menu${COLORS[RESET]}"
    
    # Run firewall.py interactively
    "$python_exec" firewall.py
    
    log "SUCCESS" "firewall.py execution completed"
    echo -e "${COLORS[GREEN]}✓ Returned from firewall.py${COLORS[RESET]}"
    
    return 0
}

# =================================================================
# MENU SYSTEM
# =================================================================

show_banner() {
    clear
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}"
    echo "=================================================================="
    echo "    Web Application Firewall - Enhanced Installer"
    echo "    Version: 2.0 with Helper.py Integration"
    echo "    Database: admin | Table: user | Columns: username, password_hash"
    echo "=================================================================="
    echo -e "${COLORS[RESET]}"
}

show_main_menu() {
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}Main Menu:${COLORS[RESET]}"
    echo -e "${COLORS[WHITE]}1.${COLORS[RESET]} Full Installation (Recommended)"
    echo -e "${COLORS[WHITE]}2.${COLORS[RESET]} Custom Installation"
    echo -e "${COLORS[WHITE]}3.${COLORS[RESET]} System Status Check"
    echo -e "${COLORS[WHITE]}4.${COLORS[RESET]} MySQL Configuration Only"
    echo -e "${COLORS[WHITE]}5.${COLORS[RESET]} View Installation Logs"
    echo -e "${COLORS[WHITE]}6.${COLORS[RESET]} Run Helper.py Only"
    echo -e "${COLORS[WHITE]}7.${COLORS[RESET]} Run Firewall.py Only"
    echo -e "${COLORS[WHITE]}8.${COLORS[RESET]} Uninstall WAF"
    echo -e "${COLORS[WHITE]}9.${COLORS[RESET]} Exit"
    echo
}

show_custom_menu() {
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}Custom Installation Options:${COLORS[RESET]}"
    echo -e "${COLORS[WHITE]}1.${COLORS[RESET]} Install Dependencies Only"
    echo -e "${COLORS[WHITE]}2.${COLORS[RESET]} Install MySQL Only"
    echo -e "${COLORS[WHITE]}3.${COLORS[RESET]} Clone Project Only"
    echo -e "${COLORS[WHITE]}4.${COLORS[RESET]} Setup Python Environment Only"
    echo -e "${COLORS[WHITE]}5.${COLORS[RESET]} Run Helper.py Only"
    echo -e "${COLORS[WHITE]}6.${COLORS[RESET]} Run Firewall.py Only"
    echo -e "${COLORS[WHITE]}7.${COLORS[RESET]} Back to Main Menu"
    echo
}

handle_main_menu() {
    while true; do
        show_banner
        show_main_menu
        
        safe_read "Please select an option [1-9]: " 30 "1"
        local choice="$REPLY"
        
        case "$choice" in
            1)
                echo -e "${COLORS[GREEN]}Starting Full Installation...${COLORS[RESET]}"
                full_installation
                ;;
            2)
                handle_custom_menu
                ;;
            3)
                system_status_check
                ;;
            4)
                mysql_configuration_only
                ;;
            5)
                view_logs
                ;;
            6)
                echo -e "${COLORS[GREEN]}Running Helper.py...${COLORS[RESET]}"
                run_helper_script
                pause_for_user
                ;;
            7)
                echo -e "${COLORS[GREEN]}Running Firewall.py...${COLORS[RESET]}"
                run_firewall_script
                pause_for_user
                ;;
            8)
                uninstall_waf
                ;;
            9)
                echo -e "${COLORS[CYAN]}Thank you for using WAF Installer!${COLORS[RESET]}"
                NORMAL_EXIT=true
                exit 0
                ;;
            *)
                echo -e "${COLORS[RED]}Invalid option. Please try again.${COLORS[RESET]}"
                sleep 2
                ;;
        esac
    done
}

handle_custom_menu() {
    while true; do
        show_banner
        show_custom_menu
        
        safe_read "Please select an option [1-7]: " 30 "7"
        local choice="$REPLY"
        
        case "$choice" in
            1)
                echo -e "${COLORS[GREEN]}Installing Dependencies...${COLORS[RESET]}"
                install_dependencies
                pause_for_user
                ;;
            2)
                echo -e "${COLORS[GREEN]}Installing MySQL...${COLORS[RESET]}"
                install_mysql && configure_mysql_credentials
                pause_for_user
                ;;
            3)
                echo -e "${COLORS[GREEN]}Cloning Project...${COLORS[RESET]}"
                clone_project
                pause_for_user
                ;;
            4)
                echo -e "${COLORS[GREEN]}Setting up Python Environment...${COLORS[RESET]}"
                setup_python_environment
                pause_for_user
                ;;
            5)
                echo -e "${COLORS[GREEN]}Running Helper.py...${COLORS[RESET]}"
                run_helper_script
                pause_for_user
                ;;
            6)
                echo -e "${COLORS[GREEN]}Running Firewall.py...${COLORS[RESET]}"
                run_firewall_script
                pause_for_user
                ;;
            7)
                return
                ;;
            *)
                echo -e "${COLORS[RED]}Invalid option. Please try again.${COLORS[RESET]}"
                sleep 2
                ;;
        esac
    done
}

pause_for_user() {
    echo
    safe_read "Press Enter to continue..." 30
}

# =================================================================
# INSTALLATION FUNCTIONS
# =================================================================

full_installation() {
    log "INFO" "Starting full WAF installation"
    
    # Phase 1: System checks and prerequisites
    echo -e "${COLORS[MAGENTA]}Phase 1: System Checks${COLORS[RESET]}"
    check_root
    check_system
    
    # Phase 2: Install dependencies
    echo -e "\n${COLORS[MAGENTA]}Phase 2: Installing Dependencies${COLORS[RESET]}"
    install_dependencies || {
        log "ERROR" "Failed to install dependencies"
        pause_for_user
        return 1
    }
    
    # Phase 3: MySQL installation and configuration
    echo -e "\n${COLORS[MAGENTA]}Phase 3: MySQL Setup${COLORS[RESET]}"
    if install_mysql; then
        configure_mysql_credentials || {
            log "WARN" "MySQL configuration failed, continuing without it"
        }
    else
        log "ERROR" "MySQL installation failed"
        echo -e "${COLORS[RED]}MySQL installation failed - continuing without database${COLORS[RESET]}"
    fi
    
    # Phase 4: Project setup
    echo -e "\n${COLORS[MAGENTA]}Phase 4: Project Setup${COLORS[RESET]}"
    clone_project || {
        log "ERROR" "Failed to clone project"
        pause_for_user
        return 1
    }
    
    setup_python_environment || {
        log "ERROR" "Failed to setup Python environment"
        pause_for_user
        return 1
    }
    
    # Phase 5: Setup MySQL database with correct schema
    if [[ "$MYSQL_CONFIGURED" == "true" ]]; then
        echo -e "\n${COLORS[MAGENTA]}Phase 5: Database Setup${COLORS[RESET]}"
        setup_mysql_database
    fi
    
    # Phase 6: Run helper.py (BEFORE firewall.py)
    echo -e "\n${COLORS[MAGENTA]}Phase 6: Running Helper Script${COLORS[RESET]}"
    run_helper_script || {
        log "WARN" "Helper script execution had issues, continuing anyway"
    }
    
    # Phase 7: Run firewall.py (AFTER helper.py) - Interactive
    echo -e "\n${COLORS[MAGENTA]}Phase 7: Starting Firewall${COLORS[RESET]}"
    echo -e "${COLORS[CYAN]}The firewall will now start with its interactive menu.${COLORS[RESET]}"
    echo -e "${COLORS[YELLOW]}You can return to this installer by exiting the firewall.${COLORS[RESET]}"
    pause_for_user
    
    run_firewall_script || {
        log "ERROR" "Failed to start firewall"
        pause_for_user
        return 1
    }
    
    # Show completion message
    show_completion_message
    
    log "SUCCESS" "Full WAF installation completed successfully"
    pause_for_user
}

system_status_check() {
    echo -e "${COLORS[CYAN]}System Status Check${COLORS[RESET]}"
    echo "=================================="
    
    # Check if project exists
    if [[ -d "$PROJECT_DIR" ]]; then
        echo -e "Project Directory: ${COLORS[GREEN]}✓ Exists${COLORS[RESET]} ($PROJECT_DIR)"
    else
        echo -e "Project Directory: ${COLORS[RED]}✗ Missing${COLORS[RESET]} ($PROJECT_DIR)"
    fi
    
    # Check virtual environment
    if [[ -d "$VENV_DIR" ]]; then
        echo -e "Virtual Environment: ${COLORS[GREEN]}✓ Exists${COLORS[RESET]} ($VENV_DIR)"
    else
        echo -e "Virtual Environment: ${COLORS[RED]}✗ Missing${COLORS[RESET]} ($VENV_DIR)"
    fi
    
    # Check MySQL
    if systemctl is-active --quiet mysql; then
        echo -e "MySQL Service: ${COLORS[GREEN]}✓ Running${COLORS[RESET]}"
        
        # Check if admin database exists
        if [[ "$MYSQL_CONFIGURED" == "true" ]] && [[ -f "$MYSQL_CONFIG_FILE" ]]; then
            source "$MYSQL_CONFIG_FILE"
            local mysql_cmd="mysql -u root"
            if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
                mysql_cmd="mysql -u root -p${MYSQL_ROOT_PASSWORD}"
            fi
            
            if echo "USE admin; SHOW TABLES LIKE 'user';" | $mysql_cmd --silent --batch 2>/dev/null | grep -q "user"; then
                echo -e "Database Schema: ${COLORS[GREEN]}✓ admin.user table exists${COLORS[RESET]}"
            else
                echo -e "Database Schema: ${COLORS[RED]}✗ admin.user table missing${COLORS[RESET]}"
            fi
        fi
    else
        echo -e "MySQL Service: ${COLORS[RED]}✗ Not Running${COLORS[RESET]}"
    fi
    
    # Check firewall process
    if [[ -f "$PID_FILE" ]]; then
        local firewall_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$firewall_pid" ]] && kill -0 "$firewall_pid" 2>/dev/null; then
            echo -e "Firewall Process: ${COLORS[GREEN]}✓ Running${COLORS[RESET]} (PID: $firewall_pid)"
        else
            echo -e "Firewall Process: ${COLORS[RED]}✗ Not Running${COLORS[RESET]}"
        fi
    else
        echo -e "Firewall Process: ${COLORS[RED]}✗ No PID File${COLORS[RESET]}"
    fi
    
    # Check helper process
    if [[ -f "$HELPER_PID_FILE" ]]; then
        local helper_pid=$(cat "$HELPER_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
            echo -e "Helper Process: ${COLORS[GREEN]}✓ Running${COLORS[RESET]} (PID: $helper_pid)"
        else
            echo -e "Helper Process: ${COLORS[YELLOW]}✓ Completed${COLORS[RESET]}"
        fi
    else
        echo -e "Helper Process: ${COLORS[YELLOW]}- Not Started${COLORS[RESET]}"
    fi
    
    pause_for_user
}

mysql_configuration_only() {
    echo -e "${COLORS[CYAN]}MySQL Configuration${COLORS[RESET]}"
    echo "=================================="
    
    # Check if MySQL is installed
    if ! command -v mysql &> /dev/null; then
        echo -e "${COLORS[YELLOW]}MySQL not found. Installing...${COLORS[RESET]}"
        install_mysql || {
            echo -e "${COLORS[RED]}Failed to install MySQL${COLORS[RESET]}"
            pause_for_user
            return 1
        }
    fi
    
    configure_mysql_credentials
    
    if [[ "$MYSQL_CONFIGURED" == "true" ]]; then
        setup_mysql_database
    fi
    
    pause_for_user
}

view_logs() {
    echo -e "${COLORS[CYAN]}Installation Logs${COLORS[RESET]}"
    echo "=================================="
    
    if [[ -f "$LOG_FILE" ]]; then
        echo -e "${COLORS[WHITE]}Main Log File: $LOG_FILE${COLORS[RESET]}"
        echo "Last 20 lines:"
        echo "----------------------------------------"
        tail -20 "$LOG_FILE"
    else
        echo -e "${COLORS[YELLOW]}No main log file found${COLORS[RESET]}"
    fi
    
    echo
    
    if [[ -f "$BG_LOG_FILE" ]]; then
        echo -e "${COLORS[WHITE]}Firewall Log File: $BG_LOG_FILE${COLORS[RESET]}"
        echo "Last 10 lines:"
        echo "----------------------------------------"
        tail -10 "$BG_LOG_FILE"
    else
        echo -e "${COLORS[YELLOW]}No firewall log file found${COLORS[RESET]}"
    fi
    
    echo
    
    if [[ -f "$HELPER_LOG_FILE" ]]; then
        echo -e "${COLORS[WHITE]}Helper Log File: $HELPER_LOG_FILE${COLORS[RESET]}"
        echo "Last 10 lines:"
        echo "----------------------------------------"
        tail -10 "$HELPER_LOG_FILE"
    else
        echo -e "${COLORS[YELLOW]}No helper log file found${COLORS[RESET]}"
    fi
    
    pause_for_user
}

uninstall_waf() {
    echo -e "${COLORS[RED]}${COLORS[BOLD]}WAF Uninstallation${COLORS[RESET]}"
    echo "=================================="
    echo -e "${COLORS[YELLOW]}This will remove all WAF components including:${COLORS[RESET]}"
    echo "• Project directory ($PROJECT_DIR)"
    echo "• Virtual environment"
    echo "• Running processes"
    echo "• Log files"
    echo "• MySQL admin database (if configured)"
    echo
    
    safe_read "Are you sure you want to uninstall? [y/N]: " 30 "n"
    
    if [[ "${REPLY,,}" == "y" ]]; then
        echo -e "${COLORS[CYAN]}Uninstalling WAF...${COLORS[RESET]}"
        
        # Stop processes
        if [[ -f "$PID_FILE" ]]; then
            local firewall_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
            if [[ -n "$firewall_pid" ]] && kill -0 "$firewall_pid" 2>/dev/null; then
                echo "Stopping firewall process..."
                kill -TERM "$firewall_pid" 2>/dev/null || true
            fi
        fi
        
        if [[ -f "$HELPER_PID_FILE" ]]; then
            local helper_pid=$(cat "$HELPER_PID_FILE" 2>/dev/null || echo "")
            if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
                echo "Stopping helper process..."
                kill -TERM "$helper_pid" 2>/dev/null || true
            fi
        fi
        
        # Remove MySQL database if configured
        if [[ "$MYSQL_CONFIGURED" == "true" ]] && [[ -f "$MYSQL_CONFIG_FILE" ]]; then
            safe_read "Also remove MySQL admin database? [y/N]: " 30 "n"
            if [[ "${REPLY,,}" == "y" ]]; then
                source "$MYSQL_CONFIG_FILE"
                local mysql_cmd="mysql -u root"
                if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
                    mysql_cmd="mysql -u root -p${MYSQL_ROOT_PASSWORD}"
                fi
                
                echo "Removing MySQL admin database..."
                echo "DROP DATABASE IF EXISTS \`admin\`; DROP USER IF EXISTS '${MYSQL_USERNAME}'@'localhost';" | $mysql_cmd --silent --batch 2>/dev/null || true
            fi
        fi
        
        # Remove project directory
        if [[ -d "$PROJECT_DIR" ]]; then
            echo "Removing project directory..."
            rm -rf "$PROJECT_DIR"
        fi
        
        # Remove log files
        echo "Removing log files..."
        rm -f "$LOG_FILE" "$BG_LOG_FILE" "$HELPER_LOG_FILE" "$PID_FILE" "$HELPER_PID_FILE" "$MYSQL_CONFIG_FILE"
        
        echo -e "${COLORS[GREEN]}WAF uninstalled successfully${COLORS[RESET]}"
    else
        echo -e "${COLORS[CYAN]}Uninstallation cancelled${COLORS[RESET]}"
    fi
    
    pause_for_user
}

show_completion_message() {
    echo -e "\n${COLORS[GREEN]}${COLORS[BOLD]}"
    echo "=================================================================="
    echo "    Installation Completed Successfully!"
    echo "=================================================================="
    echo -e "${COLORS[RESET]}"
    
    echo -e "${COLORS[CYAN]}Installation Summary:${COLORS[RESET]}"
    echo -e "• Project Directory: ${COLORS[WHITE]}$PROJECT_DIR${COLORS[RESET]}"
    echo -e "• Virtual Environment: ${COLORS[WHITE]}$VENV_DIR${COLORS[RESET]}"
    echo -e "• Log File: ${COLORS[WHITE]}$LOG_FILE${COLORS[RESET]}"
    
    if [[ "$MYSQL_CONFIGURED" == "true" ]]; then
        echo -e "• MySQL Database: ${COLORS[GREEN]}admin (configured)${COLORS[RESET]}"
        echo -e "• MySQL Table: ${COLORS[GREEN]}user (username, password_hash)${COLORS[RESET]}"
        echo -e "• MySQL Config: ${COLORS[WHITE]}$MYSQL_CONFIG_FILE${COLORS[RESET]}"
        echo -e "• Default Admin User: ${COLORS[YELLOW]}admin / admin123${COLORS[RESET]}"
    else
        echo -e "• MySQL Database: ${COLORS[YELLOW]}Not Configured${COLORS[RESET]}"
    fi
    
    echo -e "\n${COLORS[CYAN]}Useful Commands:${COLORS[RESET]}"
    echo -e "• Activate virtual env: ${COLORS[WHITE]}source $VENV_DIR/bin/activate${COLORS[RESET]}"
    echo -e "• Run helper.py: ${COLORS[WHITE]}cd $PROJECT_DIR && python3 helper.py${COLORS[RESET]}"
    echo -e "• Run firewall.py: ${COLORS[WHITE]}cd $PROJECT_DIR && python3 firewall.py${COLORS[RESET]}"
    
    if [[ "$MYSQL_CONFIGURED" == "true" ]]; then
        echo -e "• Connect to MySQL: ${COLORS[WHITE]}mysql -u $MYSQL_USERNAME -p admin${COLORS[RESET]}"
        echo -e "• View user table: ${COLORS[WHITE]}mysql -u $MYSQL_USERNAME -p -e \"SELECT username FROM admin.user;\"${COLORS[RESET]}"
    fi
    
    echo -e "\n${COLORS[GREEN]}Web Application Firewall is now ready to use!${COLORS[RESET]}"
    
    if [[ "$MYSQL_CONFIGURED" == "true" ]]; then
        echo -e "\n${COLORS[RED]}⚠️  SECURITY REMINDER:${COLORS[RESET]}"
        echo -e "${COLORS[YELLOW]}Change the default admin password (admin123) immediately!${COLORS[RESET]}"
    fi
}

# =================================================================
# MAIN EXECUTION
# =================================================================

main() {
    # Initialize logging
    echo "WAF Installation Started: $(date)" > "$LOG_FILE"
    
    # Store main process PID
    echo $$ > "$PID_FILE"
    
    log "INFO" "Starting WAF installation process"
    
    # Start menu system
    handle_main_menu
}

# Run main function
main "$@"

# Clean exit message
echo -e "${COLORS[MAGENTA]}Thank you for using the installer!${COLORS[RESET]}"
if is_project_running; then
    echo -e "${COLORS[GREEN]}Background processes are still running and will continue.${COLORS[RESET]}"
fi
log "INFO" "Installer finished"
