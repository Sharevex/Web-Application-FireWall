#!/bin/bash
set -e

# ANSI color codes
GREEN='\e[32m'
BLUE='\e[34m'
RED='\e[31m'
YELLOW='\e[33m'
CYAN='\e[36m'
MAGENTA='\e[35m'
RESET='\e[0m'
BOLD='\e[1m'

export DEBIAN_FRONTEND=noninteractive
PROJECT_DIR="/Web-Application-FireWall"
REPO_URL="https://github.com/Sharevex/Web-Application-FireWall.git"

# --- MENU-specific trap for Ctrl+C/Z ---
function menu_trap() {
    trap 'echo -e "${MAGENTA}\nGoodbye!${RESET}"; exit 0' SIGINT SIGTSTP
}
# --- ACTION-specific trap for Ctrl+C/Z ---
function action_trap() {
    trap 'echo -e "${YELLOW}\nQuitting and running in the background${RESET}"; setsid "$0" "$@" >/dev/null 2>&1 & disown; exit 0' SIGINT SIGTSTP
}

function setup_mysql() {
    echo -e "${CYAN}${BOLD}Setting up MySQL database...${RESET}"
    
    # Install MySQL server
    echo -e "${CYAN}Installing MySQL server...${RESET}"
    sudo apt install -y mysql-server mysql-client
    
    # Start and enable MySQL service
    sudo systemctl start mysql
    sudo systemctl enable mysql
    
    # Generate secure random password for admin database user
    ADMIN_DB_PASSWORD=$(openssl rand -base64 32)
    
    # Get MySQL root credentials from user
    echo -e "${YELLOW}${BOLD}MySQL Root Credentials Required${RESET}"
    echo -e "${CYAN}Please enter MySQL root credentials to create the admin database:${RESET}"
    read -p "$(echo -e "${GREEN}MySQL root username: ${RESET}")" MYSQL_ROOT_USER
    read -s -p "$(echo -e "${GREEN}MySQL root password: ${RESET}")" MYSQL_ROOT_PASSWORD
    echo
    
    # Test MySQL connection
    if ! mysql -u"$MYSQL_ROOT_USER" -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1;" >/dev/null 2>&1; then
        echo -e "${RED}${BOLD}Error: Cannot connect to MySQL with provided credentials!${RESET}"
        echo -e "${YELLOW}Please check your MySQL root credentials and try again.${RESET}"
        return 1
    fi
    
    echo -e "${CYAN}Creating admin database and user...${RESET}"
    
    # Create the admin database and user
    mysql -u"$MYSQL_ROOT_USER" -p"$MYSQL_ROOT_PASSWORD" <<EOF
-- Create admin database
CREATE DATABASE IF NOT EXISTS admin CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create admin user with secure password
CREATE USER IF NOT EXISTS 'admin_user'@'localhost' IDENTIFIED BY '$ADMIN_DB_PASSWORD';

-- Grant all privileges on admin database to admin_user
GRANT ALL PRIVILEGES ON admin.* TO 'admin_user'@'localhost';

-- Create a basic users table for the application
USE admin;
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create a basic logs table for firewall events
CREATE TABLE IF NOT EXISTS firewall_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45),
    port INT,
    protocol VARCHAR(10),
    action VARCHAR(20) NOT NULL,
    rule_matched VARCHAR(100),
    details TEXT
);

-- Create a basic configuration table
CREATE TABLE IF NOT EXISTS firewall_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default configuration values
INSERT IGNORE INTO firewall_config (config_key, config_value, description) VALUES
('max_connections_per_ip', '100', 'Maximum connections allowed per IP address'),
('rate_limit_requests', '1000', 'Maximum requests per minute per IP'),
('blocked_countries', '[]', 'JSON array of blocked country codes'),
('whitelist_ips', '["127.0.0.1", "::1"]', 'JSON array of whitelisted IP addresses'),
('enable_ai_detection', 'true', 'Enable AI-based threat detection');

FLUSH PRIVILEGES;
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${BOLD}MySQL database setup completed successfully!${RESET}"
        echo -e "${CYAN}Database Details:${RESET}"
        echo -e "${GREEN}  Database Name: ${BOLD}admin${RESET}"
        echo -e "${GREEN}  Username: ${BOLD}admin_user${RESET}"
        echo -e "${GREEN}  Password: ${BOLD}$ADMIN_DB_PASSWORD${RESET}"
        echo -e "${YELLOW}${BOLD}IMPORTANT: Please save these credentials securely!${RESET}"
        
        # Save credentials to a secure file
        DB_CONFIG_FILE="$PROJECT_DIR/database_config.txt"
        cat > "$DB_CONFIG_FILE" <<EOF
# MySQL Database Configuration for Web Application Firewall
# Generated on: $(date)

DATABASE_HOST=localhost
DATABASE_NAME=admin
DATABASE_USER=admin_user
DATABASE_PASSWORD=$ADMIN_DB_PASSWORD
DATABASE_PORT=3306

# Connection URL format:
# mysql://admin_user:$ADMIN_DB_PASSWORD@localhost:3306/admin
EOF
        chmod 600 "$DB_CONFIG_FILE"
        echo -e "${CYAN}Database configuration saved to: ${BOLD}$DB_CONFIG_FILE${RESET}"
        
    else
        echo -e "${RED}${BOLD}Error: Failed to setup MySQL database!${RESET}"
        return 1
    fi
}

function reset_project() {
    action_trap
    echo -e "${RED}${BOLD}Resetting previous configuration...${RESET}"
    sudo rm -rf "$PROJECT_DIR"
    echo -e "${GREEN}Old project deleted.${RESET}"
    trap - SIGINT SIGTSTP     # Restore trap so menu exits cleanly if Ctrl+C afterwards
}

function setup_project() {
    action_trap
    echo -e "${CYAN}Installing dependencies and setting up the project...${RESET}"
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y python3 python3-venv python3-full git build-essential curl openssl

    echo -e "${CYAN}Cloning project to / ...${RESET}"
    sudo git clone "$REPO_URL" "$PROJECT_DIR"
    sudo chown -R "$USER":"$USER" "$PROJECT_DIR"

    cd "$PROJECT_DIR"

    PY_PKGS=("netifaces" "colorama")
    APT_PKGS=()
    PIP_PKGS=()

    for pkg in "${PY_PKGS[@]}"; do
        if apt-cache show python3-"$pkg" >/dev/null 2>&1; then
            APT_PKGS+=("python3-$pkg")
        else
            PIP_PKGS+=("$pkg")
            echo -e "${YELLOW}python3-$pkg not found in repositories; will install $pkg with pip.${RESET}"
        fi
    done

    if [ ${#APT_PKGS[@]} -ne 0 ]; then
        sudo apt install -y "${APT_PKGS[@]}"
    fi

    rm -rf venv
    python3 -m venv venv
    source venv/bin/activate
    python -m pip install --upgrade pip

    if [ ${#PIP_PKGS[@]} -ne 0 ]; then
        pip install "${PIP_PKGS[@]}"
    fi

    pip install -r requirements.txt || pip install --break-system-packages -r requirements.txt

    # Setup MySQL database
    setup_mysql

    echo -e "${MAGENTA}------------------------------------------"
    echo "Running ai_detector.py and showing the output:"
    echo "------------------------------------------${RESET}"
    ./venv/bin/python3 ai_detector.py

    echo -e "${MAGENTA}------------------------------------------"
    echo "Running firewall.py and showing the output:"
    echo "------------------------------------------${RESET}"
    ./venv/bin/python3 firewall.py

    trap - SIGINT SIGTSTP
}

function update_project() {
    action_trap
    if [ -d "$PROJECT_DIR" ]; then
        echo -e "${BLUE}Updating existing project...${RESET}"
        cd "$PROJECT_DIR"
        git pull
        source venv/bin/activate
        ./venv/bin/python3 ai_detector.py
        ./venv/bin/python3 firewall.py
    else
        echo -e "${RED}Project not found. Please install it first.${RESET}"
    fi
    trap - SIGINT SIGTSTP
}

function uninstall_project() {
    action_trap
    if [ -d "$PROJECT_DIR" ]; then
        echo -e "${YELLOW}Uninstalling project...${RESET}"
        
        # Ask if user wants to remove database as well
        read -p "$(echo -e "${YELLOW}Do you want to remove the MySQL database as well? [y/N]: ${RESET}")" remove_db
        if [[ $remove_db =~ ^[Yy]$ ]]; then
            echo -e "${CYAN}Please enter MySQL root credentials to remove the database:${RESET}"
            read -p "$(echo -e "${GREEN}MySQL root username: ${RESET}")" MYSQL_ROOT_USER
            read -s -p "$(echo -e "${GREEN}MySQL root password: ${RESET}")" MYSQL_ROOT_PASSWORD
            echo
            
            mysql -u"$MYSQL_ROOT_USER" -p"$MYSQL_ROOT_PASSWORD" <<EOF
DROP DATABASE IF EXISTS admin;
DROP USER IF EXISTS 'admin_user'@'localhost';
FLUSH PRIVILEGES;
EOF
            echo -e "${GREEN}Database removed successfully.${RESET}"
        fi
        
        sudo rm -rf "$PROJECT_DIR"
        echo -e "${GREEN}Project removed.${RESET}"
    else
        echo -e "${RED}Project not found.${RESET}"
    fi
    trap - SIGINT SIGTSTP
}

function show_menu() {
    while true; do
        clear
        menu_trap
        printf "${BOLD}${CYAN}=================================================\n"
        printf "         Web Application Firewall Installer       \n"
        printf "=================================================${RESET}\n"
        printf "${GREEN}  1)${RESET} ${BOLD}Install${RESET}\n"
        printf "${GREEN}  2)${RESET} ${BOLD}Update${RESET}\n"
        printf "${GREEN}  3)${RESET} ${BOLD}Uninstall${RESET}\n"
        printf "${GREEN}  4)${RESET} ${BOLD}Exit${RESET}\n"
        printf "${CYAN}-------------------------------------------------${RESET}\n"
        read -p "$(printf "${YELLOW}Choose an option [1-4]: ${RESET}")" option

        case "$option" in
            1)  reset_project; setup_project ;;
            2)  update_project ;;
            3)  uninstall_project ;;
            4)  printf "${MAGENTA}Exiting...${RESET}\n"; break ;;
            *)  printf "${RED}Invalid option. Please try again.${RESET}\n"; sleep 1 ;;
        esac
    done
}

# Entry point
show_menu
