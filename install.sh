#!/bin/bash

# Enhanced Web Application Firewall Installer with Helper.py Integration
# Author: Enhanced version with helper.py support and prerequisite management
# Description: Automated installer for Web Application Firewall with helper.py execution

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

export DEBIAN_FRONTEND=noninteractive

# Global flags
INTERRUPTIBLE=true
NORMAL_EXIT=false
FORCE_CLEANUP=false
HELPER_RUNNING=false

# =================================================================
# LOGGING FUNCTIONS
# =================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# =================================================================
# PREREQUISITE INSTALLATION FUNCTIONS
# =================================================================

check_prerequisites() {
    log "INFO" "Checking system prerequisites..."
    
    local missing_packages=()
    local required_packages=("python3" "python3-pip" "git" "curl" "wget")
    
    for package in "${required_packages[@]}"; do
        if ! command -v "$package" &> /dev/null; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log "WARN" "Missing packages: ${missing_packages[*]}"
        return 1
    else
        log "INFO" "All prerequisites are installed"
        return 0
    fi
}

install_prerequisites() {
    log "INFO" "Installing system prerequisites..."
    
    echo -e "${COLORS[CYAN]}Installing system packages...${COLORS[RESET]}"
    
    # Update package lists
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y python3 python3-pip python3-venv git curl wget build-essential
    elif command -v yum &> /dev/null; then
        sudo yum update -y
        sudo yum install -y python3 python3-pip git curl wget gcc gcc-c++ make
    elif command -v dnf &> /dev/null; then
        sudo dnf update -y
        sudo dnf install -y python3 python3-pip git curl wget gcc gcc-c++ make
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm
        sudo pacman -S --noconfirm python python-pip git curl wget base-devel
    elif command -v zypper &> /dev/null; then
        sudo zypper refresh
        sudo zypper install -y python3 python3-pip git curl wget gcc gcc-c++ make
    else
        log "ERROR" "Unsupported package manager. Please install prerequisites manually."
        return 1
    fi
    
    log "INFO" "System prerequisites installed successfully"
}

install_python_requirements() {
    log "INFO" "Installing Python requirements..."
    
    if [[ -f "$PROJECT_DIR/requirements.txt" ]]; then
        echo -e "${COLORS[CYAN]}Installing Python dependencies...${COLORS[RESET]}"
        
        # Create virtual environment if it doesn't exist
        if [[ ! -d "$PROJECT_DIR/venv" ]]; then
            python3 -m venv "$PROJECT_DIR/venv"
        fi
        
        # Activate virtual environment and install requirements
        source "$PROJECT_DIR/venv/bin/activate"
        pip install --upgrade pip
        pip install -r "$PROJECT_DIR/requirements.txt"
        
        log "INFO" "Python requirements installed successfully"
    else
        log "WARN" "No requirements.txt found, skipping Python dependencies"
    fi
}

# =================================================================
# HELPER.PY MANAGEMENT FUNCTIONS
# =================================================================

run_helper_script() {
    log "INFO" "Running helper.py script..."
    
    if [[ ! -f "$PROJECT_DIR/helper.py" ]]; then
        log "ERROR" "helper.py not found in $PROJECT_DIR"
        return 1
    fi
    
    echo -e "${COLORS[YELLOW]}Executing helper.py...${COLORS[RESET]}"
    
    # Check if virtual environment exists and activate it
    if [[ -d "$PROJECT_DIR/venv" ]]; then
        source "$PROJECT_DIR/venv/bin/activate"
    fi
    
    cd "$PROJECT_DIR"
    
    # Run helper.py with logging
    if python3 helper.py 2>&1 | tee -a "$HELPER_LOG_FILE"; then
        log "INFO" "helper.py executed successfully"
        return 0
    else
        log "ERROR" "helper.py execution failed"
        return 1
    fi
}

start_helper_background() {
    if [[ ! -f "$PROJECT_DIR/helper.py" ]]; then
        log "ERROR" "helper.py not found"
        return 1
    fi

    if is_helper_running; then
        log "WARN" "Helper script is already running"
        return 0
    fi

    log "INFO" "Starting helper.py in background..."
    
    # Check if virtual environment exists and use it
    local python_cmd="python3"
    if [[ -d "$PROJECT_DIR/venv" ]]; then
        python_cmd="$PROJECT_DIR/venv/bin/python"
    fi
    
    cd "$PROJECT_DIR"
    nohup $python_cmd helper.py > "$HELPER_LOG_FILE" 2>&1 &
    local helper_pid=$!
    
    echo "$helper_pid" > "$HELPER_PID_FILE"
    HELPER_RUNNING=true
    
    log "INFO" "Helper script started with PID: $helper_pid"
    echo -e "${COLORS[GREEN]}Helper script started in background (PID: $helper_pid)${COLORS[RESET]}"
}

stop_helper_background() {
    if [[ -f "$HELPER_PID_FILE" ]]; then
        local pid=$(cat "$HELPER_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "Stopping helper script (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$HELPER_PID_FILE"
    fi
    HELPER_RUNNING=false
    log "INFO" "Helper script stopped"
}

is_helper_running() {
    if [[ -f "$HELPER_PID_FILE" ]]; then
        local pid=$(cat "$HELPER_PID_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$HELPER_PID_FILE" 2>/dev/null || true
        fi
    fi
    return 1
}

# =================================================================
# SIGNAL HANDLING - ENHANCED VERSION
# =================================================================

cleanup_and_exit() {
    if [[ "$NORMAL_EXIT" == "true" ]]; then
        return 0
    fi

    echo -e "\n${COLORS[YELLOW]}Cleaning up and exiting...${COLORS[RESET]}"

    if [[ "$FORCE_CLEANUP" == "true" ]]; then
        local children=$(jobs -p 2>/dev/null || true)
        if [[ -n "$children" ]]; then
            echo "Stopping background jobs..."
            kill $children 2>/dev/null || true
            wait $children 2>/dev/null || true
        fi
        
        # Stop helper script if running
        stop_helper_background
        stop_project_background
    fi

    stty sane 2>/dev/null || true
    echo -e "${COLORS[CYAN]}Log files: $LOG_FILE, $HELPER_LOG_FILE${COLORS[RESET]}"
    exit 0
}

safe_interrupt_handler() {
    if [[ "$INTERRUPTIBLE" == "true" ]]; then
        echo -e "\n${COLORS[YELLOW]}=== Interrupted! ===${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Options:${COLORS[RESET]}"
        echo -e "${COLORS[GREEN]}1) Start helper.py in background and return to menu${COLORS[RESET]}"
        echo -e "${COLORS[BLUE]}2) Start firewall.py in background and return to menu${COLORS[RESET]}"
        echo -e "${COLORS[WHITE]}3) Return to main menu${COLORS[RESET]}"
        echo -e "${COLORS[RED]}4) Exit completely (preserves background processes)${COLORS[RESET]}"
        echo -e "${COLORS[RED]}5) Exit and stop all processes${COLORS[RESET]}"

        echo -n "$(echo -e "${COLORS[YELLOW]}Choose [1-5] (auto-select 3 in 10s): ${COLORS[RESET]}")"

        if read -t 10 -n 1 choice 2>/dev/null; then
            echo
        else
            echo -e "\n${COLORS[DIM]}Timeout - returning to menu${COLORS[RESET]}"
            choice="3"
        fi

        case "${choice:-3}" in
        1)
            echo -e "${COLORS[GREEN]}Starting helper.py in background...${COLORS[RESET]}"
            start_helper_background 2>/dev/null || true
            return 0
            ;;
        2)
            echo -e "${COLORS[BLUE]}Starting firewall.py in background...${COLORS[RESET]}"
            start_project_background "firewall.py" 2>/dev/null || true
            return 0
            ;;
        3)
            echo -e "${COLORS[WHITE]}Returning to menu...${COLORS[RESET]}"
            return 0
            ;;
        4)
            echo -e "${COLORS[RED]}Exiting (background processes preserved)...${COLORS[RESET]}"
            NORMAL_EXIT=true
            cleanup_and_exit
            ;;
        5)
            echo -e "${COLORS[RED]}Stopping all processes and exiting...${COLORS[RESET]}"
            FORCE_CLEANUP=true
            cleanup_and_exit
            ;;
        *)
            echo -e "${COLORS[YELLOW]}Invalid choice, returning to menu...${COLORS[RESET]}"
            return 0
            ;;
        esac
    fi
}

# Set up signal handlers
trap safe_interrupt_handler SIGINT SIGTERM
trap cleanup_and_exit EXIT

# =================================================================
# PROJECT MANAGEMENT FUNCTIONS
# =================================================================

setup_project() {
    log "INFO" "Setting up Web Application Firewall project..."
    
    # Check prerequisites first
    if ! check_prerequisites; then
        echo -e "${COLORS[YELLOW]}Installing missing prerequisites...${COLORS[RESET]}"
        if ! install_prerequisites; then
            log "ERROR" "Failed to install prerequisites"
            return 1
        fi
    fi
    
    # Create backup if project exists
    if [[ -d "$PROJECT_DIR" ]]; then
        log "INFO" "Creating backup before update..."
        mkdir -p "$BACKUP_DIR"
        cp -r "$PROJECT_DIR" "$BACKUP_DIR/"
    fi

    # Clone or update repository
    if [[ -d "$PROJECT_DIR" ]]; then
        log "INFO" "Project directory exists, updating..."
        cd "$PROJECT_DIR"
        git pull origin main || git pull origin master || {
            log "ERROR" "Failed to update repository"
            return 1
        }
    else
        log "INFO" "Cloning repository..."
        if ! git clone "$REPO_URL" "$PROJECT_DIR"; then
            log "ERROR" "Failed to clone repository"
            return 1
        fi
    fi

    # Set proper permissions
    chmod +x "$PROJECT_DIR"/*.py 2>/dev/null || true

    # Install Python requirements
    install_python_requirements
    
    # Run helper.py after prerequisites are installed
    echo -e "${COLORS[CYAN]}Running helper.py setup script...${COLORS[RESET]}"
    if run_helper_script; then
        log "INFO" "Project setup completed successfully"
        echo -e "${COLORS[GREEN]}✓ Project setup completed!${COLORS[RESET]}"
    else
        log "WARN" "Project cloned but helper.py failed"
        echo -e "${COLORS[YELLOW]}⚠ Project cloned but helper.py encountered issues${COLORS[RESET]}"
    fi

    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

start_project_background() {
    local script_name="${1:-firewall.py}"
    
    if [[ ! -f "$PROJECT_DIR/$script_name" ]]; then
        log "ERROR" "$script_name not found"
        return 1
    fi

    if is_project_running; then
        log "WARN" "Project is already running"
        return 0
    fi

    log "INFO" "Starting $script_name in background..."
    
    # Check if virtual environment exists and use it
    local python_cmd="python3"
    if [[ -d "$PROJECT_DIR/venv" ]]; then
        python_cmd="$PROJECT_DIR/venv/bin/python"
    fi
    
    cd "$PROJECT_DIR"
    nohup $python_cmd "$script_name" > "$BG_LOG_FILE" 2>&1 &
    local bg_pid=$!
    
    echo "$bg_pid" > "$PID_FILE"
    
    log "INFO" "Project started with PID: $bg_pid"
    echo -e "${COLORS[GREEN]}Project started in background (PID: $bg_pid)${COLORS[RESET]}"
}

stop_project_background() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "Stopping project (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
    log "INFO" "Project stopped"
}

is_project_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$PID_FILE" 2>/dev/null || true
        fi
    fi
    return 1
}

uninstall_project() {
    echo -e "${COLORS[RED]}${COLORS[BOLD]}WARNING: This will remove the entire project!${COLORS[RESET]}"
    echo -e "${COLORS[YELLOW]}Are you sure you want to uninstall? [y/N]${COLORS[RESET]}"
    
    safe_read "" 10 "n"
    
    if [[ "${REPLY,,}" == "y" ]]; then
        stop_project_background
        stop_helper_background
        remove_system_command
        
        if [[ -d "$PROJECT_DIR" ]]; then
            rm -rf "$PROJECT_DIR"
            log "INFO" "Project uninstalled successfully"
            echo -e "${COLORS[GREEN]}✓ Project uninstalled${COLORS[RESET]}"
        else
            log "WARN" "Project directory not found"
            echo -e "${COLORS[YELLOW]}⚠ Project directory not found${COLORS[RESET]}"
        fi
    else
        log "INFO" "Uninstall cancelled"
        echo -e "${COLORS[CYAN]}Uninstall cancelled${COLORS[RESET]}"
    fi
    
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

# =================================================================
# SYSTEM COMMAND MANAGEMENT
# =================================================================

install_system_command() {
    log "INFO" "Installing 'firewall' system command..."
    
    local target_dir="/usr/local/bin"
    local script_dir="/usr/local/bin/custom-scripts"
    
    # Check if project is properly installed
    if [[ ! -f "$PROJECT_DIR/firewall.py" ]]; then
        log "ERROR" "Project not properly installed. Run setup first."
        echo -e "${COLORS[RED]}✗ Project not found. Please setup the project first.${COLORS[RESET]}"
        return 1
    fi
    
    # Create custom scripts directory
    sudo mkdir -p "$script_dir"
    
    # Copy the firewall script
    sudo cp "$PROJECT_DIR/firewall.py" "$script_dir/"
    sudo chmod +x "$script_dir/firewall.py"
    
    # Create wrapper script
    sudo tee "$target_dir/firewall" > /dev/null << EOF
#!/bin/bash
# WAF Firewall System Command
SCRIPT_DIR="$script_dir"
VENV_DIR="$PROJECT_DIR/venv"

if [[ -d "\$VENV_DIR" ]]; then
    source "\$VENV_DIR/bin/activate"
fi

cd "\$SCRIPT_DIR"
python3 firewall.py "\$@"
EOF
    
    sudo chmod +x "$target_dir/firewall"
    
    log "INFO" "System command installed successfully"
    echo -e "${COLORS[GREEN]}✓ 'firewall' command installed to $target_dir${COLORS[RESET]}"
    echo -e "${COLORS[CYAN]}You can now run 'firewall' from anywhere in the system${COLORS[RESET]}"
}

remove_system_command() {
    log "INFO" "Removing 'firewall' system command..."
    
    local target_file="/usr/local/bin/firewall"
    local script_dir="/usr/local/bin/custom-scripts"
    
    if [[ ! -f "$target_file" ]]; then
        log "INFO" "System command not found"
        echo -e "${COLORS[YELLOW]}⚠ 'firewall' command not installed${COLORS[RESET]}"
        return 0
    fi
    
    # Remove the command
    sudo rm -f "$target_file"
    sudo rm -rf "$script_dir"
    
    log "INFO" "System command removed successfully"
    echo -e "${COLORS[GREEN]}✓ 'firewall' command removed${COLORS[RESET]}"
}

# =================================================================
# UTILITY FUNCTIONS
# =================================================================

safe_read() {
    local prompt="$1"
    local timeout="${2:-30}"
    local default="${3:-}"
    
    echo -n "$prompt"
    if read -t "$timeout" REPLY 2>/dev/null; then
        true
    else
        REPLY="$default"
        echo -e "\n${COLORS[DIM]}Using default: $default${COLORS[RESET]}"
    fi
}

# =================================================================
# DISPLAY FUNCTIONS
# =================================================================

show_main_menu() {
    while true; do
        clear
        echo -e "${COLORS[CYAN]}${COLORS[BOLD]}"
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║              WEB APPLICATION FIREWALL                    ║"
        echo "║            Enhanced Installer with Helper.py             ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo -e "${COLORS[RESET]}"
        
        echo -e "${COLORS[GREEN]}  1)${COLORS[RESET]} Setup Project (Install Prerequisites + Run Helper)"
        echo -e "${COLORS[BLUE]}  2)${COLORS[RESET]} Start Firewall in Background"
        echo -e "${COLORS[YELLOW]}  3)${COLORS[RESET]} Stop Background Process"
        echo -e "${COLORS[MAGENTA]}  4)${COLORS[RESET]} Check Project Status"
        echo -e "${COLORS[WHITE]}  5)${COLORS[RESET]} View Background Logs"
        echo -e "${COLORS[RED]}  6)${COLORS[RESET]} Uninstall Project"
        echo -e "${COLORS[GREEN]}  7)${COLORS[RESET]} Install 'firewall' system command"
        echo -e "${COLORS[RED]}  8)${COLORS[RESET]} Remove 'firewall' system command"
        echo -e "${COLORS[CYAN]}  9)${COLORS[RESET]} Run Helper Script"
        echo -e "${COLORS[BLUE]} 10)${COLORS[RESET]} Start Helper in Background"
        echo -e "${COLORS[YELLOW]} 11)${COLORS[RESET]} Stop Helper Background Process"
        echo -e "${COLORS[WHITE]} 12)${COLORS[RESET]} View Helper Logs"
        echo -e "${COLORS[GREEN]} 13)${COLORS[RESET]} Install System Prerequisites Only"
        echo -e "${COLORS[WHITE]} 14)${COLORS[RESET]} Exit (preserve background processes)"
        echo -e "${COLORS[RED]} 15)${COLORS[RESET]} Exit and stop all processes"
        echo

        safe_read "$(echo -e "${COLORS[YELLOW]}Choose option [1-15]: ${COLORS[RESET]}")" 30 "14"

        case "${REPLY:-14}" in
        1)
            setup_project
            ;;
        2)
            if [[ -d "$PROJECT_DIR" ]]; then
                start_project_background "firewall.py"
            else
                log "ERROR" "Project not installed"
                echo -e "${COLORS[RED]}✗ Project not installed. Please setup first.${COLORS[RESET]}"
            fi
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        3)
            stop_project_background
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        4)
            show_project_status
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        5)
            view_background_logs
            ;;
        6)
            uninstall_project
            ;;
        7)
            install_system_command
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        8)
            remove_system_command
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        9)
            if [[ -d "$PROJECT_DIR" ]]; then
                run_helper_script
            else
                log "ERROR" "Project not installed"
                echo -e "${COLORS[RED]}✗ Project not installed. Please setup first.${COLORS[RESET]}"
            fi
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        10)
            if [[ -d "$PROJECT_DIR" ]]; then
                start_helper_background
            else
                log "ERROR" "Project not installed"
                echo -e "${COLORS[RED]}✗ Project not installed. Please setup first.${COLORS[RESET]}"
            fi
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        11)
            stop_helper_background
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        12)
            view_helper_logs
            ;;
        13)
            install_prerequisites
            safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
            ;;
        14)
            NORMAL_EXIT=true
            break
            ;;
        15)
            echo -e "${COLORS[YELLOW]}Stopping all background processes...${COLORS[RESET]}"
            stop_project_background
            stop_helper_background
            NORMAL_EXIT=true
            break
            ;;
        *)
            log "ERROR" "Invalid option"
            sleep 1
            ;;
        esac
    done
}

show_project_status() {
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}PROJECT STATUS${COLORS[RESET]}"
    echo "================================="

    if [[ -d "$PROJECT_DIR" ]]; then
        echo -e "${COLORS[GREEN]}✓ Project: INSTALLED${COLORS[RESET]}"
        echo -e "Location: $PROJECT_DIR"
        
        # Check firewall.py
        if [[ -f "$PROJECT_DIR/firewall.py" ]]; then
            echo -e "${COLORS[GREEN]}✓ Firewall Script: AVAILABLE${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ Firewall Script: NOT FOUND${COLORS[RESET]}"
        fi
        
        # Check helper.py
        if [[ -f "$PROJECT_DIR/helper.py" ]]; then
            echo -e "${COLORS[GREEN]}✓ Helper Script: AVAILABLE${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ Helper Script: NOT FOUND${COLORS[RESET]}"
        fi

        # Check firewall background status
        if is_project_running; then
            local pid=$(cat "$PID_FILE" 2>/dev/null)
            echo -e "${COLORS[GREEN]}✓ Firewall Background: RUNNING (PID: $pid)${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ Firewall Background: NOT RUNNING${COLORS[RESET]}"
        fi

        # Check helper background status
        if is_helper_running; then
            local pid=$(cat "$HELPER_PID_FILE" 2>/dev/null)
            echo -e "${COLORS[GREEN]}✓ Helper Background: RUNNING (PID: $pid)${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ Helper Background: NOT RUNNING${COLORS[RESET]}"
        fi
        
        # Check system command
        if [[ -f "/usr/local/bin/firewall" ]]; then
            echo -e "${COLORS[GREEN]}✓ System Command: INSTALLED${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ System Command: NOT INSTALLED${COLORS[RESET]}"
        fi
        
        # Check virtual environment
        if [[ -d "$PROJECT_DIR/venv" ]]; then
            echo -e "${COLORS[GREEN]}✓ Virtual Environment: AVAILABLE${COLORS[RESET]}"
        else
            echo -e "${COLORS[YELLOW]}⚠ Virtual Environment: NOT FOUND${COLORS[RESET]}"
        fi
    else
        echo -e "${COLORS[RED]}✗ Project: NOT INSTALLED${COLORS[RESET]}"
    fi
}

view_background_logs() {
    if [[ ! -f "$BG_LOG_FILE" ]]; then
        log "WARN" "No background log file found"
        safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
        return
    fi

    echo -e "${COLORS[CYAN]}Firewall Background Logs (last 20 lines):${COLORS[RESET]}"
    echo "=================================================="
    tail -20 "$BG_LOG_FILE" 2>/dev/null || echo "No logs available"
    echo
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

view_helper_logs() {
    if [[ ! -f "$HELPER_LOG_FILE" ]]; then
        log "WARN" "No helper log file found"
        safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
        return
    fi

    echo -e "${COLORS[CYAN]}Helper Logs (last 20 lines):${COLORS[RESET]}"
    echo "=================================================="
    tail -20 "$HELPER_LOG_FILE" 2>/dev/null || echo "No logs available"
    echo
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

# =================================================================
# MAIN EXECUTION
# =================================================================

main() {
    echo -e "${COLORS[CYAN]}Starting Enhanced Web Application Firewall Installer...${COLORS[RESET]}"
    log "INFO" "Enhanced WAF Installer started"
    
    # Create necessary directories
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Start main menu
    show_main_menu
    
    log "INFO" "Enhanced WAF Installer finished"
    echo -e "${COLORS[GREEN]}Thank you for using Enhanced WAF Installer!${COLORS[RESET]}"
}

# Only run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
