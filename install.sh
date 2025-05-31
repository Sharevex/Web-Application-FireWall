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

# =================================================================
# PYTHON ENVIRONMENT MANAGEMENT
# =================================================================

setup_python_environment() {
    log "INFO" "Setting up Python virtual environment..."
    echo -e "${COLORS[CYAN]}Setting up Python virtual environment...${COLORS[RESET]}"

    cd "$PROJECT_DIR" || {
        log "ERROR" "Failed to change to project directory"
        return 1
    }

    # Install python3-venv if not available
    if ! python3 -m venv --help >/dev/null 2>&1; then
        log "INFO" "Installing python3-venv package..."
        echo -e "${COLORS[CYAN]}Installing python3-venv package...${COLORS[RESET]}"
        apt-get update -qq
        apt-get install -y python3-venv python3-full python3-pip || {
            log "ERROR" "Failed to install python3-venv"
            return 1
        }
    fi

    # Remove existing venv if present
    if [[ -d "$VENV_DIR" ]]; then
        log "INFO" "Removing existing virtual environment"
        rm -rf "$VENV_DIR"
    fi

    # Create virtual environment with timeout
    log "INFO" "Creating virtual environment..."
    echo -e "${COLORS[CYAN]}Creating virtual environment...${COLORS[RESET]}"
    if ! timeout 60s python3 -m venv "$VENV_DIR"; then
        log "ERROR" "Failed to create virtual environment"
        return 1
    fi

    # Activate and setup
    source "$VENV_DIR/bin/activate" || {
        log "ERROR" "Cannot activate virtual environment"
        return 1
    }

    log "INFO" "Upgrading pip in virtual environment..."
    echo -e "${COLORS[CYAN]}Upgrading pip...${COLORS[RESET]}"
    python -m pip install --upgrade pip -q --timeout 30 || {
        log "WARN" "Pip upgrade failed, continuing..."
    }

    # Install requirements if available
    if [[ -f "requirements.txt" ]]; then
        log "INFO" "Installing project requirements..."
        echo -e "${COLORS[CYAN]}Installing Python dependencies...${COLORS[RESET]}"
        if ! pip install -r requirements.txt -q --timeout 120; then
            log "WARN" "Some packages may have failed to install"
            echo -e "${COLORS[YELLOW]}Warning: Some Python packages may have failed to install${COLORS[RESET]}"
        fi
    else
        # Install common dependencies for web application firewalls
        log "INFO" "Installing common dependencies..."
        echo -e "${COLORS[CYAN]}Installing common dependencies...${COLORS[RESET]}"
        pip install flask requests scapy netfilterqueue psutil -q --timeout 120 || {
            log "WARN" "Some common dependencies failed to install"
        }
    fi

    # Deactivate virtual environment for now
    deactivate 2>/dev/null || true

    log "SUCCESS" "Python environment setup completed"
    echo -e "${COLORS[GREEN]}✓ Python virtual environment setup completed${COLORS[RESET]}"
}

get_python_executable() {
    if [[ -f "$VENV_DIR/bin/python" ]]; then
        echo "$VENV_DIR/bin/python"
    else
        echo "python3"
    fi
}

# =================================================================
# HELPER.PY MANAGEMENT FUNCTIONS
# =================================================================

# Check if helper.py exists and is executable
check_helper_py() {
    local helper_path="$PROJECT_DIR/helper.py"
    
    if [[ ! -f "$helper_path" ]]; then
        log "WARN" "helper.py not found at $helper_path"
        echo -e "${COLORS[YELLOW]}Warning: helper.py not found at $helper_path${COLORS[RESET]}"
        return 1
    fi
    
    if [[ ! -x "$helper_path" ]]; then
        log "INFO" "Making helper.py executable"
        echo -e "${COLORS[BLUE]}Making helper.py executable...${COLORS[RESET]}"
        chmod +x "$helper_path" || {
            log "ERROR" "Failed to make helper.py executable"
            echo -e "${COLORS[RED]}Failed to make helper.py executable${COLORS[RESET]}"
            return 1
        }
    fi
    
    return 0
}

# Start helper.py in background using virtual environment
start_helper_background() {
    local helper_path="$PROJECT_DIR/helper.py"
    local python_exec=$(get_python_executable)
    
    log "INFO" "Starting helper.py in background"
    echo -e "${COLORS[CYAN]}Starting helper.py in background...${COLORS[RESET]}"
    
    # Check if helper is already running
    if [[ -f "$HELPER_PID_FILE" ]] && kill -0 "$(cat "$HELPER_PID_FILE")" 2>/dev/null; then
        log "WARN" "Helper.py is already running (PID: $(cat "$HELPER_PID_FILE"))"
        echo -e "${COLORS[YELLOW]}Helper.py is already running (PID: $(cat "$HELPER_PID_FILE"))${COLORS[RESET]}"
        return 0
    fi
    
    # Change to project directory
    cd "$PROJECT_DIR" || return 1
    
    # Start helper.py in background using virtual environment python
    nohup "$python_exec" "$helper_path" > "$HELPER_LOG_FILE" 2>&1 &
    local helper_pid=$!
    
    # Save PID
    echo "$helper_pid" > "$HELPER_PID_FILE"
    HELPER_RUNNING=true
    
    # Wait a moment to check if it started successfully
    sleep 2
    
    if kill -0 "$helper_pid" 2>/dev/null; then
        log "SUCCESS" "Helper.py started successfully (PID: $helper_pid)"
        echo -e "${COLORS[GREEN]}✓ Helper.py started successfully (PID: $helper_pid)${COLORS[RESET]}"
        echo -e "${COLORS[DIM]}Helper log: $HELPER_LOG_FILE${COLORS[RESET]}"
        return 0
    else
        log "ERROR" "Failed to start helper.py"
        echo -e "${COLORS[RED]}✗ Failed to start helper.py${COLORS[RESET]}"
        rm -f "$HELPER_PID_FILE"
        HELPER_RUNNING=false
        return 1
    fi
}

# Stop helper.py
stop_helper() {
    if [[ -f "$HELPER_PID_FILE" ]]; then
        local helper_pid=$(cat "$HELPER_PID_FILE")
        if kill -0 "$helper_pid" 2>/dev/null; then
            log "INFO" "Stopping helper.py (PID: $helper_pid)"
            echo -e "${COLORS[YELLOW]}Stopping helper.py (PID: $helper_pid)...${COLORS[RESET]}"
            kill "$helper_pid" 2>/dev/null || true
            wait "$helper_pid" 2>/dev/null || true
            echo -e "${COLORS[GREEN]}✓ Helper.py stopped${COLORS[RESET]}"
        fi
        rm -f "$HELPER_PID_FILE"
    fi
    HELPER_RUNNING=false
}

# Wait for helper.py to complete initialization (if needed)
wait_for_helper_ready() {
    local max_wait=30
    local wait_count=0
    
    log "INFO" "Waiting for helper.py to initialize"
    echo -e "${COLORS[BLUE]}Waiting for helper.py to initialize...${COLORS[RESET]}"
    
    while [[ $wait_count -lt $max_wait ]]; do
        # Check if helper is still running
        if [[ -f "$HELPER_PID_FILE" ]] && kill -0 "$(cat "$HELPER_PID_FILE")" 2>/dev/null; then
            # You can add specific checks here for helper readiness
            # For example, checking for a ready file or port
            if [[ -f "$PROJECT_DIR/.helper_ready" ]] || grep -q "Helper ready\|ready\|initialized\|started" "$HELPER_LOG_FILE" 2>/dev/null; then
                log "SUCCESS" "Helper.py is ready"
                echo -e "${COLORS[GREEN]}✓ Helper.py is ready${COLORS[RESET]}"
                return 0
            fi
        else
            log "ERROR" "Helper.py stopped unexpectedly"
            echo -e "${COLORS[RED]}✗ Helper.py stopped unexpectedly${COLORS[RESET]}"
            return 1
        fi
        
        sleep 1
        ((wait_count++))
        echo -n "."
    done
    
    log "WARN" "Helper.py readiness timeout, proceeding anyway"
    echo -e "\n${COLORS[YELLOW]}Warning: Helper.py readiness timeout, proceeding anyway...${COLORS[RESET]}"
    return 0
}

# =================================================================
# UTILITY FUNCTIONS
# =================================================================

is_project_running() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

is_helper_running() {
    [[ -f "$HELPER_PID_FILE" ]] && kill -0 "$(cat "$HELPER_PID_FILE")" 2>/dev/null
}

# =================================================================
# SIGNAL HANDLING - ENHANCED VERSION
# =================================================================

# Enhanced cleanup function
cleanup_and_exit() {
    # Don't cleanup if this is a normal menu exit
    if [[ "$NORMAL_EXIT" == "true" ]]; then
        return 0
    fi

    echo -e "\n${COLORS[YELLOW]}Cleaning up and exiting...${COLORS[RESET]}"

    # Stop helper.py if running
    if [[ "$HELPER_RUNNING" == "true" ]]; then
        stop_helper
    fi

    # Only kill child processes if we were interrupted or explicitly asked to cleanup
    if [[ "$FORCE_CLEANUP" == "true" ]]; then
        local children=$(jobs -p 2>/dev/null || true)
        if [[ -n "$children" ]]; then
            echo "Stopping background jobs..."
            kill $children 2>/dev/null || true
            wait $children 2>/dev/null || true
        fi
        
        # Stop main project if running
        if [[ -f "$PID_FILE" ]]; then
            local main_pid=$(cat "$PID_FILE")
            if kill -0 "$main_pid" 2>/dev/null; then
                echo "Stopping main project..."
                kill "$main_pid" 2>/dev/null || true
            fi
            rm -f "$PID_FILE"
        fi
    fi

    # Reset terminal
    stty sane 2>/dev/null || true

    echo -e "${COLORS[CYAN]}Log files:${COLORS[RESET]}"
    echo -e "${COLORS[DIM]}  Main: $LOG_FILE${COLORS[RESET]}"
    echo -e "${COLORS[DIM]}  Background: $BG_LOG_FILE${COLORS[RESET]}"
    echo -e "${COLORS[DIM]}  Helper: $HELPER_LOG_FILE${COLORS[RESET]}"
    exit 0
}

# Enhanced interrupt handler
safe_interrupt_handler() {
    if [[ "$INTERRUPTIBLE" == "true" ]]; then
        echo -e "\n${COLORS[YELLOW]}=== Interrupted! ===${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Options:${COLORS[RESET]}"
        echo -e "${COLORS[GREEN]}1) Start project in background (with helper.py) and return to menu${COLORS[RESET]}"
        echo -e "${COLORS[BLUE]}2) Return to main menu${COLORS[RESET]}"
        echo -e "${COLORS[RED]}3) Exit completely (preserves background processes)${COLORS[RESET]}"
        echo -e "${COLORS[RED]}4) Exit and stop all processes (including helper.py)${COLORS[RESET]}"

        # Use timeout to prevent hanging on read
        echo -n "$(echo -e "${COLORS[YELLOW]}Choose [1-4] (auto-select 2 in 10s): ${COLORS[RESET]}")"

        if read -t 10 -n 1 choice 2>/dev/null; then
            echo
        else
            echo -e "\n${COLORS[DIM]}Timeout - returning to menu${COLORS[RESET]}"
            choice="2"
        fi

        case "${choice:-2}" in
        1)
            echo -e "${COLORS[GREEN]}Starting project with helper.py in background...${COLORS[RESET]}"
            start_project_background "firewall.py" 2>/dev/null || true
            return 0
            ;;
        2)
            echo -e "${COLORS[BLUE]}Returning to main menu...${COLORS[RESET]}"
            return 0
            ;;
        3)
            echo -e "${COLORS[CYAN]}Exiting (background processes preserved)...${COLORS[RESET]}"
            NORMAL_EXIT=true
            exit 0
            ;;
        4)
            echo -e "${COLORS[RED]}Stopping all processes and exiting...${COLORS[RESET]}"
            FORCE_CLEANUP=true
            cleanup_and_exit
            ;;
        *)
            echo -e "${COLORS[BLUE]}Invalid choice, returning to menu...${COLORS[RESET]}"
            return 0
            ;;
        esac
    fi
}

# =================================================================
# PROJECT MANAGEMENT FUNCTIONS - ENHANCED
# =================================================================

setup_project() {
    echo -e "${COLORS[BOLD]}${COLORS[BLUE]}=== Setting up WAF Project ===${COLORS[RESET]}"
    
    # Check if project already exists
    if [[ -d "$PROJECT_DIR" ]]; then
        echo -e "${COLORS[YELLOW]}Project directory already exists${COLORS[RESET]}"
        safe_read "$(echo -e "${COLORS[YELLOW]}Reinstall? [y/N]: ${COLORS[RESET]}")" 10 "n"
        if [[ "${REPLY,,}" != "y" ]]; then
            return 0
        fi
        
        # Backup existing installation
        if [[ -d "$PROJECT_DIR" ]]; then
            log "INFO" "Creating backup of existing installation"
            mkdir -p "$BACKUP_DIR"
            cp -r "$PROJECT_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        fi
    fi
    
    # Install dependencies
    echo -e "${COLORS[CYAN]}Installing system dependencies...${COLORS[RESET]}"
    apt-get update -qq
    apt-get install -y git python3 python3-venv python3-full python3-pip curl wget build-essential || {
        log "ERROR" "Failed to install dependencies"
        return 1
    }
    
    # Clone repository
    echo -e "${COLORS[CYAN]}Cloning repository...${COLORS[RESET]}"
    if [[ -d "$PROJECT_DIR" ]]; then
        rm -rf "$PROJECT_DIR"
    fi
    
    git clone "$REPO_URL" "$PROJECT_DIR" || {
        log "ERROR" "Failed to clone repository"
        return 1
    }
    
    # Setup Python virtual environment
    setup_python_environment || {
        log "ERROR" "Failed to setup Python environment"
        return 1
    }
    
    # Make scripts executable
    chmod +x "$PROJECT_DIR"/*.py 2>/dev/null || true
    
    log "SUCCESS" "Project setup completed"
    echo -e "${COLORS[GREEN]}✓ Project installed successfully${COLORS[RESET]}"
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

# Enhanced function to start project with helper.py integration
start_project_with_helper() {
    local main_script="${1:-firewall.py}"
    local python_exec=$(get_python_executable)
    
    echo -e "${COLORS[BOLD]}${COLORS[BLUE]}=== Starting WAF Project with Helper Integration ===${COLORS[RESET]}"
    
    # Change to project directory
    cd "$PROJECT_DIR" || {
        log "ERROR" "Failed to change to project directory"
        echo -e "${COLORS[RED]}Failed to change to project directory${COLORS[RESET]}"
        return 1
    }
    
    # Step 1: Check and start helper.py
    if check_helper_py; then
        if ! start_helper_background; then
            echo -e "${COLORS[YELLOW]}Continuing without helper.py...${COLORS[RESET]}"
        else
            # Wait for helper to be ready (optional)
            wait_for_helper_ready
        fi
    else
        echo -e "${COLORS[YELLOW]}Skipping helper.py (not found or not executable)${COLORS[RESET]}"
    fi
    
    # Step 2: Start main firewall script
    echo -e "${COLORS[CYAN]}Starting main firewall application...${COLORS[RESET]}"
    
    if [[ ! -f "$main_script" ]]; then
        log "ERROR" "$main_script not found in $PROJECT_DIR"
        echo -e "${COLORS[RED]}Error: $main_script not found in $PROJECT_DIR${COLORS[RESET]}"
        stop_helper  # Clean up helper if main script fails
        return 1
    fi
    
    # Make main script executable if needed
    chmod +x "$main_script" 2>/dev/null || true
    
    # Start the main application using virtual environment python
    log "INFO" "Executing: $python_exec $main_script"
    echo -e "${COLORS[GREEN]}Executing: $python_exec $main_script${COLORS[RESET]}"
    "$python_exec" "$main_script"
}

# Enhanced background project starter
start_project_background() {
    local main_script="${1:-firewall.py}"
    local python_exec=$(get_python_executable)
    
    log "INFO" "Starting WAF project in background"
    echo -e "${COLORS[CYAN]}Starting WAF project in background...${COLORS[RESET]}"
    
    # Check if already running
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo -e "${COLORS[YELLOW]}Project is already running (PID: $(cat "$PID_FILE"))${COLORS[RESET]}"
        return 0
    fi
    
    cd "$PROJECT_DIR" || return 1
    
    # Start helper.py first
    if check_helper_py; then
        start_helper_background || echo -e "${COLORS[YELLOW]}Continuing without helper.py...${COLORS[RESET]}"
    fi
    
    # Start main script in background using virtual environment python
    nohup "$python_exec" "$main_script" > "$BG_LOG_FILE" 2>&1 &
    local main_pid=$!
    
    echo "$main_pid" > "$PID_FILE"
    
    sleep 2
    if kill -0 "$main_pid" 2>/dev/null; then
        log "SUCCESS" "Project started in background (PID: $main_pid)"
        echo -e "${COLORS[GREEN]}✓ Project started in background (PID: $main_pid)${COLORS[RESET]}"
        echo -e "${COLORS[DIM]}Background log: $BG_LOG_FILE${COLORS[RESET]}"
        if [[ "$HELPER_RUNNING" == "true" ]]; then
            echo -e "${COLORS[DIM]}Helper log: $HELPER_LOG_FILE${COLORS[RESET]}"
        fi
        return 0
    else
        log "ERROR" "Failed to start project in background"
        echo -e "${COLORS[RED]}✗ Failed to start project in background${COLORS[RESET]}"
        rm -f "$PID_FILE"
        stop_helper
        return 1
    fi
}

stop_project_background() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "Stopping background project (PID: $pid)"
            echo -e "${COLORS[YELLOW]}Stopping background project (PID: $pid)...${COLORS[RESET]}"
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            echo -e "${COLORS[GREEN]}✓ Background project stopped${COLORS[RESET]}"
        else
            echo -e "${COLORS[YELLOW]}Background project not running (stale PID file)${COLORS[RESET]}"
        fi
        rm -f "$PID_FILE"
    else
        echo -e "${COLORS[YELLOW]}No background project running${COLORS[RESET]}"
    fi
    
    # Also stop helper.py
    stop_helper
}

uninstall_project() {
    echo -e "${COLORS[RED]}${COLORS[BOLD]}=== Uninstall Project ===${COLORS[RESET]}"
    safe_read "$(echo -e "${COLORS[RED]}Really uninstall? [y/N]: ${COLORS[RESET]}")" 10 "n"
    
    if [[ "${REPLY,,}" == "y" ]]; then
        # Stop any running processes first
        stop_project_background
        
        if [[ -d "$PROJECT_DIR" ]]; then
            log "INFO" "Removing project directory"
            rm -rf "$PROJECT_DIR"
            echo -e "${COLORS[GREEN]}✓ Project uninstalled${COLORS[RESET]}"
        else
            echo -e "${COLORS[YELLOW]}Project not installed${COLORS[RESET]}"
        fi
        
        # Clean up system command if installed
        remove_system_command
    else
        echo -e "${COLORS[CYAN]}Uninstall cancelled${COLORS[RESET]}"
    fi
    
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

# =================================================================
# SYSTEM COMMAND FUNCTIONS
# =================================================================

install_system_command() {
    local cmd_name="firewall"
    local install_dir="/usr/local/bin"
    local script_dir="/usr/local/bin/custom-scripts"
    local symlink_path="$install_dir/$cmd_name"
    
    echo -e "${COLORS[CYAN]}Installing system command '$cmd_name'...${COLORS[RESET]}"
    
    if [[ ! -d "$PROJECT_DIR" ]]; then
        log "ERROR" "Project not installed"
        echo -e "${COLORS[RED]}Error: Project not installed${COLORS[RESET]}"
        return 1
    fi
    
    # Create custom scripts directory
    mkdir -p "$script_dir"
    
    # Create wrapper script with virtual environment support
    cat > "$script_dir/$cmd_name" << 'EOF'
#!/bin/bash
# WAF System Command Wrapper with Virtual Environment Support
PROJECT_DIR="/Web-Application-FireWall"
VENV_DIR="$PROJECT_DIR/venv"
HELPER_PID_FILE="/tmp/waf_helper.pid"
HELPER_LOG_FILE="/tmp/waf_helper.log"

# Function to get correct Python executable
get_python_executable() {
    if [[ -f "$VENV_DIR/bin/python" ]]; then
        echo "$VENV_DIR/bin/python"
    else
        echo "python3"
    fi
}

# Function to start helper.py if not running
start_helper_if_needed() {
    if [[ -f "$PROJECT_DIR/helper.py" ]] && [[ ! -f "$HELPER_PID_FILE" || ! $(kill -0 "$(cat "$HELPER_PID_FILE")" 2>/dev/null) ]]; then
        echo "Starting helper.py..."
        local python_exec=$(get_python_executable)
        cd "$PROJECT_DIR"
        nohup "$python_exec" "$PROJECT_DIR/helper.py" > "$HELPER_LOG_FILE" 2>&1 &
        echo $! > "$HELPER_PID_FILE"
        sleep 2
        echo "Helper.py started successfully"
    fi
}

if [[ -d "$PROJECT_DIR" ]]; then
    cd "$PROJECT_DIR"
    start_helper_if_needed
    python_exec=$(get_python_executable)
    "$python_exec" firewall.py "$@"
else
    echo "Error: WAF project not found at $PROJECT_DIR"
    exit 1
fi
EOF
    
    chmod +x "$script_dir/$cmd_name"
    
    # Create symlink
    if [[ -L "$symlink_path" ]]; then
        rm "$symlink_path"
    fi
    
    ln -s "$script_dir/$cmd_name" "$symlink_path"
    
    # Verify installation
    if command -v "$cmd_name" >/dev/null 2>&1; then
        log "SUCCESS" "System command '$cmd_name' installed"
        echo -e "${COLORS[GREEN]}✓ System command '$cmd_name' installed${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}You can now run: $cmd_name${COLORS[RESET]}"
        echo -e "${COLORS[DIM]}This will automatically start helper.py before firewall.py using the virtual environment${COLORS[RESET]}"
    else
        log "ERROR" "Failed to install system command"
        echo -e "${COLORS[RED]}✗ Failed to install system command${COLORS[RESET]}"
        return 1
    fi
}

remove_system_command() {
    local cmd_name="firewall"
    local install_dir="/usr/local/bin"
    local script_dir="/usr/local/bin/custom-scripts"
    local symlink_path="$install_dir/$cmd_name"
    
    if command -v "$cmd_name" >/dev/null 2>&1; then
        log "INFO" "Removing system command '$cmd_name'"
        echo -e "${COLORS[YELLOW]}Removing system command '$cmd_name'...${COLORS[RESET]}"
        
        # Remove symlink
        [[ -L "$symlink_path" ]] && rm "$symlink_path"
        
        # Remove script
        [[ -f "$script_dir/$cmd_name" ]] && rm "$script_dir/$cmd_name"
        
        echo -e "${COLORS[GREEN]}✓ System command '$cmd_name' removed${COLORS[RESET]}"
    else
        echo -e "${COLORS[YELLOW]}System command '$cmd_name' not installed${COLORS[RESET]}"
    fi
}

# =================================================================
# STATUS AND MONITORING FUNCTIONS
# =================================================================

show_project_status() {
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}PROJECT STATUS${COLORS[RESET]}"
    echo "================================="

    if [[ -d "$PROJECT_DIR" ]]; then
        echo -e "${COLORS[GREEN]}✓ Project: INSTALLED${COLORS[RESET]}"
        echo -e "Location: $PROJECT_DIR"

        # Check virtual environment
        if [[ -d "$VENV_DIR" ]]; then
            echo -e "${COLORS[GREEN]}✓ Virtual Environment: CONFIGURED${COLORS[RESET]}"
            echo -e "Location: $VENV_DIR"
        else
            echo -e "${COLORS[YELLOW]}○ Virtual Environment: NOT CONFIGURED${COLORS[RESET]}"
        fi

        # Check helper.py status
        if is_helper_running; then
            local helper_pid=$(cat "$HELPER_PID_FILE")
            echo -e "${COLORS[GREEN]}✓ Helper.py: RUNNING (PID: $helper_pid)${COLORS[RESET]}"
        else
            echo -e "${COLORS[YELLOW]}○ Helper.py: NOT RUNNING${COLORS[RESET]}"
        fi

        # Check main project status
        if is_project_running; then
            local pid=$(cat "$PID_FILE")
            echo -e "${COLORS[GREEN]}✓ Background: RUNNING (PID: $pid)${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ Background: NOT RUNNING${COLORS[RESET]}"
        fi
    else
        echo -e "${COLORS[RED]}✗ Project: NOT INSTALLED${COLORS[RESET]}"
    fi
    
    # Show log file locations
    echo -e "\n${COLORS[CYAN]}Log Files:${COLORS[RESET]}"
    [[ -f "$HELPER_LOG_FILE" ]] && echo -e "${COLORS[DIM]}  Helper: $HELPER_LOG_FILE${COLORS[RESET]}"
    [[ -f "$BG_LOG_FILE" ]] && echo -e "${COLORS[DIM]}  Background: $BG_LOG_FILE${COLORS[RESET]}"
    [[ -f "$LOG_FILE" ]] && echo -e "${COLORS[DIM]}  Installer: $LOG_FILE${COLORS[RESET]}"
    
    # Check for helper.py file
    if [[ -f "$PROJECT_DIR/helper.py" ]]; then
        echo -e "${COLORS[GREEN]}✓ Helper.py: FOUND${COLORS[RESET]}"
    else
        echo -e "${COLORS[YELLOW]}○ Helper.py: NOT FOUND${COLORS[RESET]}"
    fi
    
    # Check system command
    if command -v firewall >/dev/null 2>&1; then
        echo -e "${COLORS[GREEN]}✓ System Command: INSTALLED${COLORS[RESET]}"
    else
        echo -e "${COLORS[YELLOW]}○ System Command: NOT INSTALLED${COLORS[RESET]}"
    fi
}

view_background_logs() {
    echo -e "${COLORS[CYAN]}${COLORS[BOLD]}=== Background Logs ===${COLORS[RESET]}"
    
    if [[ -f "$BG_LOG_FILE" ]]; then
        echo -e "${COLORS[CYAN]}Main Background Logs (last 20 lines):${COLORS[RESET]}"
        echo "=================================================="
        tail -20 "$BG_LOG_FILE" 2>/dev/null || echo "No logs available"
        echo
    else
        echo -e "${COLORS[YELLOW]}No main background log file found${COLORS[RESET]}"
    fi
    
    if [[ -f "$HELPER_LOG_FILE" ]]; then
        echo -e "${COLORS[CYAN]}Helper.py Logs (last 20 lines):${COLORS[RESET]}"
        echo "=================================================="
        tail -20 "$HELPER_LOG_FILE" 2>/dev/null || echo "No helper logs available"
        echo
    else
        echo -e "${COLORS[YELLOW]}No helper log file found${COLORS[RESET]}"
    fi
    
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

# =================================================================
# ENHANCED MENU SYSTEM
# =================================================================

run_project_interactive() {
    echo -e "${COLORS[BOLD]}${COLORS[BLUE]}=== Run WAF Project ===${COLORS[RESET]}"
    echo -e "${COLORS[CYAN]}Choose execution mode:${COLORS[RESET]}"
    echo -e "${COLORS[GREEN]}1) Run interactively (helper.py + firewall.py)${COLORS[RESET]}"
    echo -e "${COLORS[BLUE]}2) Run in background${COLORS[RESET]}"
    echo -e "${COLORS[YELLOW]}3) Show project status${COLORS[RESET]}"
    echo -e "${COLORS[RED]}4) Stop all processes${COLORS[RESET]}"
    echo -e "${COLORS[WHITE]}5) Back to main menu${COLORS[RESET]}"
    
    safe_read "$(echo -e "${COLORS[YELLOW]}Choose [1-5]: ${COLORS[RESET]}")" 30 "5"
    
    case "${REPLY:-5}" in
    1)
        if [[ -d "$PROJECT_DIR" ]]; then
            start_project_with_helper "firewall.py"
        else
            echo -e "${COLORS[RED]}Project not installed${COLORS[RESET]}"
        fi
        ;;
    2)
        if [[ -d "$PROJECT_DIR" ]]; then
            start_project_background "firewall.py"
        else
            echo -e "${COLORS[RED]}Project not installed${COLORS[RESET]}"
        fi
        ;;
    3)
        show_project_status
        safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
        ;;
    4)
        echo -e "${COLORS[RED]}Stopping all processes...${COLORS[RESET]}"
        stop_project_background
        ;;
    5)
        return 0
        ;;
    *)
        echo -e "${COLORS[RED]}Invalid choice${COLORS[RESET]}"
        ;;
    esac
}

# =================================================================
# MAIN MENU SYSTEM
# =================================================================

main_menu() {
    # Set up signal handlers
    trap safe_interrupt_handler SIGINT SIGTERM
    trap cleanup_and_exit EXIT

    while true; do
        clear
        echo -e "${COLORS[BOLD]}${COLORS[CYAN]}"
        echo "================================================================"
        echo "       Web Application Firewall Installer (Enhanced)"
        echo "              with Helper.py & Virtual Environment"
        echo "================================================================"
        echo -e "${COLORS[RESET]}"

        echo -e "${COLORS[BLUE]}  1)${COLORS[RESET]} Install/Setup Project (with Virtual Environment)"
        echo -e "${COLORS[GREEN]}  2)${COLORS[RESET]} Run Project (Interactive/Background)"
        echo -e "${COLORS[YELLOW]}  3)${COLORS[RESET]} Stop Background Process"
        echo -e "${COLORS[CYAN]}  4)${COLORS[RESET]} Show Project Status"
        echo -e "${COLORS[MAGENTA]}  5)${COLORS[RESET]} View Background Logs"
        echo -e "${COLORS[RED]}  6)${COLORS[RESET]} Uninstall Project"
        echo -e "${COLORS[GREEN]}  7)${COLORS[RESET]} Install 'firewall' system command"
        echo -e "${COLORS[RED]}  8)${COLORS[RESET]} Remove 'firewall' system command"
        echo -e "${COLORS[WHITE]}  9)${COLORS[RESET]} Exit (preserve background processes)"
        echo -e "${COLORS[RED]} 10)${COLORS[RESET]} Exit and stop all processes"
        echo

        # Safe input with timeout
        safe_read "$(echo -e "${COLORS[YELLOW]}Choose option [1-10]: ${COLORS[RESET]}")" 30 "9"

        case "${REPLY:-9}" in
        1) 
            setup_project 
            ;;
        2)
            run_project_interactive
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
            # Normal exit - preserve background processes
            NORMAL_EXIT=true
            echo -e "${COLORS[GREEN]}Exiting (background processes preserved)...${COLORS[RESET]}"
            break
            ;;
        10)
            # Exit and cleanup
            echo -e "${COLORS[YELLOW]}Stopping all background processes...${COLORS[RESET]}"
            stop_project_background
            NORMAL_EXIT=true
            break
            ;;
        *)
            log "ERROR" "Invalid option: ${REPLY}"
            echo -e "${COLORS[RED]}Invalid option${COLORS[RESET]}"
            sleep 1
            ;;
        esac
    done
}

# =================================================================
# STARTUP
# =================================================================

# Initialize logging
echo "WAF Installer Enhanced with Virtual Environment - $(date)" > "$LOG_FILE"
log "INFO" "Starting Enhanced WAF Installer with Helper.py Integration and Virtual Environment Support"

echo -e "${COLORS[GREEN]}Enhanced WAF installer with helper.py integration and virtual environment support loaded${COLORS[RESET]}"
echo -e "${COLORS[CYAN]}Log file: $LOG_FILE${COLORS[RESET]}"

# Start main menu
main_menu

echo -e "${COLORS[CYAN]}Thank you for using the Enhanced WAF Installer!${COLORS[RESET]}"
