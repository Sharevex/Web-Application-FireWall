#!/bin/bash

# Enhanced Web Application Firewall Installer with Proper Signal Handling
# Author: Enhanced version with fixed interrupt handling
# Description: Automated installer for Web Application Firewall with reliable signal handling

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
readonly BG_LOG_FILE="/tmp/waf_background.log"
readonly VENV_DIR="$PROJECT_DIR/venv"

export DEBIAN_FRONTEND=noninteractive

# Global flags
INTERRUPTIBLE=true
NORMAL_EXIT=false
FORCE_CLEANUP=false

# =================================================================
# SIGNAL HANDLING - FIXED VERSION
# =================================================================

# Cleanup function - only kills processes if forced or interrupted
cleanup_and_exit() {
    # Don't cleanup if this is a normal menu exit
    if [[ "$NORMAL_EXIT" == "true" ]]; then
        return 0
    fi

    echo -e "\n${COLORS[YELLOW]}Cleaning up and exiting...${COLORS[RESET]}"

    # Only kill child processes if we were interrupted or explicitly asked to cleanup
    if [[ "$FORCE_CLEANUP" == "true" ]]; then
        local children=$(jobs -p 2>/dev/null || true)
        if [[ -n "$children" ]]; then
            echo "Stopping background jobs..."
            kill $children 2>/dev/null || true
            wait $children 2>/dev/null || true
        fi
    fi

    # Reset terminal
    stty sane 2>/dev/null || true

    echo -e "${COLORS[CYAN]}Log file: $LOG_FILE${COLORS[RESET]}"
    exit 0
}

# Safe interrupt handler - preserves background processes unless explicitly stopped
safe_interrupt_handler() {
    if [[ "$INTERRUPTIBLE" == "true" ]]; then
        echo -e "\n${COLORS[YELLOW]}=== Interrupted! ===${COLORS[RESET]}"
        echo -e "${COLORS[CYAN]}Options:${COLORS[RESET]}"
        echo -e "${COLORS[GREEN]}1) Start project in background and return to menu${COLORS[RESET]}"
        echo -e "${COLORS[BLUE]}2) Return to main menu${COLORS[RESET]}"
        echo -e "${COLORS[RED]}3) Exit completely (preserves background processes)${COLORS[RESET]}"
        echo -e "${COLORS[RED]}4) Exit and stop all processes${COLORS[RESET]}"

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
            echo -e "${COLORS[GREEN]}Starting project in background...${COLORS[RESET]}"
            start_project_background "firewall.py" 2>/dev/null || true
            return 0
            ;;
        2)
            echo -e "${COLORS[BLUE]}Returning to menu...${COLORS[RESET]}"
            return 0
            ;;
        3)
            echo -e "${COLORS[GREEN]}Exiting (background processes will continue)...${COLORS[RESET]}"
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
    else
        # Force exit if not in interruptible state
        echo -e "\n${COLORS[RED]}Force interrupting...${COLORS[RESET]}"
        FORCE_CLEANUP=true
        cleanup_and_exit
    fi
}

# Set up proper signal traps
setup_traps() {
    # Handle Ctrl+C (SIGINT) and Ctrl+Z (SIGTSTP)
    trap 'safe_interrupt_handler' SIGINT
    trap 'safe_interrupt_handler' SIGTSTP
    # Handle script termination - but don't auto-cleanup on normal exit
    trap 'cleanup_and_exit' SIGTERM
}

# Disable interrupts during critical operations
disable_interrupts() {
    INTERRUPTIBLE=false
    trap 'echo -e "\n${COLORS[RED]}Please wait, critical operation in progress...${COLORS[RESET]}"' SIGINT SIGTSTP
}

# Re-enable interrupts
enable_interrupts() {
    INTERRUPTIBLE=true
    setup_traps
}

# =================================================================
# BACKGROUND EXECUTION FUNCTIONS - IMPROVED
# =================================================================

start_project_background() {
    local project_file="${1:-firewall.py}"

    if [[ ! -d "$PROJECT_DIR" ]]; then
        log "ERROR" "Project not installed. Please install first."
        return 1
    fi

    cd "$PROJECT_DIR" || return 1

    if [[ ! -f "$project_file" ]]; then
        log "ERROR" "$project_file not found in project directory"
        return 1
    fi

    # Check if already running
    if is_project_running; then
        local existing_pid=$(cat "$PID_FILE" 2>/dev/null)
        log "WARN" "Project is already running in background (PID: $existing_pid)"
        return 0
    fi

    log "INFO" "Starting $project_file in background..."

    # Ensure virtual environment exists
    if [[ ! -f "./venv/bin/python3" ]]; then
        log "ERROR" "Virtual environment not found. Please reinstall the project."
        return 1
    fi

    # Start the project in background with proper redirection
    nohup ./venv/bin/python3 "$project_file" </dev/null >>"$BG_LOG_FILE" 2>&1 &
    local pid=$!

    # Disown the process so it won't be killed when the script exits
    disown

    # Save PID for later reference
    echo "$pid" >"$PID_FILE"

    # Brief wait to check if it started successfully
    sleep 2

    if kill -0 "$pid" 2>/dev/null; then
        log "SUCCESS" "Project started successfully in background (PID: $pid)"
        log "INFO" "Background logs: $BG_LOG_FILE"
        log "INFO" "Process is detached and will continue after script exit"
        return 0
    else
        log "ERROR" "Failed to start project in background"
        rm -f "$PID_FILE"
        return 1
    fi
}

is_project_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$PID_FILE"
            return 1
        fi
    fi
    return 1
}

stop_project_background() {
    if [[ ! -f "$PID_FILE" ]]; then
        log "INFO" "No background process running"
        return 0
    fi

    local pid=$(cat "$PID_FILE" 2>/dev/null)
    if [[ -z "$pid" ]]; then
        log "WARN" "Invalid PID file, cleaning up..."
        rm -f "$PID_FILE"
        return 0
    fi

    if kill -0 "$pid" 2>/dev/null; then
        log "INFO" "Stopping background process (PID: $pid)..."

        # Graceful shutdown
        kill -TERM "$pid" 2>/dev/null || true

        # Wait up to 5 seconds for graceful shutdown
        for i in {1..5}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 1
        done

        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            log "WARN" "Process still running, forcing termination..."
            kill -KILL "$pid" 2>/dev/null || true
            sleep 1
        fi

        if ! kill -0 "$pid" 2>/dev/null; then
            log "SUCCESS" "Background process stopped successfully"
        else
            log "ERROR" "Failed to stop background process"
            return 1
        fi
    else
        log "INFO" "Background process was not running"
    fi

    rm -f "$PID_FILE"
    return 0
}

# =================================================================
# UTILITY FUNCTIONS - IMPROVED
# =================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
    "INFO") echo -e "${COLORS[CYAN]}[INFO]${COLORS[RESET]} $message" ;;
    "WARN") echo -e "${COLORS[YELLOW]}[WARN]${COLORS[RESET]} $message" ;;
    "ERROR") echo -e "${COLORS[RED]}[ERROR]${COLORS[RESET]} $message" ;;
    "SUCCESS") echo -e "${COLORS[GREEN]}[SUCCESS]${COLORS[RESET]} $message" ;;
    esac

    # Log to file with error handling
    echo "[$timestamp] [$level] $message" >>"$LOG_FILE" 2>/dev/null || true
}

# Safe progress indicator that can be interrupted
show_progress() {
    local message="$1"
    local duration="${2:-3}"

    echo -ne "${COLORS[CYAN]}$message"
    for ((i = 0; i < duration; i++)); do
        if [[ "$INTERRUPTIBLE" == "false" ]]; then
            echo -n "."
        else
            # Use brief sleep to allow interruption
            sleep 0.2
            echo -n "."
            sleep 0.2
            echo -n "."
            sleep 0.2
            echo -n "."
            sleep 0.2
            echo -n "."
            sleep 0.2
        fi
    done
    echo -e "${COLORS[RESET]}"
}

# Safe read with timeout
safe_read() {
    local prompt="$1"
    local timeout="${2:-30}"
    local default="${3:-}"

    echo -n "$prompt"
    if read -t "$timeout" -r REPLY 2>/dev/null; then
        echo
    else
        echo -e "\n${COLORS[DIM]}Timeout - using default: ${default:-N}${COLORS[RESET]}"
        REPLY="$default"
    fi
}

# =================================================================
# CORE FUNCTIONS - WITH PROPER SIGNAL HANDLING
# =================================================================

setup_project() {
    log "INFO" "Starting Web Application Firewall installation..."

    # Disable interrupts during critical package operations
    disable_interrupts

    log "INFO" "Updating system packages..."
    if ! sudo apt update -qq 2>/dev/null; then
        log "ERROR" "Failed to update package lists"
        enable_interrupts
        return 1
    fi

    log "INFO" "Installing base dependencies..."
    local base_packages=("python3" "python3-venv" "python3-full" "git" "build-essential")

    if ! sudo apt install -y "${base_packages[@]}" -qq 2>/dev/null; then
        log "ERROR" "Failed to install base packages"
        enable_interrupts
        return 1
    fi

    # Re-enable interrupts for git operations
    enable_interrupts

    log "INFO" "Cloning project repository..."
    if [[ -d "$PROJECT_DIR" ]]; then
        log "WARN" "Project directory exists, removing..."
        sudo rm -rf "$PROJECT_DIR"
    fi

    # Git clone with timeout to prevent hanging
    if ! timeout 60s sudo git clone "$REPO_URL" "$PROJECT_DIR"; then
        log "ERROR" "Failed to clone repository (timeout or network error)"
        return 1
    fi

    sudo chown -R "$USER":"$USER" "$PROJECT_DIR" 2>/dev/null || true
    cd "$PROJECT_DIR" || {
        log "ERROR" "Cannot access project directory"
        return 1
    }

    # Setup Python environment
    setup_python_environment || {
        log "ERROR" "Python setup failed"
        return 1
    }

    log "SUCCESS" "Installation completed successfully!"

    # Ask if user wants to start in background
    safe_read "$(echo -e "${COLORS[YELLOW]}Start firewall in background now? [y/N]: ${COLORS[RESET]}")" 10 "N"
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_project_background "firewall.py"

        # Wait a moment for firewall to initialize
        sleep 2
        
        # Ask separately about running helper.py for configuration
        safe_read "$(echo -e "${COLORS[YELLOW]}Run configuration helper now? [y/N]: ${COLORS[RESET]}")" 10 "Y"
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Running helper.py for configuration..."
            source "$VENV_DIR/bin/activate"
            
            # Ensure we have proper terminal access for interactive input
            if [[ -t 0 ]]; then
                python3 helper.py
            else
                # Force terminal allocation if stdin is not a terminal
                python3 helper.py < /dev/tty
            fi
        else
            log "INFO" "Configuration skipped. You can run 'cd $PROJECT_DIR && source venv/bin/activate && python3 helper.py' later"
        fi
    fi
}


setup_python_environment() {
    log "INFO" "Setting up Python virtual environment..."

    # Remove existing venv if present
    [[ -d "venv" ]] && rm -rf venv

    # Create virtual environment with timeout
    if ! timeout 30s python3 -m venv venv; then
        log "ERROR" "Failed to create virtual environment"
        return 1
    fi

    # Activate and setup
    source venv/bin/activate || {
        log "ERROR" "Cannot activate virtual environment"
        return 1
    }

    log "INFO" "Upgrading pip..."
    python -m pip install --upgrade pip -q --timeout 30 || {
        log "WARN" "Pip upgrade failed, continuing..."
    }

    # Install requirements if available
    if [[ -f "requirements.txt" ]]; then
        log "INFO" "Installing project requirements..."
        if ! pip install -r requirements.txt -q --timeout 60; then
            log "WARN" "Some packages may have failed to install"
        fi
    fi

    log "SUCCESS" "Python environment setup completed"
}

# =================================================================
# SYSTEM COMMAND INSTALLATION FUNCTION
# =================================================================

install_system_command() {
    local script_path="$(realpath "$0")"
    local command_name="firewall"
    local install_dir="/usr/local/bin"
    local scripts_dir="/usr/local/bin/custom-scripts"

    log "INFO" "Installing system command '$command_name'..."

    # Check if we have sudo access
    if ! sudo -n true 2>/dev/null; then
        log "WARN" "Sudo access required for system command installation"
        safe_read "$(echo -e "${COLORS[YELLOW]}Enter sudo password to continue or press Enter to skip: ${COLORS[RESET]}")" 30 ""
        if [[ -z "$REPLY" ]]; then
            log "INFO" "System command installation skipped"
            return 0
        fi
    fi

    # Create custom scripts directory
    if ! sudo mkdir -p "$scripts_dir"; then
        log "ERROR" "Failed to create scripts directory"
        return 1
    fi

    # Copy script to permanent location
    local target_script="$scripts_dir/${command_name}.sh"
    if ! sudo cp "$script_path" "$target_script"; then
        log "ERROR" "Failed to copy script to $target_script"
        return 1
    fi

    # Make it executable
    if ! sudo chmod +x "$target_script"; then
        log "ERROR" "Failed to make script executable"
        return 1
    fi

    # Create symbolic link
    local symlink_path="$install_dir/$command_name"
    if [[ -L "$symlink_path" ]] || [[ -f "$symlink_path" ]]; then
        log "WARN" "Command '$command_name' already exists, removing old version..."
        sudo rm -f "$symlink_path" 2>/dev/null || true
    fi

    if ! sudo ln -s "$target_script" "$symlink_path"; then
        log "ERROR" "Failed to create symbolic link"
        return 1
    fi

    # Verify installation
    if command -v "$command_name" >/dev/null 2>&1; then
        log "SUCCESS" "System command '$command_name' installed successfully!"
        log "INFO" "You can now run '$command_name' from anywhere in the terminal"
        log "INFO" "Script location: $target_script"
        log "INFO" "Command link: $symlink_path"
        return 0
    else
        log "ERROR" "Command installation verification failed"
        return 1
    fi
}

remove_system_command() {
    local command_name="firewall"
    local install_dir="/usr/local/bin"
    local scripts_dir="/usr/local/bin/custom-scripts"
    local symlink_path="$install_dir/$command_name"
    local target_script="$scripts_dir/${command_name}.sh"

    log "INFO" "Removing system command '$command_name'..."

    # Check if command exists
    if ! command -v "$command_name" >/dev/null 2>&1; then
        log "INFO" "System command '$command_name' is not installed"
        return 0
    fi

    # Remove symbolic link
    if [[ -L "$symlink_path" ]] || [[ -f "$symlink_path" ]]; then
        if sudo rm -f "$symlink_path"; then
            log "SUCCESS" "Removed command link: $symlink_path"
        else
            log "WARN" "Failed to remove command link"
        fi
    fi

    # Remove script file
    if [[ -f "$target_script" ]]; then
        if sudo rm -f "$target_script"; then
            log "SUCCESS" "Removed script file: $target_script"
        else
            log "WARN" "Failed to remove script file"
        fi
    fi

    # Remove scripts directory if empty
    if [[ -d "$scripts_dir" ]] && [[ -z "$(ls -A "$scripts_dir" 2>/dev/null)" ]]; then
        if sudo rmdir "$scripts_dir" 2>/dev/null; then
            log "INFO" "Removed empty scripts directory"
        fi
    fi

    # Verify removal
    if ! command -v "$command_name" >/dev/null 2>&1; then
        log "SUCCESS" "System command '$command_name' removed successfully!"
        return 0
    else
        log "WARN" "Command may still be accessible (check your PATH)"
        return 1
    fi
}

# =================================================================
# MENU SYSTEM - WITH SAFE INPUT HANDLING
# =================================================================

show_menu() {
    setup_traps

    while true; do
        clear

        # Header
        echo -e "${COLORS[BOLD]}${COLORS[CYAN]}"
        echo "================================================================="
        echo "              Web Application Firewall Installer                "
        echo "================================================================="
        echo -e "${COLORS[RESET]}"

        # Show background status
        if is_project_running; then
            local pid=$(cat "$PID_FILE" 2>/dev/null)
            echo -e "${COLORS[GREEN]}🟢 Background Process: RUNNING (PID: $pid)${COLORS[RESET]}"
        else
            echo -e "${COLORS[DIM]}⚫ Background Process: Not Running${COLORS[RESET]}"
        fi
        echo

        # Menu options
        # Menu options
        echo -e "${COLORS[GREEN]}  1)${COLORS[RESET]} Install/Reinstall Project"
        echo -e "${COLORS[BLUE]}  2)${COLORS[RESET]} Start Project in Background"
        echo -e "${COLORS[YELLOW]}  3)${COLORS[RESET]} Stop Background Process"
        echo -e "${COLORS[CYAN]}  4)${COLORS[RESET]} Check Status"
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
        1) setup_project ;;
        2)
            if [[ -d "$PROJECT_DIR" ]]; then
                start_project_background "firewall.py"
            else
                log "ERROR" "Project not installed"
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
            # Normal exit - preserve background processes
            NORMAL_EXIT=true
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

        if is_project_running; then
            local pid=$(cat "$PID_FILE" 2>/dev/null)
            echo -e "${COLORS[GREEN]}✓ Background: RUNNING (PID: $pid)${COLORS[RESET]}"
        else
            echo -e "${COLORS[RED]}✗ Background: NOT RUNNING${COLORS[RESET]}"
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

    echo -e "${COLORS[CYAN]}Background Logs (last 20 lines):${COLORS[RESET]}"
    echo "=================================================="
    tail -20 "$BG_LOG_FILE" 2>/dev/null || echo "No logs available"
    echo
    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

uninstall_project() {
    safe_read "$(echo -e "${COLORS[RED]}Really uninstall? [y/N]: ${COLORS[RESET]}")" 10 "N"

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        stop_project_background
        log "INFO" "Uninstalling..."
        sudo rm -rf "$PROJECT_DIR" 2>/dev/null || true
        rm -f "$PID_FILE" "$BG_LOG_FILE" 2>/dev/null || true
        log "SUCCESS" "Project uninstalled"
    else
        log "INFO" "Uninstall cancelled"
    fi

    safe_read "$(echo -e "${COLORS[CYAN]}Press Enter to continue...${COLORS[RESET]}")" 10
}

# =================================================================
# ENTRY POINT
# =================================================================

main() {
    # Initialize
    touch "$LOG_FILE" "$BG_LOG_FILE" 2>/dev/null || true
    log "INFO" "Installer started"

    # Ensure we can handle signals properly
    setup_traps

    # Check if we have required permissions
    if ! touch /tmp/test_write 2>/dev/null; then
        echo -e "${COLORS[RED]}ERROR: Cannot write to /tmp directory${COLORS[RESET]}"
        exit 1
    fi
    rm -f /tmp/test_write 2>/dev/null || true

    # Run main menu
    show_menu

    # Clean exit message
    echo -e "${COLORS[MAGENTA]}Thank you for using the installer!${COLORS[RESET]}"
    if is_project_running; then
        echo -e "${COLORS[GREEN]}Background processes are still running and will continue.${COLORS[RESET]}"
    fi
    log "INFO" "Installer finished"
}

# Run the script
main "$@"
