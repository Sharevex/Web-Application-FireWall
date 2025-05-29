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
    sudo apt install -y python3 python3-venv python3-full git build-essential curl

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
