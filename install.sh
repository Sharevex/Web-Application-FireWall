#!/bin/bash
set -e

# Trap Ctrl+C and Ctrl+Z and move to background
trap 'echo "Quitting and running in the background"; setsid "$0" "$@" >/dev/null 2>&1 & disown; exit 0' SIGINT SIGTSTP

export DEBIAN_FRONTEND=noninteractive

PROJECT_DIR="/Web-Application-FireWall"
REPO_URL="https://github.com/Sharevex/Web-Application-FireWall.git"

function reset_project() {
    echo "Resetting previous configuration..."
    sudo rm -rf "$PROJECT_DIR"
    echo "Old project deleted."
}

function setup_project() {
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y python3 python3-venv python3-full git build-essential curl

    echo "Cloning project to / ..."
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
            echo "python3-$pkg not found in repositories; will install $pkg with pip."
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

    echo "------------------------------------------"
    echo "Running ai_detector.py and showing the output:"
    echo "------------------------------------------"
    ./venv/bin/python3 ai_detector.py

    echo "------------------------------------------"
    echo "Running firewall.py and showing the output:"
    echo "------------------------------------------"
    ./venv/bin/python3 firewall.py
}

function update_project() {
    if [ -d "$PROJECT_DIR" ]; then
        echo "Updating existing project..."
        cd "$PROJECT_DIR"
        git pull
        source venv/bin/activate
        ./venv/bin/python3 ai_detector.py
        ./venv/bin/python3 firewall.py
    else
        echo "Project not found. Please install it first."
    fi
}

function uninstall_project() {
    if [ -d "$PROJECT_DIR" ]; then
        echo "Uninstalling project..."
        sudo rm -rf "$PROJECT_DIR"
        echo "Project removed."
    else
        echo "Project not found."
    fi
}

function show_menu() {
    echo "========================================"
    echo "   Web Application Firewall Installer"
    echo "========================================"
    echo "1) Install"
    echo "2) Update"
    echo "3) Uninstall"
    echo "4) Exit"
    echo "========================================"
    read -p "Choose an option [1-4]: " option

    case "$option" in
        1)
            reset_project
            setup_project
            ;;
        2)
            update_project
            ;;
        3)
            uninstall_project
            ;;
        4)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            show_menu
            ;;
    esac
}

# Entry point
show_menu
