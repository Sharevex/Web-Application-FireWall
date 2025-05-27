#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
trap '' SIGINT  # Ignore Ctrl+C to allow script continuation

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

    # Try apt install for supported packages, fallback to pip
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

### Main Logic ###
if [[ "$1" == "--reset" ]]; then
    reset_project
    setup_project
else
    if [ -d "$PROJECT_DIR" ]; then
        echo "Project already exists in $PROJECT_DIR"
        read -p "Do you want to reset and reinstall it? (y/n): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            reset_project
            setup_project
        else
            echo "Skipping reset. Updating project instead..."
            cd "$PROJECT_DIR"
            git pull
            source venv/bin/activate
            ./venv/bin/python3 ai_detector.py
            ./venv/bin/python3 firewall.py
        fi
    else
        setup_project
    fi
fi
