#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# Ignore Ctrl+C (SIGINT) to allow script continuation
trap '' SIGINT

sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-full git build-essential curl

# Clone or update project
cd /opt
if [ ! -d Web-Application-FireWall ]; then
  sudo git clone https://github.com/Sharevex/Web-Application-FireWall.git
  sudo chown -R "$USER":"$USER" Web-Application-FireWall
else
  cd Web-Application-FireWall && git pull && cd ..
fi
cd Web-Application-FireWall

# Try apt install for supported packages, fallback to pip
PY_PKGS=("netifaces" "colorama")
APT_PKGS=()
PIP_PKGS=()

for pkg in "${PY_PKGS[@]}"; do
    if apt-cache show python3-$pkg >/dev/null 2>&1; then
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

# If you want to run the external script AFTER, uncomment the next line:
# bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/6TO4-GRE-IPIP-SIT/main/ubuntu24.sh)"

