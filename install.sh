#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# Update and upgrade system
sudo apt update && sudo apt upgrade -y

# Install base dependencies
sudo apt install -y python3 python3-venv python3-full git build-essential curl

# Install system-managed Python deps (externally managed workaround)
for pkg in netifaces colorama; do
    package_name=$(apt search python3-$pkg | grep -o "^python3-$pkg\S*")
    if [[ -n "$package_name" ]]; then
        sudo apt install -y "$package_name"
    else
        echo "Package python3-$pkg not found in the repositories."
    fi
done

# Clone or update project
cd /opt
if [ ! -d Web-Application-FireWall ]; then
  sudo git clone https://github.com/Sharevex/Web-Application-FireWall.git
  sudo chown -R "$USER":"$USER" Web-Application-FireWall
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

# Clean and create virtualenv
rm -rf venv
python3 -m venv venv

# Activate venv and upgrade pip
source venv/bin/activate
python -m pip install --upgrade pip

# Print pip info
echo "Using pip at: $(which pip)"
pip --version

# Install remaining Python deps from requirements (should skip netifaces/colorama via apt, but will not error if present)
if ! pip install -r requirements.txt; then
   echo "Standard pip install failed. Trying with --break-system-packages"
   pip install --break-system-packages -r requirements.txt
fi

# Kill previous instance if running
pkill -f start.sh || true

# Start the app
nohup ./venv/bin/python3 ./start.sh > output.txt 2>&1 &

# Setup cronjob to restart as needed
CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup /opt/Web-Application-FireWall/venv/bin/python3 ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
# Avoid duplicate cronjob:
(crontab -l 2>/dev/null | grep -Fv "$CRONJOB" ; echo "$CRONJOB") | crontab -

echo "Done. App runs in venv. If you see errors, send pip output above."
