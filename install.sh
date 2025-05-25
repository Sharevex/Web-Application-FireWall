#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# Update and upgrade system
apt update && apt upgrade -y

# Install dependencies
apt install -y python3 python3-venv python3-full git build-essential

# Get latest project code
cd /opt
if [ ! -d Web-Application-FireWall ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git
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

# Debug: print pip info
echo "Using pip at: $(which pip)"
pip --version

# Install requirements (use PEP 668 workaround if needed)
if ! pip install -r requirements.txt; then
   echo "Standard pip install failed. Trying with --break-system-packages"
   pip install --break-system-packages -r requirements.txt
fi

# Kill previous instance, if running
pkill -f start.sh || true

# Start the app (assume start.sh runs python using venv, or update if needed)
nohup ./venv/bin/python3 ./start.sh > output.txt 2>&1 &

# Setup cronjob with full venv python path (avoid "source venv" in cron)
CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup /opt/Web-Application-FireWall/venv/bin/python3 ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
# Avoid duplicate cronjob:
(crontab -l 2>/dev/null | grep -Fv "$CRONJOB" ; echo "$CRONJOB") | crontab -

echo "Done. App runs in venv. If you see any more errors, send the pip output above."
