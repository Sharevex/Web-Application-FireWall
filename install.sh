#!/bin/bash

set -e

export DEBIAN_FRONTEND=noninteractive

apt update && apt upgrade -y
apt install -y python3 python3-venv git build-essential

cd /opt || exit 1

if [ ! -d Web-Application-FireWall ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

# Set up the Python virtual environment
if [ ! -d venv ]; then
    python3 -m venv venv
fi

source venv/bin/activate

# Upgrade pip & install dependencies in the venv
python -m pip install --upgrade pip
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
fi

# Kill old instance
pkill -f start.sh || true

# Start the app using virtualenv python
nohup venv/bin/python ./start.sh > output.txt 2>&1 &

# Add/replace cron job to keep it running
CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || source venv/bin/activate && nohup venv/bin/python ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
(crontab -l 2>/dev/null | grep -Fv "$CRONJOB" ; echo "$CRONJOB") | crontab -

echo "Setup complete. App runs in a Python venv. System is safe."
