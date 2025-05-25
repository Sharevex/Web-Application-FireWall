#!/bin/bash

set -e

# Make apt non-interactive and keep system current
export DEBIAN_FRONTEND=noninteractive

apt update && apt upgrade -y

# Install core Python3, pip, and basic build tools/utilities
apt install -y python3 python3-pip python3-venv git build-essential

# Ensure pip is up-to-date
python3 -m pip install --upgrade pip

# Move to /opt and clone or update the repo
cd /opt || exit 1

if [ ! -d Web-Application-FireWall ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

# Install Python dependencies if requirements.txt exists
if [ -f requirements.txt ]; then
  pip3 install --upgrade -r requirements.txt
fi

# Kill previous running instance of the app (edit as needed)
pkill -f start.sh || true

# Start the application and save output to output.txt
nohup ./start.sh > output.txt 2>&1 &

# Add cron job for persistence, only if not already present
CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
(crontab -l 2>/dev/null | grep -Fv "$CRONJOB" ; echo "$CRONJOB") | crontab -

echo "All done. System updated, dependencies installed, project running, cron job set."
