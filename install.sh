#!/bin/bash

set -e

# Ensure apt works without prompts
export DEBIAN_FRONTEND=noninteractive

cd /opt || exit 1

# Clone or update repo
if [ ! -d Web-Application-FireWall ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

# Install pip3 if missing
if [ -f requirements.txt ]; then
  if ! command -v pip3 &> /dev/null; then
    apt update
    apt install -y python3-pip
  fi
  pip3 install -r requirements.txt
fi

# Kill previous instance
pkill -f start.sh || true

# Start application and log output
nohup ./start.sh > output.txt 2>&1 &

# Add cron job for persistence
CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
(crontab -l 2>/dev/null; echo "$CRONJOB") | grep -Fv "$CRONJOB" | cat - <(echo "$CRONJOB") | crontab -

echo "Setup complete."
