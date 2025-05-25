#!/bin/bash

# Change to /opt or another preferred directory
cd /opt || exit 1

# Git clone or update
if [ ! -d Web-Application-FireWall ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

# Install pip3 if not present, then install requirements
if [ -f requirements.txt ]; then
  if ! command -v pip3 &> /dev/null; then
    apt update && apt install -y python3-pip
  fi
  pip3 install -r requirements.txt
fi

# Kill previous instance (adjust as needed)
pkill -f start.sh || true

# Start application and save output to output.txt
nohup ./start.sh > output.txt 2>&1 &

# Add cron job to keep running (saves output as well)
(crontab -l 2>/dev/null; \
 echo "*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &" \
) | sort -u | crontab -
