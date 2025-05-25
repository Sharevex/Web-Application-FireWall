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

# (Optional) Install dependencies if needed
# e.g., pip install -r requirements.txt

# (Optional) Stop existing instance
pkill -f start.sh || true

# (Optional) Start application (edit below as needed!)
nohup ./start.sh > /dev/null 2>&1 &

# Setup cron to keep it running. Adjust the file/command if needed.
(crontab -l 2>/dev/null; echo "*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup ./start.sh > /dev/null 2>&1 &") | sort -u | crontab -
