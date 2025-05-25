#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-full git build-essential curl

cd /opt
if [ ! -d Web-Application-FireWall ]; then
  sudo git clone https://github.com/Sharevex/Web-Application-FireWall.git
  sudo chown -R "$USER":"$USER" Web-Application-FireWall
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

rm -rf venv
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip

echo "Using pip at: $(which pip)"
pip --version

# This will work for all python packages, including netifaces and colorama
if ! pip install -r requirements.txt; then
   echo "Trying with --break-system-packages"
   pip install --break-system-packages -r requirements.txt
fi

pkill -f start.sh || true
nohup ./venv/bin/python3 ./start.sh > output.txt 2>&1 &

CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && pgrep -f start.sh > /dev/null || nohup /opt/Web-Application-FireWall/venv/bin/python3 ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
(crontab -l 2>/dev/null | grep -Fv "$CRONJOB" ; echo "$CRONJOB") | crontab -

echo "Done. App runs in venv."
