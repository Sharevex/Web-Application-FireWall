#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt update && apt upgrade -y
apt install -y python3 python3-venv python3-full git build-essential

cd /opt || exit 1

if [ ! -d Web-Application-FireWall ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git
else
  cd Web-Application-FireWall && git pull && cd ..
fi

cd Web-Application-FireWall

# Always fresh venv for reliability
rm -rf venv
python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip

# Try normal install first, fallback to break-system-packages if blocked
if ! pip install -r requirements.txt; then
   pip install --break-system-packages -r requirements.txt
fi

pkill -f start.sh || true
nohup ./venv/bin/python ./start.sh > output.txt 2>&1 &

CRONJOB="*/5 * * * * cd /opt/Web-Application-FireWall && source venv/bin/activate && pgrep -f start.sh > /dev/null || nohup ./venv/bin/python ./start.sh > /opt/Web-Application-FireWall/output.txt 2>&1 &"
(crontab -l 2>/dev/null | grep -Fv "$CRONJOB"; echo "$CRONJOB") | crontab -

echo "Setup complete. All installed in a virtualenv."
