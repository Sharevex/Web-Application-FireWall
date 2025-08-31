#!/usr/bin/env bash
set -euo pipefail

REPO=https://github.com/Sharevex/Web-Application-FireWall.git
APP_DIR=/opt/firewall
VENV_DIR="$APP_DIR/.venv"

export DEBIAN_FRONTEND=noninteractive

# 0) Pre-reqs (Ubuntu/Debian)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq || true
  sudo apt-get install -y python3 python3-venv python3-pip python3-distutils build-essential git || true
fi

# 1) Clone/update repo
sudo mkdir -p "$APP_DIR"
sudo chown -R "$(id -u)":"$(id -g)" "$APP_DIR"
cd "$APP_DIR"

if [ ! -d .git ]; then
  git clone "$REPO" .
else
  git pull --ff-only
fi

# 2) Create/activate venv (with fallback to system Python if needed)
USE_SYS_PY=false
if ! [ -x "$VENV_DIR/bin/python3" ]; then
  echo "[install] Creating virtualenv…"
  if ! python3 -m venv "$VENV_DIR"; then
    echo "[install] venv creation failed; will use system Python."
    USE_SYS_PY=true
  fi
fi

if [ "$USE_SYS_PY" = false ]; then
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  PYTHON="$VENV_DIR/bin/python3"
else
  PYTHON="$(command -v python3)"
fi

# 3) Application environment (edit if needed)
export APP_SECRET_KEY="${APP_SECRET_KEY:-changeme}"

# >>> MySQL settings required by your app <<<
export MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
export MYSQL_PORT="${MYSQL_PORT:-3306}"
export MYSQL_USER="${MYSQL_USER:-admin}"
export MYSQL_PASSWORD="${MYSQL_PASSWORD:-At@1381928}"
export MYSQL_DB="${MYSQL_DB:-admin}"

# 4) Run deployment helper (installs pip deps + registers/starts service)
"$PYTHON" - <<'PYCODE'
from deployment_helper import DeploymentHelper
import os, sys

# Use the Python we are currently running (venv or system)
python_exec = sys.executable

helper = DeploymentHelper(
    service_name="firewall",
    script_path="/opt/firewall/firewall.py",           # adjust if different
    requirements_file="/opt/firewall/requirements.txt",
    python_exec=python_exec,
    env_vars={
        "APP_SECRET_KEY": os.environ.get("APP_SECRET_KEY","changeme"),
        "MYSQL_HOST": os.environ.get("MYSQL_HOST","127.0.0.1"),
        "MYSQL_PORT": os.environ.get("MYSQL_PORT","3306"),
        "MYSQL_USER": os.environ.get("MYSQL_USER","admin"),
        "MYSQL_PASSWORD": os.environ.get("MYSQL_PASSWORD","At@1381928"),
        "MYSQL_DB": os.environ.get("MYSQL_DB","admin"),
    },
    linux_extra_packages=["iptables"],
    log_to_file=False
)
helper.setup_environment()
# On Linux, we want iptables, so run as root
helper.install_autostart(user="root")
PYCODE

echo "[install] Done. Service should be running."
echo "Check status:   sudo systemctl status firewall"
echo "View logs:      sudo journalctl -u firewall -n 200 -f"
echo "Env in unit:    systemctl show firewall -p Environment"
