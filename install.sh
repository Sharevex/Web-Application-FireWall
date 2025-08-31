#!/usr/bin/env bash
set -euo pipefail

REPO=https://github.com/Sharevex/Web-Application-FireWall.git
APP_DIR=/opt/firewall
VENV_DIR="$APP_DIR/.venv"

export DEBIAN_FRONTEND=noninteractive

# 0) Pre-reqs (Ubuntu/Debian)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq || true
  # base python + venv + pip
  sudo apt-get install -y python3 python3-venv python3-pip || true
  # sometimes ensurepip still missing on older images:
  sudo apt-get install -y python3-distutils || true
  # optional but handy for some wheels
  sudo apt-get install -y build-essential || true
fi

# 1) Clone/update repo
sudo mkdir -p "$APP_DIR"
sudo chown -R "$(id -u):$(id -g)" "$APP_DIR"
cd "$APP_DIR"

if [ ! -d .git ]; then
  git clone "$REPO" .
else
  git pull --ff-only
fi

# 2) Create/activate venv (with fallback)
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
  PYTHON=python3
else
  PYTHON=python3
fi

# 3) Optional: set env vars for your app here (edit as needed)
#    These can also be injected via deployment_helper env_vars.
export APP_SECRET_KEY="${APP_SECRET_KEY:-changeme}"
# Example MySQL settings (uncomment + adjust if you use MySQL)
# export MYSQL_HOST=127.0.0.1
# export MYSQL_PORT=3306
# export MYSQL_USER=admin
# export MYSQL_PASSWORD='At@1381928'
# export MYSQL_DB=admin

# 4) Run deployment helper (installs pip deps + registers service)
$PYTHON - <<'PYCODE'
from deployment_helper import DeploymentHelper
import os, sys

helper = DeploymentHelper(
    service_name="firewall",
    script_path="/opt/firewall/firewall.py",           # adjust if different
    requirements_file="/opt/firewall/requirements.txt",
    env_vars={
        "APP_SECRET_KEY": os.environ.get("APP_SECRET_KEY","changeme"),
        # Uncomment if you want deployment_helper to inject DB envs into systemd:
        # "MYSQL_HOST": os.environ.get("MYSQL_HOST","127.0.0.1"),
        # "MYSQL_PORT": os.environ.get("MYSQL_PORT","3306"),
        # "MYSQL_USER": os.environ.get("MYSQL_USER","admin"),
        # "MYSQL_PASSWORD": os.environ.get("MYSQL_PASSWORD","At@1381928"),
        # "MYSQL_DB": os.environ.get("MYSQL_DB","admin"),
    },
    linux_extra_packages=["iptables"],                 # for OS-level blocking
    log_to_file=False                                  # use journald by default
)
helper.setup_environment()
# On Linux, run as root to allow iptables: user="root"
helper.install_autostart(user="root")
PYCODE

echo "[install] Done. Service should be running. Check status with: sudo systemctl status firewall"
