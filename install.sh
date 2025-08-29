#!/usr/bin/env bash
set -e

# 1. Clone/update repo
mkdir -p /opt/firewall
cd /opt/firewall
if [ ! -d ".git" ]; then
  git clone https://github.com/Sharevex/Web-Application-FireWall.git .
else
  git pull
fi

# 2. Create venv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install deployment helper + run setup
python3 - <<'PYCODE'
from deployment_helper import DeploymentHelper

helper = DeploymentHelper(
    service_name="firewall",
    script_path="/opt/firewall/firewall.py",   # adjust if entrypoint differs
    requirements_file="/opt/firewall/requirements.txt",
    env_vars={"APP_SECRET_KEY": "changeme"},   # inject your secrets here
    linux_extra_packages=["iptables"],
)
helper.setup_environment()
helper.install_autostart(user="root")
PYCODE
