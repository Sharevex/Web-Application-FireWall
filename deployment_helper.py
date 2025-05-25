#!/usr/bin/env python3
"""
deployment_helper.py
--------------------
Utility module to make the firewall project production-ready on
Linux, Windows or macOS.

Core features
=============
1. Detect the current OS.
2. Install Python & OS-level dependencies.
3. Register the project as an auto-starting background service:
     * systemd service on Linux
     * @reboot cron fallback (when systemd unavailable)
     * Scheduled Task on Windows
     * launchd agent on macOS
4. Provide helpers to daemonise/detach a process so it keeps
   running after the controlling shell exits (e.g. after Ctrl+C).

Usage example
=============
from deployment_helper import DeploymentHelper

helper = DeploymentHelper(
        service_name="firewall",
        script_path="/opt/firewall/main.py",   # absolute path!
        requirements_file="requirements.txt"   # optional
)
helper.setup_environment()
helper.install_autostart()
"""

import os
import sys
import json
import shlex
import stat
import subprocess
import platform
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, check: bool = True, capture: bool = False):
    """Run *cmd* in the shell and return completed-process object."""
    print(f"[deploy] ⇒ {cmd}")
    return subprocess.run(cmd, shell=True, check=check,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None,
                          text=True)


def _is_root() -> bool:
    if os.name == "nt":
        # On Windows the presence of the SE_DEBUG_NAME privilege can be checked
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DeploymentHelper:
    """
    Bundle all deployment tasks in one place so the main project
    only needs to call two public methods:
        * setup_environment()
        * install_autostart()
    """
    def __init__(
        self,
        service_name: str,
        script_path: str,
        requirements_file: str = "requirements.txt",
        python_exec: str = sys.executable,
    ):
        self.service_name = service_name
        self.script_path = Path(script_path).resolve()
        self.requirements_file = Path(requirements_file).resolve()
        self.python_exec = python_exec
        self.current_os = platform.system().lower()   # 'linux', 'windows', 'darwin'

    # ------------------------------------------------------------------ #
    # Public interface                                                   #
    # ------------------------------------------------------------------ #

    def setup_environment(self) -> None:
        """Install pip requirements and any OS-specific packages."""
        if self.requirements_file.exists():
            _run(f"{shlex.quote(self.python_exec)} -m pip install -r {shlex.quote(str(self.requirements_file))}")
        else:
            print("[deploy] ⚠ requirements.txt not found – skipping pip install.")

        if self.current_os == "linux":
            self._install_linux_dependencies()
        elif self.current_os == "windows":
            self._install_windows_dependencies()
        elif self.current_os == "darwin":
            self._install_macos_dependencies()
        else:
            print(f"[deploy] ⚠ Unsupported OS: {self.current_os}")

    def install_autostart(self, user: Optional[str] = None) -> None:
        """Create a boot-time service/agent/cron entry."""
        if self.current_os == "linux":
            if self._has_systemd():
                self._create_systemd_service(user)
            else:
                self._create_cron_reboot_entry()
        elif self.current_os == "windows":
            self._create_windows_task()
        elif self.current_os == "darwin":
            self._create_launchd_agent()
        else:
            raise RuntimeError(f"Unsupported OS: {self.current_os}")

    # ------------------------------------------------------------------ #
    # Dependency install methods                                         #
    # ------------------------------------------------------------------ #

    def _install_linux_dependencies(self):
        # Example: iptables for blocking, build tools for python libs
        if not _is_root():
            print("[deploy] ⚠ Need root to install OS packages (skipping).")
            return
        _run("apt-get update -qq")
        _run("apt-get install -y --no-install-recommends iptables")

    def _install_windows_dependencies(self):
        # Nothing mandatory: pip modules already installed above.
        pass

    def _install_macos_dependencies(self):
        # Example: ensure iptables-like tool (pf) is enabled – macOS bundles pfctl
        pass

    # ------------------------------------------------------------------ #
    # Service creation helpers                                           #
    # ------------------------------------------------------------------ #

    # ---------- Linux: systemd ---------------------------------------- #

    def _has_systemd(self) -> bool:
        return Path("/bin/systemctl").exists() or Path("/usr/bin/systemctl").exists()

    def _create_systemd_service(self, user: Optional[str]):
        if not _is_root():
            raise PermissionError("Root privileges are required to create systemd services.")

        unit_file = f"""/etc/systemd/system/{self.service_name}.service"""
        exec_cmd = f"{shlex.quote(self.python_exec)} {shlex.quote(str(self.script_path))}"
        unit_contents = f"""[Unit]
Description=🔥 {self.service_name} Firewall
After=network.target

[Service]
Type=simple
ExecStart={exec_cmd}
Restart=always
RestartSec=5
User={user or 'root'}
WorkingDirectory={shlex.quote(str(self.script_path.parent))}

[Install]
WantedBy=multi-user.target
"""
        print(f"[deploy] Writing systemd unit: {unit_file}")
        Path(unit_file).write_text(unit_contents)
        _run("systemctl daemon-reload")
        _run(f"systemctl enable {self.service_name}")
        _run(f"systemctl start {self.service_name}")
        print("[deploy] ✅ systemd service installed & started.")

    # ---------- Linux: cron fallback ---------------------------------- #

    def _create_cron_reboot_entry(self):
        cron_line = f"@reboot {shlex.quote(self.python_exec)} {shlex.quote(str(self.script_path))} >> /var/log/{self.service_name}.log 2>&1"
        # Append if not already present
        result = _run("crontab -l", check=False, capture=True)
        existing = result.stdout.splitlines() if result.stdout else []
        if cron_line not in existing:
            (result.stdout and print("[deploy] Existing crontab:\n", result.stdout))
            new_crontab = "\n".join(existing + [cron_line])
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
            proc.communicate(new_crontab.encode())
            print("[deploy] ✅ @reboot cron job added.")
        else:
            print("[deploy] ℹ cron job already present – skipping.")

    # ---------- Windows: Scheduled Task ------------------------------- #

    def _create_windows_task(self):
        if not _is_root():
            raise PermissionError("Administrator privileges required to create scheduled task.")
        task_cmd = (
            f'schtasks /Create /SC ONSTART /RL HIGHEST /TN "{self.service_name}" '
            f'/TR "{self.python_exec} {self.script_path}" /F'
        )
        _run(task_cmd)
        print("[deploy] ✅ Windows Scheduled Task created.")

    # ---------- macOS: launchd agent ---------------------------------- #

    def _create_launchd_agent(self):
        plist_dir = Path.home() / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / f"com.{self.service_name}.plist"
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key> <string>com.{self.service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.python_exec}</string>
        <string>{self.script_path}</string>
    </array>
    <key>RunAtLoad</key> <true/>
    <key>KeepAlive</key> <true/>
    <key>StandardOutPath</key> <string>/tmp/{self.service_name}.out</string>
    <key>StandardErrorPath</key> <string>/tmp/{self.service_name}.err</string>
</dict>
</plist>
"""
        plist_path.write_text(plist_content)
        _run(f"launchctl unload {plist_path}", check=False)  # ignore if not loaded yet
        _run(f"launchctl load {plist_path}")
        print(f"[deploy] ✅ launchd agent loaded: {plist_path}")

    # ------------------------------------------------------------------ #
    # Process daemonisation (optional)                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def fork_detach():
        """
        Double-fork magic to detach from controlling terminal on POSIX.
        Call only if you need to run the script as a background process
        *without* systemd/cron/launchd.
        """
        if os.name != "posix":
            print("[deploy] fork_detach() skipped – not POSIX.")
            return
        if os.fork() > 0:
            sys.exit(0)                # first parent exits
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)                # second parent exits
        sys.stdout.flush()
        sys.stderr.flush()
        # redirect stdio to /dev/null
        with open('/dev/null', 'wb', 0) as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
            os.dup2(devnull.fileno(), sys.stdout.fileno())
            os.dup2(devnull.fileno(), sys.stderr.fileno())
        print("[deploy] 🔒 detached daemon running (PID {})".format(os.getpid()))
