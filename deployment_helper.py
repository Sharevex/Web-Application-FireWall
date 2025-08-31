#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deployment_helper.py
--------------------
Make your app production-ready on Linux/Windows/macOS:
- Install Python deps (and optional OS packages).
- Register the app as an auto-start background service.
- Provide uninstall & daemonize helpers.

Usage:
    from deployment_helper import DeploymentHelper
    import sys

    helper = DeploymentHelper(
        service_name="firewall",
        script_path="/opt/firewall/firewall.py",           # absolute path!
        requirements_file="/opt/firewall/requirements.txt",
        python_exec=sys.executable,                        # or venv python
        env_vars={"APP_SECRET_KEY": "changeme"},           # injected into service
        linux_extra_packages=["iptables"],                 # extra apt packages
        log_to_file=False                                  # Linux: use journald
    )
    helper.setup_environment()
    helper.install_autostart(user="root")                 # root recommended for iptables
"""

from __future__ import annotations

import os
import sys
import shlex
import stat
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

class CommandError(RuntimeError):
    def __init__(self, cmd: str, code: int, output: str):
        super().__init__(f"Command failed ({code}): {cmd}\n{output}")
        self.cmd = cmd
        self.code = code
        self.output = output


def _run(cmd: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the completed process; raise rich error if failed."""
    print(f"[deploy] ⇒ {cmd}")
    proc = subprocess.run(
        cmd,
        shell=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if check and proc.returncode != 0:
        output = proc.stdout or ""
        raise CommandError(cmd, proc.returncode, output)
    return proc


def _is_root() -> bool:
    if os.name == "nt":
        try:
            import ctypes  # type: ignore
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _ensure_abs(path: Path) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_absolute():
        raise ValueError(f"Expected absolute path, got: {p}")
    return p


# ---------------------------------------------------------------------------
# Main helper
# ---------------------------------------------------------------------------

@dataclass
class DeploymentHelper:
    service_name: str
    script_path: str
    requirements_file: Optional[str] = "requirements.txt"
    python_exec: str = sys.executable
    env_vars: Dict[str, str] = field(default_factory=dict)
    linux_extra_packages: Iterable[str] = field(default_factory=lambda: ["iptables"])
    log_to_file: bool = False  # Linux: if True, log to /var/log/<service>.log; else use journald

    def __post_init__(self):
        self.script_path = str(_ensure_abs(Path(self.script_path)))
        if self.requirements_file:
            self.requirements_file = str(Path(self.requirements_file).expanduser().resolve())
        self.python_exec = str(Path(self.python_exec).expanduser().resolve())
        self.current_os = platform.system().lower()  # 'linux', 'windows', 'darwin'
        self.work_dir = str(Path(self.script_path).parent)

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def setup_environment(self) -> None:
        """Install pip requirements + minimal OS deps."""
        if self.requirements_file and Path(self.requirements_file).exists():
            _run(f"{shlex.quote(self.python_exec)} -m pip install -r {shlex.quote(self.requirements_file)}")
        else:
            print("[deploy] ℹ requirements.txt not found – skipping pip install.")

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
                self._create_systemd_service(user=user or "root")
            else:
                self._create_cron_reboot_entry()
        elif self.current_os == "windows":
            self._create_windows_task()
        elif self.current_os == "darwin":
            self._create_launchd_agent()
        else:
            raise RuntimeError(f"Unsupported OS: {self.current_os}")

    def uninstall_autostart(self) -> None:
        """Remove the service/agent/task created by install_autostart()."""
        if self.current_os == "linux":
            if self._has_systemd():
                self._remove_systemd_service()
            else:
                self._remove_cron_reboot_entry()
        elif self.current_os == "windows":
            self._remove_windows_task()
        elif self.current_os == "darwin":
            self._remove_launchd_agent()
        else:
            raise RuntimeError(f"Unsupported OS: {self.current_os}")

    # ------------------------------------------------------------------ #
    # Dependencies                                                       #
    # ------------------------------------------------------------------ #

    def _install_linux_dependencies(self) -> None:
        if not _is_root():
            print("[deploy] ⚠ Need root to install Linux packages – skipped.")
            return
        pkgs = " ".join(shlex.quote(p) for p in self.linux_extra_packages)
        if pkgs:
            _run("apt-get update -qq || true", check=False)
            _run(f"apt-get install -y --no-install-recommends {pkgs}")

    def _install_windows_dependencies(self) -> None:
        # Nothing mandatory beyond pip deps; hook for future.
        pass

    def _install_macos_dependencies(self) -> None:
        # macOS bundles pfctl; nothing extra by default.
        pass

    # ------------------------------------------------------------------ #
    # Linux - systemd / cron                                             #
    # ------------------------------------------------------------------ #

    def _has_systemd(self) -> bool:
        return Path("/run/systemd/system").exists() or Path("/bin/systemctl").exists()

    def _env_lines_systemd(self) -> str:
        # Use Environment= lines (small sets); for lots of env use EnvironmentFile.
        lines = []
        for k, v in self.env_vars.items():
            lines.append(f'Environment="{k}={v}"')
        return "\n".join(lines)

    def _create_systemd_service(self, user: str = "root") -> None:
        if not _is_root():
            raise PermissionError("Root privileges are required to create systemd services.")

        unit_path = Path(f"/etc/systemd/system/{self.service_name}.service")
        exec_cmd = f"{shlex.quote(self.python_exec)} {shlex.quote(self.script_path)}"
        env_block = self._env_lines_systemd()
        log_block = ""
        if self.log_to_file:
            log_path = f"/var/log/{self.service_name}.log"
            Path("/var/log").mkdir(parents=True, exist_ok=True)
            log_block = f"\nStandardOutput=append:{log_path}\nStandardError=append:{log_path}\n"

        unit = f"""[Unit]
Description={self.service_name} service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={shlex.quote(self.work_dir)}
ExecStart={exec_cmd}
Restart=always
RestartSec=3
{env_block}
# LimitNOFILE=65536
{log_block}[Install]
WantedBy=multi-user.target
"""
        print(f"[deploy] Writing systemd unit: {unit_path}")
        unit_path.write_text(unit)
        _run("systemctl daemon-reload")
        _run(f"systemctl enable {shlex.quote(self.service_name)}")
        _run(f"systemctl restart {shlex.quote(self.service_name)}")
        print("[deploy] ✅ systemd service installed & started.")

    def _remove_systemd_service(self) -> None:
        if not _is_root():
            raise PermissionError("Root privileges are required to remove systemd services.")
        _run(f"systemctl disable --now {shlex.quote(self.service_name)}", check=False)
        unit_path = Path(f"/etc/systemd/system/{self.service_name}.service")
        if unit_path.exists():
            unit_path.unlink()
            _run("systemctl daemon-reload")
        print("[deploy] ✅ systemd service removed.")

    def _create_cron_reboot_entry(self) -> None:
        cron_line = (
            f"@reboot cd {shlex.quote(self.work_dir)} && "
            f"{shlex.quote(self.python_exec)} {shlex.quote(self.script_path)}"
        )
        if self.env_vars:
            env_inline = " ".join(f'{k}={shlex.quote(v)}' for k, v in self.env_vars.items())
            cron_line = f"@reboot {env_inline} {cron_line[len('@reboot '):]}"

        existing = _run("crontab -l", check=False).stdout or ""
        lines = [ln for ln in existing.splitlines() if ln.strip()]
        if cron_line not in lines:
            lines.append(cron_line)
            new_cron = "\n".join(lines) + "\n"
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
            proc.communicate(new_cron)
            print("[deploy] ✅ @reboot cron job added.")
        else:
            print("[deploy] ℹ cron job already present – skipping.")

    def _remove_cron_reboot_entry(self) -> None:
        existing = _run("crontab -l", check=False).stdout or ""
        lines = [ln for ln in existing.splitlines() if ln.strip()]
        new_lines = [ln for ln in lines if self.service_name not in ln or self.script_path not in ln]
        if new_lines != lines:
            new_cron = "\n".join(new_lines) + "\n"
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
            proc.communicate(new_cron)
            print("[deploy] ✅ @reboot cron job removed.")
        else:
            print("[deploy] ℹ no matching cron entry found – skipping.")

    # ------------------------------------------------------------------ #
    # Windows - Scheduled Task                                           #
    # ------------------------------------------------------------------ #

    def _create_windows_task(self) -> None:
        if not _is_root():
            raise PermissionError("Administrator privileges required to create a Scheduled Task.")

        _run(f'schtasks /Delete /TN "{self.service_name}" /F', check=False)

        task_cmd = self._windows_task_command_line()
        _run(
            f'schtasks /Create /SC ONSTART /RL HIGHEST /TN "{self.service_name}" '
            f'/TR "{task_cmd}" /F'
        )
        print("[deploy] ✅ Windows Scheduled Task created.")

    def _windows_task_command_line(self) -> str:
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        wrapper = Path(program_data) / f"{self.service_name}_launch.cmd"
        lines = ["@echo off"]
        for k, v in self.env_vars.items():
            lines.append(f"set {k}={v}")
        lines.append(f'"{self.python_exec}" "{self.script_path}"')
        wrapper.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        except Exception:
            pass
        return str(wrapper)

    def _remove_windows_task(self) -> None:
        _run(f'schtasks /Delete /TN "{self.service_name}" /F', check=False)
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        wrapper = Path(program_data) / f"{self.service_name}_launch.cmd"
        if wrapper.exists():
            wrapper.unlink()
        print("[deploy] ✅ Windows Scheduled Task removed.")

    # ------------------------------------------------------------------ #
    # macOS - launchd                                                    #
    # ------------------------------------------------------------------ #

    def _plist_path(self) -> Path:
        return Path.home() / "Library" / "LaunchAgents" / f"com.{self.service_name}.plist"

    def _create_launchd_agent(self) -> None:
        plist_dir = self._plist_path().parent
        plist_dir.mkdir(parents=True, exist_ok=True)

        program_args = [self.python_exec, self.script_path]
        plist = _to_plist({
            "Label": f"com.{self.service_name}",
            "ProgramArguments": program_args,
            "RunAtLoad": True,
            "KeepAlive": True,
            "WorkingDirectory": self.work_dir,
            "StandardOutPath": f"/tmp/{self.service_name}.out",
            "StandardErrorPath": f"/tmp/{self.service_name}.err",
            "EnvironmentVariables": self.env_vars or {},
        })
        self._plist_path().write_text(plist, encoding="utf-8")

        _run(f"launchctl unload {shlex.quote(str(self._plist_path()))}", check=False)
        _run(f"launchctl load {shlex.quote(str(self._plist_path()))}")
        print(f"[deploy] ✅ launchd agent loaded: {self._plist_path()}")

    def _remove_launchd_agent(self) -> None:
        _run(f"launchctl unload {shlex.quote(str(self._plist_path()))}", check=False)
        if self._plist_path().exists():
            self._plist_path().unlink()
        print(f"[deploy] ✅ launchd agent removed: {self._plist_path()}")

    # ------------------------------------------------------------------ #
    # Optional POSIX daemonization                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def fork_detach() -> None:
        """Double-fork to detach on POSIX (use only if you *don’t* use systemd/cron/launchd)."""
        if os.name != "posix":
            print("[deploy] fork_detach() skipped – not POSIX.")
            return
        if os.fork() > 0:
            os._exit(0)
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        with open("/dev/null", "rb", 0) as devnull_in, \
             open("/dev/null", "ab", 0) as devnull_out:
            os.dup2(devnull_in.fileno(), 0)
            os.dup2(devnull_out.fileno(), 1)
            os.dup2(devnull_out.fileno(), 2)
        print(f"[deploy] 🔒 detached daemon PID={os.getpid()}")


# ---------------------------------------------------------------------------
# Minimal PLIST writer (no external deps)
# ---------------------------------------------------------------------------

def _to_plist(d: dict) -> str:
    """Very small, safe plist generator for the keys we use."""
    def esc(s: str) -> str:
        return (s
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
    def el(key: str, val) -> str:
        if isinstance(val, bool):
            return f"<key>{esc(key)}</key>\n<{str(val).lower()}/>"
        if isinstance(val, (int, float)):
            return f"<key>{esc(key)}</key>\n<integer>{val}</integer>"
        if isinstance(val, str):
            return f"<key>{esc(key)}</key>\n<string>{esc(val)}</string>"
        if isinstance(val, list):
            items = "\n".join(f"<string>{esc(str(x))}</string>" for x in val)
            return f"<key>{esc(key)}</key>\n<array>\n{items}\n</array>"
        if isinstance(val, dict):
            items = "\n".join(el(k, v) for k, v in val.items())
            return f"<key>{esc(key)}</key>\n<dict>\n{items}\n</dict>"
        return f"<key>{esc(key)}</key>\n<string>{esc(str(val))}</string>"
    body = "\n".join(el(k, v) for k, v in d.items())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
{body}
</dict>
</plist>
"""
# ---------------------------------------------------------------------------
# Simple CLI for quick usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    def parse_env_kv(pairs):
        env = {}
        for item in pairs or []:
            if "=" not in item:
                raise argparse.ArgumentTypeError(f"--env expects KEY=VALUE, got: {item}")
            k, v = item.split("=", 1)
            env[k] = v
        return env

    parser = argparse.ArgumentParser(
        description="Deploy your app as a service (systemd/cron/launchd/Scheduled Task)."
    )
    parser.add_argument("--service-name", required=True,
                        help="Service/Task/Agent name, e.g. firewall")
    parser.add_argument("--script-path", required=True,
                        help="Absolute path to your entrypoint script, e.g. /opt/firewall/firewall.py")
    parser.add_argument("--requirements-file", default="requirements.txt",
                        help="Path to requirements.txt (optional)")
    parser.add_argument("--python-exec", default=sys.executable,
                        help="Python executable to use (default: current)")
    parser.add_argument("--env", action="append", default=[],
                        help="Environment var to inject (repeatable): KEY=VALUE")
    parser.add_argument("--env-json", default=None,
                        help="Path to JSON file with environment vars to inject")
    parser.add_argument("--linux-extra-packages", nargs="*", default=["iptables"],
                        help="Extra apt packages to install on Linux (default: iptables)")
    parser.add_argument("--log-to-file", action="store_true",
                        help="On Linux, log to /var/log/<service>.log instead of journald")

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="Install Python deps and OS packages")
    sub.add_parser("install", help="Install and start autostart service/agent")
    sub.add_parser("uninstall", help="Remove autostart service/agent")
    sub.add_parser("restart", help="Restart service (Linux systemd only)")
    sub.add_parser("status", help="Show service status (Linux systemd only)")
    sub.add_parser("logs", help="Tail service logs (Linux systemd only)")
    sub.add_parser("run", help="Run the app in foreground (no service)")

    args = parser.parse_args()

    # Merge env from --env-json (if provided) and --env KEY=VALUE
    env_vars = {}
    if args.env_json:
        with open(args.env_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise SystemExit("--env-json must contain a JSON object of key/value pairs")
            env_vars.update({str(k): str(v) for k, v in loaded.items()})
    env_vars.update(parse_env_kv(args.env))

    helper = DeploymentHelper(
        service_name=args.service_name,
        script_path=args.script_path,
        requirements_file=args.requirements_file,
        python_exec=args.python_exec,
        env_vars=env_vars,
        linux_extra_packages=args.linux_extra_packages,
        log_to_file=args.log_to_file,
    )

    try:
        if args.cmd == "setup":
            helper.setup_environment()

        elif args.cmd == "install":
            helper.setup_environment()
            # On Linux, root is recommended (iptables, systemd)
            helper.install_autostart(user="root" if helper.current_os == "linux" else None)

        elif args.cmd == "uninstall":
            helper.uninstall_autostart()

        elif args.cmd == "restart":
            if helper.current_os != "linux":
                raise SystemExit("restart is only supported on Linux systemd")
            _run(f"systemctl restart {shlex.quote(helper.service_name)}")

        elif args.cmd == "status":
            if helper.current_os != "linux":
                raise SystemExit("status is only supported on Linux systemd")
            _run(f"systemctl status {shlex.quote(helper.service_name)}", check=False, capture=False)

        elif args.cmd == "logs":
            if helper.current_os != "linux":
                raise SystemExit("logs is only supported on Linux systemd")
            _run(f"journalctl -u {shlex.quote(helper.service_name)} -n 200 -f", check=False, capture=False)

        elif args.cmd == "run":
            # Run the script in the foreground using the chosen python
            cmd = f"{shlex.quote(helper.python_exec)} {shlex.quote(helper.script_path)}"
            # Inherit current env + injected env_vars
            env = os.environ.copy()
            env.update(helper.env_vars)
            print(f"[deploy] ⇒ {cmd}")
            os.execvpe(helper.python_exec, [helper.python_exec, helper.script_path], env)

    except CommandError as ce:
        print(str(ce))
        sys.exit(ce.code)
    except Exception as e:
        print(f"[deploy] ERROR: {e}")
        sys.exit(1)
