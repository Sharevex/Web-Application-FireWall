#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deployment_helper.py
- Installs pip deps
- Creates system service with EnvironmentFile (no secrets in unit)
- Cross-OS (systemd/cron/launchd/Scheduled Tasks)

Env file path: /etc/<service>.env (auto-written if env_vars passed)
"""

from __future__ import annotations
import os, sys, shlex, stat, platform, subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional

class CommandError(RuntimeError):
    def __init__(self, cmd: str, code: int, output: str):
        super().__init__(f"Command failed ({code}): {cmd}\n{output}")
        self.cmd, self.code, self.output = cmd, code, output

def _run(cmd: str, check=True, capture=True):
    print(f"[deploy] ⇒ {cmd}")
    p = subprocess.run(cmd, shell=True, text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    if check and p.returncode != 0:
        raise CommandError(cmd, p.returncode, p.stdout or "")
    return p

def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0

def _ensure_abs(p: Path) -> Path:
    q = Path(p).expanduser().resolve()
    if not q.is_absolute():
        raise ValueError(f"Expected absolute path: {q}")
    return q

@dataclass
class DeploymentHelper:
    service_name: str
    script_path: str
    requirements_file: Optional[str] = "requirements.txt"
    python_exec: str = sys.executable
    env_vars: Dict[str, str] = field(default_factory=dict)
    linux_extra_packages: Iterable[str] = field(default_factory=lambda: ["iptables", "nftables", "ipset"])
    log_to_file: bool = False

    def __post_init__(self):
        self.script_path = str(_ensure_abs(Path(self.script_path)))
        self.requirements_file = str(Path(self.requirements_file).expanduser().resolve()) if self.requirements_file else None
        self.python_exec = str(Path(self.python_exec).expanduser().resolve())
        self.current_os = platform.system().lower()
        self.work_dir = str(Path(self.script_path).parent)
        self.env_file = Path(f"/etc/{self.service_name}.env")

    def setup_environment(self):
        if self.requirements_file and Path(self.requirements_file).exists():
            _run(f"{shlex.quote(self.python_exec)} -m pip install -r {shlex.quote(self.requirements_file)}")
        else:
            print("[deploy] no requirements.txt found; skipping pip install")
        if self.current_os == "linux" and _is_root():
            pkgs = " ".join(shlex.quote(p) for p in self.linux_extra_packages)
            if pkgs:
                _run("apt-get update -qq || true", check=False)
                _run(f"apt-get install -y --no-install-recommends {pkgs}", check=False)
        # Write env file if env_vars provided (Linux only)
        if self.env_vars and self.current_os == "linux":
            content = "\n".join(f"{k}={v}" for k, v in self.env_vars.items()) + "\n"
            self.env_file.write_text(content, encoding="utf-8")
            os.chmod(self.env_file, 0o600)
            print(f"[deploy] wrote {self.env_file}")

    def install_autostart(self, user: Optional[str] = None):
        if self.current_os == "linux":
            if self._has_systemd():
                self._create_systemd_service(user or "root")
            else:
                self._create_cron_reboot_entry()
        elif self.current_os == "windows":
            self._create_windows_task()
        elif self.current_os == "darwin":
            self._create_launchd_agent()
        else:
            raise RuntimeError(f"unsupported OS: {self.current_os}")

    def uninstall_autostart(self):
        if self.current_os == "linux":
            if self._has_systemd():
                self._remove_systemd_service()
            else:
                self._remove_cron_reboot_entry()
        elif self.current_os == "windows":
            self._remove_windows_task()
        elif self.current_os == "darwin":
            self._remove_launchd_agent()

    # -------- Linux --------
    def _has_systemd(self) -> bool:
        return Path("/run/systemd/system").exists() or Path("/bin/systemctl").exists()

    def _create_systemd_service(self, user: str):
        if not _is_root():
            raise PermissionError("root required for systemd unit")
        unit_path = Path(f"/etc/systemd/system/{self.service_name}.service")
        exec_cmd = f"{self.python_exec} {self.script_path}"

        log_block = ""
        if self.log_to_file:
            log_path = f"/var/log/{self.service_name}.log"
            Path("/var/log").mkdir(parents=True, exist_ok=True)
            log_block = f"\nStandardOutput=append:{log_path}\nStandardError=append:{log_path}"

        env_line = f"EnvironmentFile={self.env_file}" if self.env_file.exists() else ""
        unit = f"""[Unit]
Description={self.service_name} service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={self.work_dir}
{env_line}
ExecStart={exec_cmd}
Restart=always
RestartSec=3{log_block}

[Install]
WantedBy=multi-user.target
"""
        unit_path.write_text(unit)
        try:
            _run("systemctl daemon-reload")
            _run(f"systemctl enable {shlex.quote(self.service_name)}")
            _run(f"systemctl restart {shlex.quote(self.service_name)}")
            print("[deploy] systemd service installed & started")
        except Exception as e:
            print("[deploy] ERROR installing service:", e)
            if unit_path.exists():
                unit_path.unlink()
                _run("systemctl daemon-reload", check=False)

    def _remove_systemd_service(self):
        if not _is_root():
            raise PermissionError("root required")
        _run(f"systemctl disable --now {shlex.quote(self.service_name)}", check=False)
        p = Path(f"/etc/systemd/system/{self.service_name}.service")
        if p.exists():
            p.unlink()
            _run("systemctl daemon-reload", check=False)
        if self.env_file.exists():
            self.env_file.unlink()
        print("[deploy] systemd service removed")

    def _create_cron_reboot_entry(self):
        cron_line = f"@reboot cd {shlex.quote(self.work_dir)} && {shlex.quote(self.python_exec)} {shlex.quote(self.script_path)}"
        env_prefix = ""
        if self.env_vars:
            env_prefix = " ".join(f'{k}={shlex.quote(v)}' for k, v in self.env_vars.items()) + " "
        existing = _run("crontab -l", check=False).stdout or ""
        lines = [ln for ln in existing.splitlines() if ln.strip()]
        if env_prefix + cron_line not in lines:
            lines.append(env_prefix + cron_line)
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
            proc.communicate("\n".join(lines) + "\n")
            print("[deploy] @reboot cron added")
        else:
            print("[deploy] cron already present")

    # -------- Windows / macOS (unchanged essentials) --------
    def _create_windows_task(self):
        raise NotImplementedError("Windows task creation omitted for brevity")

    def _remove_windows_task(self):
        pass

    def _create_launchd_agent(self):
        raise NotImplementedError("macOS launchd creation omitted for brevity")

    def _remove_launchd_agent(self):
        pass

if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--service-name", required=True)
    ap.add_argument("--script-path", required=True)
    ap.add_argument("--requirements-file", default="requirements.txt")
    ap.add_argument("--python-exec", default=sys.executable)
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("--env-json", default=None)
    ap.add_argument("--log-to-file", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    sub.add_parser("install")
    sub.add_parser("uninstall")
    args = ap.parse_args()

    env_vars = {}
    if args.env_json:
        env_vars.update(json.load(open(args.env_json)))
    for kv in args.env:
        k, v = kv.split("=", 1)
        env_vars[k] = v

    helper = DeploymentHelper(
        service_name=args.service_name,
        script_path=args.script_path,
        requirements_file=args.requirements_file,
        python_exec=args.python_exec,
        env_vars=env_vars,
        log_to_file=args.log_to_file,
    )
    if args.cmd == "setup":
        helper.setup_environment()
    elif args.cmd == "install":
        helper.setup_environment()
        helper.install_autostart(user="root")
    elif args.cmd == "uninstall":
        helper.uninstall_autostart()
