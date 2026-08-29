"""User-local macOS launchd lifecycle for Netbot services."""
from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

LABEL = "com.netbot.watch"
SYSTEMD_UNIT = "netbot-watch.service"
OPENRC_SERVICE = "netbot-watch"


def detect_backend() -> str:
    """Detect an actually available supervisor, without distro assumptions."""
    if sys.platform == "darwin" and shutil.which("launchctl"):
        return "launchd"
    if sys.platform == "linux":
        systemctl = shutil.which("systemctl")
        if systemctl and (Path("/run/systemd/system").exists() or
                          subprocess.run([systemctl, "--user", "show-environment"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         check=False).returncode == 0):
            return "systemd"
        if shutil.which("rc-service") and (shutil.which("openrc-run") or Path("/sbin/openrc").exists()):
            return "openrc"
    return "unsupported"


def plist_path() -> Path:
    prefix = os.environ.get("NETBOT_PREFIX")
    if prefix:
        return Path(prefix).expanduser() / "current" / "launchd" / "com.netbot.watch.plist"
    installed = Path.home() / "Library" / "Application Support" / "Netbot" / "current" / "launchd" / "com.netbot.watch.plist"
    if installed.is_file():
        return installed
    return Path(__file__).parents[1] / "launchd" / "com.netbot.watch.plist"


def domain() -> str:
    return f"gui/{os.getuid()}"


def service_marker() -> Path:
    prefix = os.environ.get("NETBOT_PREFIX")
    root = Path(prefix).expanduser() if prefix else Path.home() / "Library" / "Application Support" / "Netbot"
    return root / "service.loaded"


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], text=True,
                          capture_output=True, check=False)


def _launchd_start() -> dict:
    result = launchctl("bootstrap", domain(), str(plist_path()))
    if result.returncode == 0:
        service_marker().parent.mkdir(parents=True, exist_ok=True)
        service_marker().touch()
    return {"action": "start", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def _launchd_stop() -> dict:
    result = launchctl("bootout", f"{domain()}/{LABEL}")
    if result.returncode == 0:
        service_marker().unlink(missing_ok=True)
    return {"action": "stop", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def _launchd_restart() -> dict:
    stopped = _launchd_stop()
    if not stopped["ok"] and "Could not find service" not in stopped["stderr"]:
        return {"action": "restart", "ok": False, "stop": stopped}
    started = _launchd_start()
    return {"action": "restart", "ok": started["ok"],
            "stop": stopped, "start": started}


def _launchd_status() -> dict:
    if os.environ.get("NETBOT_PREFIX") and not service_marker().is_file():
        return {"action": "status", "loaded": False, "running": False,
                "watcher": False, "pid": None, "command": "",
                "stdout": "", "stderr": "service not installed for this prefix"}
    if not plist_path().is_file():
        return {"action": "status", "loaded": False, "running": False,
                "watcher": False, "pid": None, "command": "",
                "stdout": "", "stderr": "installed watcher plist is absent"}
    result = launchctl("print", f"{domain()}/{LABEL}")
    text = result.stdout + result.stderr
    pid = re.search(r"\n\s*pid = (\d+)", text)
    process_id = int(pid.group(1)) if pid else None
    command = ""
    if process_id is not None:
        process = subprocess.run(["ps", "-p", str(process_id), "-o", "command="],
                                 text=True, capture_output=True, check=False)
        command = process.stdout.strip()
    return {"action": "status", "loaded": result.returncode == 0,
            "running": bool(pid), "watcher": "netbot.watcher" in command,
            "pid": process_id, "command": command,
            "stdout": result.stdout, "stderr": result.stderr}


def systemd_unit_path() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd" / "user" / SYSTEMD_UNIT


def _systemd(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", "--user", *args], text=True,
                          capture_output=True, check=False)


def _systemd_status() -> dict:
    if not systemd_unit_path().is_file():
        return {"action": "status", "backend": "systemd", "loaded": False,
                "running": False, "watcher": False, "pid": None,
                "stdout": "", "stderr": "unit is not installed"}
    result = _systemd("show", SYSTEMD_UNIT, "--property=LoadState,ActiveState,MainPID", "--no-pager")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    pid = int(values.get("MainPID", "0") or 0)
    return {"action": "status", "backend": "systemd", "loaded": values.get("LoadState") == "loaded",
            "running": values.get("ActiveState") == "active", "watcher": pid > 0,
            "pid": pid or None, "stdout": result.stdout, "stderr": result.stderr}


def _systemd_start() -> dict:
    reload_result = _systemd("daemon-reload")
    if reload_result.returncode:
        return {"action": "start", "backend": "systemd", "ok": False, "stderr": reload_result.stderr}
    result = _systemd("enable", "--now", SYSTEMD_UNIT)
    return {"action": "start", "backend": "systemd", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def _systemd_stop() -> dict:
    result = _systemd("disable", "--now", SYSTEMD_UNIT)
    return {"action": "stop", "backend": "systemd", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def _systemd_restart() -> dict:
    result = _systemd("restart", SYSTEMD_UNIT)
    return {"action": "restart", "backend": "systemd", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def _openrc_status() -> dict:
    installed = Path("/etc/init.d") / OPENRC_SERVICE
    if not installed.is_file():
        return {"action": "status", "backend": "openrc", "installed": False,
                "loaded": False, "running": False, "watcher": False,
                "pid": None, "stdout": "", "stderr": "root installation required"}
    result = subprocess.run(["rc-service", OPENRC_SERVICE, "status"], text=True,
                            capture_output=True, check=False)
    return {"action": "status", "backend": "openrc", "installed": True,
            "loaded": True, "running": result.returncode == 0,
            "watcher": result.returncode == 0, "pid": None,
            "stdout": result.stdout, "stderr": result.stderr}


def _openrc_action(action: str) -> dict:
    installed = Path("/etc/init.d") / OPENRC_SERVICE
    if not installed.is_file():
        return {"action": action, "backend": "openrc", "ok": False,
                "stderr": "OpenRC service is not installed; explicit root installation is required"}
    result = subprocess.run(["rc-service", OPENRC_SERVICE, action], text=True,
                            capture_output=True, check=False)
    return {"action": action, "backend": "openrc", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def start() -> dict:
    backend = detect_backend()
    if backend == "launchd": return _launchd_start()
    if backend == "systemd": return _systemd_start()
    if backend == "openrc": return _openrc_action("start")
    return {"action": "start", "backend": backend, "ok": False, "stderr": "unsupported supervisor"}


def stop() -> dict:
    backend = detect_backend()
    if backend == "launchd": return _launchd_stop()
    if backend == "systemd": return _systemd_stop()
    if backend == "openrc": return _openrc_action("stop")
    return {"action": "stop", "backend": backend, "ok": False, "stderr": "unsupported supervisor"}


def restart() -> dict:
    backend = detect_backend()
    if backend == "launchd": return _launchd_restart()
    if backend == "systemd": return _systemd_restart()
    if backend == "openrc": return _openrc_action("restart")
    return {"action": "restart", "backend": backend, "ok": False, "stderr": "unsupported supervisor"}


def status() -> dict:
    backend = detect_backend()
    if backend == "launchd":
        result = _launchd_status()
    elif backend == "systemd":
        result = _systemd_status()
    elif backend == "openrc":
        result = _openrc_status()
    else:
        result = {"action": "status", "loaded": False, "running": False,
                  "watcher": False, "pid": None, "stdout": "",
                  "stderr": "unsupported supervisor"}
    result["backend"] = backend
    return result


def validate_plist() -> dict:
    with plist_path().open("rb") as stream:
        plist = plistlib.load(stream)
    return {"label": plist.get("Label"), "plist": plist}
