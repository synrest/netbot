"""User-local macOS launchd lifecycle for Netbot services."""
from __future__ import annotations

import os
import plistlib
import re
import subprocess
from pathlib import Path

LABEL = "com.netbot.watch"


def plist_path() -> Path:
    return Path(__file__).parents[1] / "launchd" / "com.netbot.watch.plist"


def domain() -> str:
    return f"gui/{os.getuid()}"


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], text=True,
                          capture_output=True, check=False)


def start() -> dict:
    result = launchctl("bootstrap", domain(), str(plist_path()))
    return {"action": "start", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def stop() -> dict:
    result = launchctl("bootout", f"{domain()}/{LABEL}")
    return {"action": "stop", "ok": result.returncode == 0,
            "stdout": result.stdout, "stderr": result.stderr}


def restart() -> dict:
    stopped = stop()
    if not stopped["ok"] and "Could not find service" not in stopped["stderr"]:
        return {"action": "restart", "ok": False, "stop": stopped}
    started = start()
    return {"action": "restart", "ok": started["ok"],
            "stop": stopped, "start": started}


def status() -> dict:
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


def validate_plist() -> dict:
    with plist_path().open("rb") as stream:
        plist = plistlib.load(stream)
    return {"label": plist.get("Label"), "plist": plist}
