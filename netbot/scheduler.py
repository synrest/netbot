"""User-level native scheduler artifacts for the one-shot maintainer."""
from __future__ import annotations

import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

LABEL = "com.netbot.maintain"
SERVICE = "netbot-maintain.service"
TIMER = "netbot-maintain.timer"
MARKER = "# netbot-managed: scheduler-maintain"


def interval_seconds(value: str | int = "30m") -> int:
    if isinstance(value, int):
        seconds = value * 60
    else:
        text = str(value).strip().lower()
        if text.endswith("m"):
            seconds = int(text[:-1]) * 60
        elif text.endswith("h"):
            seconds = int(text[:-1]) * 3600
        else:
            seconds = int(text) * 60
    if seconds < 300:
        raise ValueError("scheduler interval must be at least 5 minutes")
    return seconds


def _home(home: Path | None = None) -> Path:
    return home or Path.home()


def paths(home: Path | None = None, *, platform_name: str | None = None) -> dict[str, Path]:
    home = _home(home)
    platform_name = platform_name or sys.platform
    if platform_name == "darwin":
        return {"plist": home / "Library" / "LaunchAgents" / f"{LABEL}.plist"}
    if platform_name == "linux":
        root = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) if home == Path.home() else home / ".config"
        return {"service": root / "systemd" / "user" / SERVICE,
                "timer": root / "systemd" / "user" / TIMER}
    return {}


def resolve_executable(executable: str | Path | None = None) -> list[str]:
    if executable:
        path = Path(executable)
        if not path.is_absolute():
            raise ValueError("scheduler executable must be absolute")
        return [str(path)]
    found = shutil.which("netbot")
    if found and Path(found).is_absolute():
        return [found]
    interpreter = Path(sys.executable).resolve()
    if not interpreter.is_absolute():
        raise ValueError("could not resolve an absolute Python executable")
    return [str(interpreter), "-m", "netbot.cli"]


def _atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise FileExistsError(f"unsafe scheduler artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)


def render(platform_name: str, executable: str | Path | None = None,
           interval: str | int = "30m", *, home: Path | None = None) -> dict[str, bytes]:
    seconds = interval_seconds(interval)
    command = resolve_executable(executable) + ["maintain"]
    if platform_name == "darwin":
        data = {"Label": LABEL, "ProgramArguments": command,
                "StartInterval": seconds, "RunAtLoad": True,
                "StandardOutPath": str(_home(home) / "Library" / "Logs" / "Netbot" / "maintain.log"),
                "StandardErrorPath": str(_home(home) / "Library" / "Logs" / "Netbot" / "maintain.err.log"),
                "NetbotManaged": True}
        return {"plist": plistlib.dumps(data, sort_keys=False)}
    if platform_name == "linux":
        exe = " ".join(command)
        service = f"{MARKER}\n[Unit]\nDescription=Netbot one-shot maintenance\n\n[Service]\nType=oneshot\nExecStart={exe}\n"
        timer = f"{MARKER}\n[Unit]\nDescription=Run Netbot maintenance periodically\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec={seconds}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
        return {"service": service.encode(), "timer": timer.encode()}
    raise ValueError(f"unsupported platform: {platform_name}")


def _owned(path: Path, data: bytes) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    return path.read_bytes() == data


def _marked(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    raw = path.read_bytes()
    return MARKER.encode() in raw or b"NetbotManaged" in raw


def _native(platform_name: str, action: str, paths_: dict[str, Path]) -> dict:
    if platform_name == "darwin":
        args = ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(paths_["plist"])] if action == "install" else ["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"]
    else:
        args = ["systemctl", "--user", "daemon-reload"] if action == "install" else ["systemctl", "--user", "disable", "--now", TIMER]
    first = subprocess.run(args, text=True, capture_output=True, check=False)
    if action == "install" and first.returncode == 0 and platform_name == "linux":
        first = subprocess.run(["systemctl", "--user", "enable", "--now", TIMER], text=True, capture_output=True, check=False)
    return {"action": action, "ok": first.returncode == 0, "stdout": first.stdout, "stderr": first.stderr}


def install(*, home: Path | None = None, platform_name: str | None = None,
            executable: str | Path | None = None, interval: str | int = "30m",
            dry_run: bool = False, native: bool = True) -> dict:
    platform_name = platform_name or sys.platform
    if platform_name not in {"darwin", "linux"}:
        return {"result": "UNSUPPORTED", "platform": platform_name}
    paths_ = paths(home, platform_name=platform_name)
    rendered = render(platform_name, executable, interval, home=home)
    already = all(_owned(paths_[key], data) for key, data in rendered.items())
    artifacts = {key: {"path": str(paths_[key]), "content": value.decode(errors="replace")}
                 for key, value in rendered.items()}
    for key, data in rendered.items():
        path = paths_[key]
        if (path.exists() or path.is_symlink()) and not _owned(path, data) and not _marked(path):
            return {"result": "CONFLICT", "platform": platform_name, "artifacts": artifacts}
    if dry_run:
        return {"result": "WOULD_INSTALL", "platform": platform_name, "artifacts": artifacts,
                "native_action": "load/enable"}
    if already:
        return {"result": "ALREADY_INSTALLED", "platform": platform_name,
                "artifacts": artifacts, "native": {"action": "unchanged", "ok": True}}
    for key, data in rendered.items():
        _atomic_write(paths_[key], data)
    native_result = _native(platform_name, "install", paths_) if native else {"ok": True, "action": "skipped"}
    return {"result": "INSTALLED",
            "platform": platform_name, "artifacts": artifacts, "native": native_result}


def remove(*, home: Path | None = None, platform_name: str | None = None,
           dry_run: bool = False, native: bool = True) -> dict:
    platform_name = platform_name or sys.platform
    if platform_name not in {"darwin", "linux"}:
        return {"result": "UNSUPPORTED", "platform": platform_name}
    paths_ = paths(home, platform_name=platform_name)
    rendered = render(platform_name, home=home)
    for key, data in rendered.items():
        if paths_[key].exists() and not _marked(paths_[key]):
            return {"result": "CONFLICT", "platform": platform_name, "artifacts": [str(paths_[key])]}
    if dry_run:
        return {"result": "WOULD_REMOVE", "platform": platform_name, "artifacts": [str(p) for p in paths_.values()]}
    native_result = _native(platform_name, "remove", paths_) if native else {"ok": True, "action": "skipped"}
    for path in paths_.values():
        path.unlink(missing_ok=True)
    return {"result": "REMOVED", "platform": platform_name, "native": native_result}


def status(*, home: Path | None = None, platform_name: str | None = None) -> dict:
    platform_name = platform_name or sys.platform
    paths_ = paths(home, platform_name=platform_name)
    present = {key: path.is_file() and not path.is_symlink() for key, path in paths_.items()}
    backend = "launchd" if platform_name == "darwin" else "systemd" if platform_name == "linux" else "unsupported"
    enabled = False
    configured_interval = None
    if backend == "launchd" and present.get("plist"):
        with paths_["plist"].open("rb") as stream:
            configured_interval = f"{plistlib.load(stream).get('StartInterval', 0) // 60}m"
        result = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, text=True, check=False)
        enabled = result.returncode == 0
    elif backend == "systemd" and present.get("timer"):
        for line in paths_["timer"].read_text().splitlines():
            if line.startswith("OnUnitActiveSec="):
                configured_interval = f"{int(line.split('=', 1)[1][:-1]) // 60}m"
                break
        result = subprocess.run(["systemctl", "--user", "is-enabled", TIMER], capture_output=True, text=True, check=False)
        enabled = result.returncode == 0
    rendered = render(platform_name, home=home) if platform_name in {"darwin", "linux"} else {}
    owned = bool(present) and all(_marked(paths_[key]) for key in paths_)
    return {"platform": platform_name, "backend": backend, "installed": all(present.values()) if present else False,
            "ownership": "OWNED" if owned else "ABSENT_OR_CONFLICT",
            "configured_interval": configured_interval or "30m", "executable": resolve_executable()[0],
            "artifact_paths": {key: str(path) for key, path in paths_.items()}, "present": present, "enabled": enabled}
