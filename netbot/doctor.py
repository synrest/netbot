"""Read-only local installation and capability diagnostics."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from .service import detect_backend, status as service_status
from .version import __version__


def install_prefix() -> Path:
    configured = os.environ.get("NETBOT_PREFIX")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "Library" / "Application Support" / "Netbot"


def check(label: str, ok: bool, detail: str, warning: bool = False) -> dict:
    return {"name": label, "status": "WARNING" if warning else ("OK" if ok else "ERROR"), "detail": detail}


def diagnose() -> dict:
    prefix = install_prefix()
    backend = detect_backend()
    checks = [check("python", sys.version_info >= (3, 10), platform.python_version()),
              check("tailscale", bool(shutil.which("tailscale")), shutil.which("tailscale") or "not found"),
              check("ssh", bool(shutil.which("ssh")), shutil.which("ssh") or "not found"),
              check("launchctl", bool(shutil.which("launchctl")), shutil.which("launchctl") or "not found",
                    warning=sys.platform != "darwin")]
    tailscale = shutil.which("tailscale")
    if tailscale:
        version = subprocess.run([tailscale, "version"], text=True, capture_output=True, timeout=5, check=False)
        checks.append(check("tailscale-version", version.returncode == 0,
                            version.stdout.splitlines()[0] if version.stdout else version.stderr.strip()))
        status = subprocess.run([tailscale, "status", "--json"], text=True,
                                capture_output=True, timeout=5, check=False)
        checks.append(check("tailscale-status", status.returncode == 0,
                            "daemon status accessible" if status.returncode == 0 else status.stderr.strip()))
    config = prefix / "config" / "topology.yaml"
    state = prefix / "state"
    runtime = prefix / "run"
    logs = (Path.home() / "Library" / "Logs" / "Netbot" if sys.platform == "darwin"
            else prefix / "logs")
    checks.extend([check("topology", config.is_file(), str(config)),
                   check("state", state.exists() and os.access(state, os.R_OK | os.W_OK), str(state)),
                   check("runtime", runtime.exists() and os.access(runtime, os.R_OK | os.W_OK), str(runtime)),
                   check("logs", logs.exists() and os.access(logs, os.R_OK | os.W_OK), str(logs))])
    if backend in {"launchd", "systemd", "openrc"}:
        try:
            service = service_status()
        except (OSError, subprocess.SubprocessError) as exc:
            service = {"loaded": False, "watcher": False,
                       "running": False, "error": str(exc)}
        checks.append(check("supervisor", True, backend))
        checks.append(check("watcher-service", service.get("loaded", False) and service.get("watcher", False),
                            service.get("error") or f"backend={backend} loaded={service.get('loaded')} running={service.get('running')} pid={service.get('pid')}",
                            warning=backend == "openrc" and not service.get("installed", False)))
    else:
        checks.append(check("supervisor", False, "unsupported supervisor"))
        checks.append(check("watcher-service", False, "not installed", warning=True))
    return {"version": __version__, "python": platform.python_version(),
            "install_prefix": str(prefix), "backend": backend, "checks": checks}
