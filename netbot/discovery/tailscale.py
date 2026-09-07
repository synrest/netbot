import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from ..models import TailscaleNode

TAILSCALED_SOCKET = "/var/run/tailscaled.socket"
_MACOS_CANDIDATES = ("/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale")
_LINUX_CANDIDATES = ("/usr/bin/tailscale", "/usr/local/bin/tailscale")


def resolve_executable(executable: str | Path | None = None, *, platform_name=None):
    """Resolve Tailscale without relying on an interactive scheduler PATH."""
    if executable is not None:
        path = Path(executable)
        if not path.is_absolute():
            raise ValueError("Tailscale executable must be an absolute path")
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None

    found = shutil.which("tailscale")
    if found:
        path = Path(found).resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)

    platform_name = platform_name or platform.system().lower()
    candidates = _MACOS_CANDIDATES if platform_name == "darwin" else _LINUX_CANDIDATES if platform_name == "linux" else ()
    for candidate in candidates:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None

def _first(d, *keys):
    for k in keys:
        if d.get(k) is not None: return d[k]
    return None

def normalize_status(payload: dict) -> list[TailscaleNode]:
    nodes = []
    for key, value in (payload.get("Peer") or payload.get("peer") or {}).items():
        value = dict(value); value.setdefault("NodeID", key)
        last_seen = _first(value, "LastSeen", "LastSeenTime")
        if last_seen and str(last_seen).startswith("0001-"): last_seen = None
        nodes.append(TailscaleNode(str(_first(value, "NodeID", "ID")) if _first(value, "NodeID", "ID") else None,
            _first(value, "HostName", "Name", "DNSName"), _first(value, "DNSName", "DNS"),
            list(_first(value, "TailscaleIPs", "Addresses") or []), value.get("Online"),
            _first(value, "OS", "OSFamily"), last_seen, value))
    self_node = payload.get("Self") or payload.get("self")
    if self_node:
        value = dict(self_node); value.setdefault("HostName", value.get("Name"))
        last_seen = _first(value, "LastSeen", "LastSeenTime")
        if last_seen and str(last_seen).startswith("0001-"): last_seen = None
        value["_netbot_self"] = True
        nodes.insert(0, TailscaleNode(str(_first(value, "NodeID", "ID")) if _first(value, "NodeID", "ID") else None,
            _first(value, "HostName", "Name", "DNSName"), _first(value, "DNSName", "DNS"),
            list(_first(value, "TailscaleIPs", "Addresses") or []), value.get("Online", True),
            _first(value, "OS", "OSFamily"), last_seen, value))
    return nodes

def short_dns_name(name):
    return name.rstrip(".").split(".", 1)[0] if name else None

def discover(executable: str | Path | None = None, *, platform_name=None) -> tuple[list[TailscaleNode], str | None]:
    try:
        resolved = resolve_executable(executable, platform_name=platform_name)
        if not resolved:
            return [], "tailscale executable not found"
        result = subprocess.run([resolved, f"--socket={TAILSCALED_SOCKET}", "status", "--json"],
                                text=True, capture_output=True, check=True)
        return normalize_status(json.loads(result.stdout)), None
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        detail = (getattr(exc, "stderr", "") or str(exc)).strip()
        return [], detail
