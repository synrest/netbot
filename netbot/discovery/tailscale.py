import json, subprocess
from ..models import TailscaleNode

TAILSCALED_SOCKET = "/var/run/tailscaled.socket"

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

def discover() -> tuple[list[TailscaleNode], str | None]:
    try:
        result = subprocess.run(["tailscale", f"--socket={TAILSCALED_SOCKET}", "status", "--json"],
                                text=True, capture_output=True, check=True)
        return normalize_status(json.loads(result.stdout)), None
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        detail = (getattr(exc, "stderr", "") or str(exc)).strip()
        return [], detail
