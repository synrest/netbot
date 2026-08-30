"""Canonical desired-topology snapshots for future distribution."""

from datetime import datetime, timezone
import hashlib
import json
import subprocess
from pathlib import Path

from .config import load_topology, load_topology_authority
from .models import DesiredHost

SNAPSHOT_SCHEMA = 1
_HOST_FIELDS = ("class", "kind", "observed_names", "parent", "os_family",
                "lifecycle", "superseded_by")
_TAILSCALE_FIELDS = ("node_id", "name")
_SSH_FIELDS = ("aliases", "user", "port", "hostname", "controller")


def _normalize(value):
    if isinstance(value, dict):
        return {str(key): _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("unsupported topology value: " + type(value).__name__)


def _host_payload(host):
    attrs = host.attrs
    payload = {key: _normalize(attrs[key]) for key in _HOST_FIELDS if key in attrs}
    bindings = attrs.get("bindings", {})
    binding_payload = {}
    tailscale = bindings.get("tailscale", {})
    ssh = bindings.get("ssh", {})
    if tailscale:
        binding_payload["tailscale"] = {key: _normalize(tailscale[key]) for key in _TAILSCALE_FIELDS if key in tailscale}
    if ssh:
        binding_payload["ssh"] = {key: _normalize(ssh[key]) for key in _SSH_FIELDS if key in ssh}
    if binding_payload:
        payload["bindings"] = binding_payload
    return {"identity": host.identity, **payload}


def topology_payload(topology_version, hosts, authority=None):
    """Return the canonical, desired-only payload hashed by snapshots."""
    payload = {"version": topology_version,
               "hosts": [_host_payload(host) for host in sorted(hosts, key=lambda h: h.identity)]}
    if authority is not None:
        payload["authority"] = authority
    return payload


def canonical_json(payload):
    return json.dumps(_normalize(payload), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def build_snapshot(config: Path, generated_at=None):
    topology_version, hosts = load_topology(config)
    topology = topology_payload(topology_version, hosts, load_topology_authority(config))
    canonical = canonical_json(topology).encode("utf-8")
    content_hash = hashlib.sha256(canonical).hexdigest()
    return {"schema": SNAPSHOT_SCHEMA, "version": topology_version, "content_hash": content_hash,
            "topology": topology,
            "generated_at": generated_at or datetime.now(timezone.utc).isoformat()}


def compare_snapshot(snapshot, previous):
    if previous is None:
        return "NO_PREVIOUS_SNAPSHOT"
    return "SAME" if snapshot["content_hash"] == previous["content_hash"] else "CHANGED"


def persist_snapshot(state, snapshot):
    """Persist the complete snapshot atomically through State's SQLite DB."""
    return state.save_topology_snapshot(snapshot)


def validate_snapshot(snapshot, expected_authority=None):
    if not isinstance(snapshot, dict):
        return False, "snapshot is not a JSON object"
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        return False, "unsupported snapshot schema"
    topology = snapshot.get("topology")
    if not isinstance(topology, dict) or not isinstance(topology.get("version"), int) or not isinstance(topology.get("hosts"), list):
        return False, "invalid topology structure"
    if snapshot.get("version") != topology["version"]:
        return False, "snapshot version does not match topology version"
    if set(topology) - {"version", "authority", "hosts"}:
        return False, "unsupported topology fields"
    content_hash = snapshot.get("content_hash")
    if not isinstance(content_hash, str) or len(content_hash) != 64 or any(c not in "0123456789abcdef" for c in content_hash):
        return False, "invalid content hash"
    if hashlib.sha256(canonical_json(topology).encode("utf-8")).hexdigest() != content_hash:
        return False, "content hash mismatch"
    identities = [host.get("identity") for host in topology["hosts"] if isinstance(host, dict)]
    if len(identities) != len(topology["hosts"]) or any(not isinstance(identity, str) or not identity for identity in identities):
        return False, "invalid topology host identity"
    if len(set(identities)) != len(identities):
        return False, "duplicate topology identity"
    for host in topology["hosts"]:
        if set(host) - {"identity", *_HOST_FIELDS, "bindings"}:
            return False, "unsupported topology host fields"
        bindings = host.get("bindings", {})
        if not isinstance(bindings, dict) or set(bindings) - {"tailscale", "ssh"}:
            return False, "unsupported topology binding fields"
        for name, allowed in (("tailscale", _TAILSCALE_FIELDS), ("ssh", _SSH_FIELDS)):
            binding = bindings.get(name, {})
            if not isinstance(binding, dict) or set(binding) - set(allowed):
                return False, "unsupported topology " + name + " fields"
    if expected_authority is not None:
        if topology.get("authority") != expected_authority:
            return False, "snapshot authority does not match expected authority"
    return True, None


def hosts_from_snapshot(snapshot):
    """Decode validated canonical topology data into existing desired models."""
    return [DesiredHost(host["identity"], {key: value for key, value in host.items() if key != "identity"})
            for host in snapshot["topology"]["hosts"]]


def local_machine_identity(config: Path, nodes):
    """Resolve the local topology identity from the observed self hostname."""
    self_node = next((node for node in nodes if node.raw.get("_netbot_self")), None)
    if self_node is None:
        return None
    _, hosts = load_topology(config)
    names = {self_node.name, (self_node.dns_name or "").rstrip(".").split(".", 1)[0]}
    names.discard(None)
    matches = [host.identity for host in hosts
               if host.identity in names or host.attrs.get("bindings", {}).get("tailscale", {}).get("name") in names]
    return matches[0] if len(matches) == 1 else None


def effective_topology(config: Path, state, current_identity, nodes=None):
    """Select authoritative desired topology without silently falling back."""
    authority = load_topology_authority(config)
    local_version, local_hosts = load_topology(config)
    # Older isolated/test topologies have no authority declaration. Preserve
    # their local-only behavior when the current identity is known; configured
    # multi-machine topologies always use the strict authority rules below.
    if authority is None:
        payload = topology_payload(local_version, local_hosts)
        canonical = canonical_json(payload).encode("utf-8")
        return {"state": "OK", "source": "local-authority", "authority": current_identity,
                "effective_hash": hashlib.sha256(canonical).hexdigest(),
                "accepted_at": None, "fetch_state": "not-applicable", "desired": local_hosts}
    if authority is not None and current_identity == authority:
        snapshot = build_snapshot(config)
        return {"state": "OK", "source": "local-authority", "authority": authority,
                "effective_hash": snapshot["content_hash"], "accepted_at": None,
                "fetch_state": "not-applicable", "desired": local_hosts}
    accepted = state.latest_accepted_topology_snapshot()
    if accepted is None:
        return {"state": "NO_AUTHORITATIVE_TOPOLOGY", "source": "none", "authority": authority,
                "effective_hash": None, "accepted_at": None,
                "fetch_state": state.latest_topology_fetch_status(), "desired": []}
    if accepted.get("invalid"):
        return {"state": "NO_AUTHORITATIVE_TOPOLOGY", "source": "none", "authority": authority,
                "effective_hash": None, "accepted_at": accepted["accepted_at"],
                "fetch_state": state.latest_topology_fetch_status(), "reason": accepted["reason"], "desired": []}
    valid, reason = validate_snapshot(accepted["snapshot"], authority)
    if not valid:
        return {"state": "NO_AUTHORITATIVE_TOPOLOGY", "source": "none", "authority": authority,
                "effective_hash": None, "accepted_at": accepted["accepted_at"],
                "fetch_state": state.latest_topology_fetch_status(), "reason": reason, "desired": []}
    return {"state": "OK", "source": "accepted-authority", "authority": authority,
            "effective_hash": accepted["snapshot"]["content_hash"], "accepted_at": accepted["accepted_at"],
            "fetch_state": state.latest_topology_fetch_status(), "desired": hosts_from_snapshot(accepted["snapshot"])}


def resolve_authority(config: Path):
    authority = load_topology_authority(config)
    if not authority:
        return None, "topology authority is not explicitly configured"
    _, hosts = load_topology(config)
    host = next((host for host in hosts if host.identity == authority), None)
    if host is None:
        return None, "configured topology authority identity is not declared"
    ssh = host.attrs.get("bindings", {}).get("ssh", {})
    aliases = ssh.get("aliases", [])
    user = ssh.get("user")
    if not aliases or not user or len(aliases) != 1:
        return None, "authority requires exactly one explicit SSH alias and user"
    return {"identity": authority, "alias": aliases[0], "user": user}, None


def export_snapshot(state):
    snapshot = state.latest_topology_snapshot()
    if snapshot is None:
        return None
    return snapshot


def snapshot_ssh_command(authority):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
            f"{authority['user']}@{authority['alias']}", "netbot topology snapshot --export"]


def fetch_snapshot(config: Path, state, runner=subprocess.run):
    authority, reason = resolve_authority(config)
    if reason:
        result = {"result": "UNAVAILABLE", "authority": load_topology_authority(config), "reason": reason}
        state.save_topology_fetch_status(result)
        return result
    command = snapshot_ssh_command(authority)
    try:
        completed = runner(command, text=True, capture_output=True, check=False, timeout=8)
    except (OSError, TimeoutError) as exc:
        result = {"result": "UNAVAILABLE", "authority": authority["identity"], "command": command, "reason": str(exc)}
        state.save_topology_fetch_status(result)
        return result
    if completed.returncode != 0:
        result = {"result": "UNAVAILABLE", "authority": authority["identity"], "command": command,
                  "reason": (completed.stderr or "SSH transport failed").strip()}
        state.save_topology_fetch_status(result)
        return result
    try:
        envelope = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        result = {"result": "REJECTED", "authority": authority["identity"], "command": command,
                  "reason": "malformed snapshot JSON: " + str(exc)}
        state.save_topology_fetch_status(result)
        return result
    if not isinstance(envelope, dict):
        result = {"result": "REJECTED", "authority": authority["identity"], "command": command, "reason": "snapshot export is not an object"}
        state.save_topology_fetch_status(result)
        return result
    source = envelope.get("source_authority")
    snapshot = envelope.get("snapshot")
    if source != authority["identity"]:
        result = {"result": "REJECTED", "authority": authority["identity"], "command": command, "reason": "source authority identity mismatch"}
        state.save_topology_fetch_status(result)
        return result
    valid, reason = validate_snapshot(snapshot, authority["identity"])
    if not valid:
        result = {"result": "REJECTED", "authority": authority["identity"], "command": command, "reason": reason}
        state.save_topology_fetch_status(result)
        return result
    previous = state.latest_accepted_topology_snapshot()
    if previous and not previous.get("invalid") and previous["snapshot"]["content_hash"] == snapshot["content_hash"]:
        result = {"result": "SAME", "authority": authority["identity"], "command": command, "remote_hash": snapshot["content_hash"], "accepted_hash": previous["snapshot"]["content_hash"]}
        state.save_topology_fetch_status(result)
        return result
    try:
        state.save_accepted_topology_snapshot(snapshot, authority["identity"], "ssh")
    except Exception as exc:
        result = {"result": "REJECTED", "authority": authority["identity"], "command": command,
                  "remote_hash": snapshot["content_hash"], "reason": "snapshot persistence failed: " + str(exc)}
        state.save_topology_fetch_status(result)
        return result
    result = {"result": "ACCEPTED", "authority": authority["identity"], "command": command,
              "remote_hash": snapshot["content_hash"], "accepted_hash": snapshot["content_hash"]}
    state.save_topology_fetch_status(result)
    return result
