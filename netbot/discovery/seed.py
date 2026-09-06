"""Read-only local SSH seed discovery."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from .provider import DiscoveredPeer
from .ssh import effective_config, inspect_ssh, known_host_fingerprints


AUTH_PUBLIC_KEY = "PUBLIC_KEY_PROVEN"
AUTH_PASSWORD = "PASSWORD_GATED"
AUTH_UNAVAILABLE = "UNAVAILABLE"
AUTH_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SSHSeed:
    alias: str
    provenance: str
    source: str
    effective: dict[str, Any]
    correlation: dict[str, Any] | None
    auth_state: str
    auth_evidence: str | None = None
    known_hosts: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _auth_probe(alias: str, runner: Callable[..., Any]) -> tuple[str, str | None]:
    command = ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
               "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
               "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1", alias, "true"]
    try:
        completed = runner(command, text=True, capture_output=True, check=False, timeout=4)
    except subprocess.TimeoutExpired:
        return AUTH_UNAVAILABLE, "bounded SSH authentication probe timed out"
    except OSError as exc:
        return AUTH_UNAVAILABLE, f"SSH authentication probe unavailable: {exc}"
    if completed.returncode == 0:
        return AUTH_PUBLIC_KEY, "noninteractive public-key authentication succeeded"
    error = (completed.stderr or "").strip()
    low = error.lower()
    if "permission denied" in low and ("publickey,password" in low or "publickey,keyboard-interactive" in low):
        return AUTH_PASSWORD, "server advertised password-capable authentication after public-key failure"
    if any(token in low for token in ("timed out", "connection refused", "could not resolve hostname", "nodename nor servname")):
        return AUTH_UNAVAILABLE, error or "SSH destination unavailable"
    return AUTH_UNKNOWN, error or "noninteractive SSH authentication failed without a classified cause"


def _correlate(effective: dict[str, Any], peers: list[DiscoveredPeer]) -> dict[str, Any] | None:
    hostname = (effective.get("hostname") or "").rstrip(".")
    for peer in peers:
        names = {x for x in (peer.advertised_name, (peer.metadata.get("DNSName") if peer.metadata else None)) if x}
        dns = {x.rstrip(".") for x in names}
        if hostname in dns or hostname in {address for address in peer.addresses}:
            return {"provider": peer.provider, "provider_node_id": peer.provider_node_id,
                    "advertised_name": peer.advertised_name, "evidence": "exact hostname/address match"}
    return None


def discover_local_ssh(home: Path, peers: list[DiscoveredPeer], *,
                       runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Enumerate explicit human/managed aliases without crawling remotely."""
    human, includes = inspect_ssh(home, exclude_managed=True)
    all_hosts, _ = inspect_ssh(home, exclude_managed=False)
    managed_paths = {str(path) for path in (home / ".ssh" / "config.d").glob("50-netbot.conf")}
    human_aliases = {host.alias for host in human}
    managed = [host for host in all_hosts if host.source in managed_paths or host.alias not in human_aliases and host.source.endswith("50-netbot.conf")]

    known = known_host_fingerprints(home, runner=runner)
    entries: list[SSHSeed] = []
    for host, provenance in [(host, "SSH_CONFIG_HUMAN") for host in human] + [(host, "SSH_CONFIG_MANAGED") for host in managed]:
        resolved = effective_config(host.alias, runner=runner)
        effective = resolved.get("effective", {}) if resolved.get("status") == "available" else {}
        if isinstance(effective.get("port"), str) and effective["port"].isdigit():
            effective = dict(effective)
            effective["port"] = int(effective["port"])
        if effective:
            auth_state, auth_evidence = _auth_probe(host.alias, runner)
            correlation = _correlate(effective, peers)
            host_candidates = {effective.get("hostname"), host.hostname, host.alias}
            key_evidence = [entry for entry in known.get("entries", []) if entry.get("host") in host_candidates]
        else:
            auth_state, auth_evidence, correlation, key_evidence = AUTH_UNAVAILABLE, resolved.get("error"), None, []
        entries.append(SSHSeed(host.alias, provenance, host.source, effective, correlation,
                               auth_state, auth_evidence, key_evidence))

    seen = set()
    aliases = []
    for entry in entries:
        if (entry.provenance, entry.alias) not in seen:
            seen.add((entry.provenance, entry.alias)); aliases.append(entry)
    correlated_ids = {entry.correlation.get("provider_node_id") for entry in aliases if entry.correlation}
    unresolved = [peer.as_dict() for peer in peers if peer.provider_node_id not in correlated_ids]
    return {"human_aliases": [entry.as_dict() for entry in aliases if entry.provenance == "SSH_CONFIG_HUMAN"],
            "managed_aliases": [entry.as_dict() for entry in aliases if entry.provenance == "SSH_CONFIG_MANAGED"],
            "includes": includes,
            "known_hosts": {"status": known.get("status"),
                            "entry_count": len(known.get("entries", []))},
            "unresolved_provider_peers": unresolved}
