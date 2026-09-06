"""Bounded, read-only recursive SSH discovery."""

from __future__ import annotations

import json
import shlex
import subprocess
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .provider import DiscoveredPeer
from .seed import AUTH_PUBLIC_KEY, AUTH_UNKNOWN, AUTH_UNAVAILABLE, SSHSeed, _correlate
from .ssh import parse_ssh_config_sources
from .tailscale import normalize_status
from .remote_ssh import _parse_effective


@dataclass(frozen=True)
class RelationshipObservation:
    source: str
    destination: str
    alias: str
    effective: dict[str, Any]
    auth_state: str
    provenance: str
    observed_from: str
    evidence: str | None = None

    def as_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class NodeObservation:
    observation_identity: str
    observed_from: str
    aliases: tuple[str, ...] = ()
    provider_peers: tuple[dict[str, Any], ...] = ()
    status: str = "OBSERVED"

    def as_dict(self):
        return asdict(self)


@dataclass
class DiscoveryGraph:
    nodes: dict[str, NodeObservation] = field(default_factory=dict)
    relationships: list[RelationshipObservation] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    reason: str | None = None

    def add_node(self, node: NodeObservation):
        self.nodes.setdefault(node.observation_identity, node)

    def as_dict(self):
        return {"nodes": [node.as_dict() for node in self.nodes.values()],
                "relationships": [item.as_dict() for item in self.relationships],
                "sources": self.sources, "truncated": self.truncated, "reason": self.reason}


@dataclass(frozen=True)
class RemoteSourceObservation:
    source: str
    aliases: tuple[SSHSeed, ...]
    provider_peers: tuple[DiscoveredPeer, ...] = ()
    status: str = "OBSERVED"
    reason: str | None = None


def _remote_argv(source_alias: str, command: str) -> list[str]:
    return ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
            "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1", source_alias, command]


REMOTE_SEED_COMMAND = r'''set -eu
if [ -f "$HOME/.ssh/config" ]; then
  printf '%s\n' 'NETBOT_CONFIG_BEGIN'
  cat "$HOME/.ssh/config"
  printf '%s\n' 'NETBOT_CONFIG_END'
fi
if [ -d "$HOME/.ssh/config.d" ]; then
  for file in "$HOME/.ssh/config.d"/*; do
    [ -f "$file" ] || continue
    printf 'NETBOT_FILE_BEGIN %s\n' "${file##*/}"
    cat "$file"
    printf '%s\n' 'NETBOT_FILE_END'
  done
fi
if command -v tailscale >/dev/null 2>&1; then
  printf '%s\n' 'NETBOT_TAILSCALE_BEGIN'
  tailscale --socket=/var/run/tailscaled.socket status --json 2>/dev/null || true
  printf '%s\n' 'NETBOT_TAILSCALE_END'
fi'''


def _parse_remote_seed(output: str) -> tuple[list[tuple[str, str]], list[DiscoveredPeer]]:
    sources: list[tuple[str, str]] = []
    provider: list[DiscoveredPeer] = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == "NETBOT_CONFIG_BEGIN":
            i += 1; body = []
            while i < len(lines) and lines[i] != "NETBOT_CONFIG_END": body.append(lines[i]); i += 1
            sources.append(("~/.ssh/config", "\n".join(body) + "\n"))
        elif line.startswith("NETBOT_FILE_BEGIN "):
            name = line.split(" ", 1)[1]; i += 1; body = []
            while i < len(lines) and lines[i] != "NETBOT_FILE_END": body.append(lines[i]); i += 1
            sources.append((f"~/.ssh/config.d/{name}", "\n".join(body) + "\n"))
        elif line == "NETBOT_TAILSCALE_BEGIN":
            i += 1; body = []
            while i < len(lines) and lines[i] != "NETBOT_TAILSCALE_END": body.append(lines[i]); i += 1
            try:
                provider = [DiscoveredPeer("tailscale", node.node_id, node.name, list(node.addresses),
                                           node.online, dict(node.raw), node.last_seen)
                            for node in normalize_status(json.loads("\n".join(body)))]
            except (ValueError, TypeError, json.JSONDecodeError):
                provider = []
        i += 1
    return sources, provider


class RemoteSSHSeedObserver:
    """Fixed-purpose observer for one already authenticated SSH source."""

    def __init__(self, runner: Callable[..., Any] = subprocess.run, timeout: float = 8):
        self.runner = runner; self.timeout = timeout

    def observe(self, source: str) -> RemoteSourceObservation:
        try:
            result = self.runner(_remote_argv(source, REMOTE_SEED_COMMAND), text=True,
                                 capture_output=True, check=False, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return RemoteSourceObservation(source, (), status="SOURCE_UNAVAILABLE", reason="remote seed timeout")
        except OSError as exc:
            return RemoteSourceObservation(source, (), status="SOURCE_UNAVAILABLE", reason=str(exc))
        if result.returncode != 0:
            return RemoteSourceObservation(source, (), status="SOURCE_UNAVAILABLE",
                                           reason=(result.stderr or "remote seed failed").strip())
        sources, provider = _parse_remote_seed(result.stdout or "")
        hosts, _ = parse_ssh_config_sources(sources, exclude_managed=False)
        aliases = []
        for host in hosts:
            effective_result = self.runner(_remote_argv(source, "ssh -G " + shlex.quote(host.alias)),
                                           text=True, capture_output=True, check=False, timeout=self.timeout)
            effective, error = _parse_effective(effective_result.stdout or "") if effective_result.returncode == 0 else (None, "ssh -G failed")
            aliases.append(SSHSeed(host.alias, "SSH_CONFIG_MANAGED" if host.source.endswith("50-netbot.conf") else "SSH_CONFIG_HUMAN",
                                   host.source, effective or {}, _correlate(effective or {}, provider),
                                   AUTH_UNKNOWN, error))
        return RemoteSourceObservation(source, tuple(aliases), tuple(provider))


def _seed_relationship(source: str, seed: dict[str, Any]) -> RelationshipObservation:
    correlation = seed.get("correlation") or {}
    destination = correlation.get("provider_node_id") or seed.get("effective", {}).get("hostname") or seed["alias"]
    return RelationshipObservation(source, str(destination), seed["alias"], seed.get("effective", {}),
                                   seed.get("auth_state", AUTH_UNKNOWN), seed.get("provenance", "UNKNOWN"),
                                   source, seed.get("auth_evidence"))


def crawl(seed_source: str, local_seed: dict[str, Any], observer: Any, *,
          max_depth: int = 3, max_nodes: int = 64, per_operation_timeout: float = 8,
          total_cycle_budget: float = 120, now: Callable[[], float] = time.monotonic) -> DiscoveryGraph:
    """Traverse only sources reached through PUBLIC_KEY_PROVEN relationships."""
    del per_operation_timeout  # observer owns the operation timeout contract.
    graph = DiscoveryGraph()
    graph.add_node(NodeObservation(seed_source, seed_source,
                                    tuple(item["alias"] for item in local_seed.get("human_aliases", []) + local_seed.get("managed_aliases", []))))
    frontier = deque()
    for item in local_seed.get("human_aliases", []) + local_seed.get("managed_aliases", []):
        edge = _seed_relationship(seed_source, item); graph.relationships.append(edge)
        if edge.auth_state == AUTH_PUBLIC_KEY:
            frontier.append((edge.destination, edge.alias, 1))
    # The controller has already been observed locally; cycles back to it add
    # evidence but never trigger a second source inspection this cycle.
    visited: set[str] = {seed_source}
    started = now()
    while frontier:
        if now() - started >= total_cycle_budget:
            graph.truncated = True; graph.reason = "total cycle budget exhausted"; break
        source_key, source_alias, depth = frontier.popleft()
        if source_key in visited: continue
        if depth > max_depth:
            graph.truncated = True; graph.reason = "maximum crawl depth reached"; continue
        if len(visited) - 1 >= max_nodes:
            graph.truncated = True; graph.reason = "maximum crawl nodes reached"; break
        visited.add(source_key)
        observation = observer.observe(source_alias)
        graph.sources.append({"source": source_key, "alias": source_alias,
                              "status": observation.status, "reason": observation.reason})
        if observation.status != "OBSERVED":
            continue
        graph.add_node(NodeObservation(source_key, seed_source,
                                       tuple(seed.alias for seed in observation.aliases),
                                       tuple(peer.as_dict() for peer in observation.provider_peers)))
        for seed in observation.aliases:
            edge = RelationshipObservation(source_key,
                                           (seed.correlation or {}).get("provider_node_id") or seed.effective.get("hostname") or seed.alias,
                                           seed.alias, seed.effective, seed.auth_state, seed.provenance,
                                           source_key, seed.auth_evidence)
            graph.relationships.append(edge)
            if edge.auth_state == AUTH_PUBLIC_KEY and edge.destination not in visited:
                frontier.append((edge.destination, edge.alias, depth + 1))
    return graph
