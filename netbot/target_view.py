"""Machine-relative, read-only SSH topology view."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .config import load_topology
from .discovery.remote_ssh import RemoteSSHObservation, inspect_target
from .generate.ssh import _target_matches_observation
from .peer_policy import expected_peers, load_peer_policy, PolicyValidationError
from .desired_route import desired_route


@dataclass(frozen=True)
class SSHRelationship:
    identity: str
    alias: str
    state: str
    provenance: str
    effective: dict[str, Any]
    reason: str | None = None
    candidate_endpoint: str | None = None
    candidate_user: str | None = None
    action: str = "none"
    desired_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SSHView:
    target_identity: str
    status: str
    relationships: list[SSHRelationship]
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_identity": self.target_identity,
            "status": self.status,
            "reason": self.reason,
            "relationships": [item.as_dict() for item in self.relationships],
        }


def _ssh(host):
    return host.attrs.get("bindings", {}).get("ssh", {})


def _observed_dict(node):
    if isinstance(node, dict):
        return node
    return {
        "status": "present",
        "name": node.name,
        "dns_name": node.dns_name,
        "addresses": node.addresses,
    }


def _by_identity(observed):
    return {item.get("identity"): item for item in observed or [] if isinstance(item, dict) and item.get("identity")}


def _relationship(identity, alias, observation: RemoteSSHObservation, bindings,
                  target_identity, observed, known_observed, desired_hosts, desired_reason=None):
    effective = observation.effective
    provenance = observation.provenance
    if observation.status == "UNAVAILABLE":
        return SSHRelationship(identity, alias, "UNAVAILABLE", provenance, effective, observation.reason,
                               desired_reason=desired_reason)
    if observation.status == "INVALID":
        return SSHRelationship(identity, alias, "UNKNOWN", provenance, effective, observation.reason,
                               desired_reason=desired_reason)
    if provenance == "CONFLICT":
        return SSHRelationship(identity, alias, "CONFLICT", provenance, effective, observation.reason,
                               desired_reason=desired_reason)
    if provenance == "UNKNOWN":
        return SSHRelationship(identity, alias, "UNKNOWN", provenance, effective, observation.reason,
                               desired_reason=desired_reason)

    route_result = desired_route(target_identity, identity, desired_hosts)
    route_status = route_result.state
    route = {"hostname": route_result.hostname, "port": route_result.port} \
        if route_result.state == "ROUTABLE" else None
    route_reason = route_result.reason
    endpoint = None
    user = bindings.get("user")
    if route_status == "ROUTABLE":
        endpoint = f"{route['hostname']}:{route['port']}"
    elif route_reason:
        return SSHRelationship(identity, alias, "NOT_ROUTABLE_FROM_TARGET", provenance, effective, route_reason,
                               desired_reason=desired_reason)

    if provenance == "ABSENT":
        return SSHRelationship(
            identity, alias, "MISSING", provenance, effective,
            "no explicit manual alias on target", endpoint, user,
            "would-generate" if endpoint and user else "none",
            desired_reason,
        )
    if provenance == "MANAGED":
        return SSHRelationship(identity, alias, "VALID_MANAGED", provenance, effective,
                               "validated Netbot-owned alias", desired_reason=desired_reason)

    # Explicit ownership is valid only when its effective endpoint and
    # declared user/port agree with this topology relationship.
    if not observed or not _target_matches_observation(
        {"effective_config": {"effective": effective}, "target": effective.get("hostname")}, observed
    ):
        if any(_target_matches_observation(
            {"effective_config": {"effective": effective}, "target": effective.get("hostname")},
            other,
        ) for other_identity, other in known_observed.items() if other_identity != identity):
            return SSHRelationship(identity, alias, "CONFLICT", provenance, effective,
                                   "explicit alias maps to a different observed topology identity",
                                   desired_reason=desired_reason)
        return SSHRelationship(identity, alias, "UNKNOWN", provenance, effective,
                               "explicit alias destination is not proven by observation",
                               desired_reason=desired_reason)
    if user and effective.get("user") != user:
        return SSHRelationship(identity, alias, "CONFLICT", provenance, effective,
                               "explicit alias user conflicts with topology binding",
                               desired_reason=desired_reason)
    expected_port = route.get("port", 22) if route else 22
    if effective.get("port") != expected_port:
        return SSHRelationship(identity, alias, "CONFLICT", provenance, effective,
                               "explicit alias port conflicts with topology route",
                               desired_reason=desired_reason)
    return SSHRelationship(identity, alias, "VALID_MANUAL", provenance, effective,
                           "explicit manual alias maps to intended topology identity",
                           desired_reason=desired_reason)


def build_ssh_view(
    config_path,
    target_identity: str,
    observed=None,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> SSHView:
    """Build a target-relative view from topology and local observations."""
    _, hosts = load_topology(config_path)
    target = next((host for host in hosts if host.identity == target_identity), None)
    if target is None:
        return SSHView(target_identity, "UNKNOWN", [], "target identity is not in topology")

    try:
        policy = load_peer_policy(config_path)
        policy_result = expected_peers(target_identity, hosts, policy)
    except PolicyValidationError as exc:
        return SSHView(target_identity, "INVALID_POLICY", [], str(exc))
    if policy_result.state != "OK":
        return SSHView(target_identity, policy_result.state, [], policy_result.reason)

    claims: dict[str, set[str]] = {}
    candidates: list[tuple[Any, str, str]] = []
    by_identity = {host.identity: host for host in hosts}
    for decision in policy_result.peers:
        host = by_identity[decision.destination_identity]
        aliases = _ssh(host).get("aliases", [])
        alias = sorted(aliases)[0]
        claims.setdefault(alias, set()).add(host.identity)
        candidates.append((host, alias, decision.reason))

    observed_by_identity = _by_identity(observed)
    relationships = []
    unavailable = False
    for host, alias, desired_reason in candidates:
        bindings = _ssh(host)
        if len(claims[alias]) > 1:
            relationships.append(SSHRelationship(
                host.identity, alias, "CONFLICT", "UNKNOWN", {},
                "SSH alias is claimed by multiple topology identities",
                desired_reason=desired_reason,
            ))
            continue
        observation = inspect_target(config_path, target_identity, alias, runner=runner)
        unavailable = unavailable or observation.status == "UNAVAILABLE"
        relationship = _relationship(
            host.identity, alias, observation, bindings, target_identity,
            observed_by_identity.get(host.identity), observed_by_identity, hosts, desired_reason,
        )
        relationships.append(relationship)
    status = "UNAVAILABLE" if unavailable else "OK"
    reason = "target transport or observation unavailable" if unavailable else None
    return SSHView(target_identity, status, relationships, reason)
