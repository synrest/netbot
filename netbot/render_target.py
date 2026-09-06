"""Pure preview rendering of a target's desired Netbot SSH namespace."""

from __future__ import annotations

from dataclasses import dataclass

from .config import load_topology
from .desired_route import desired_route
from .discovery.remote_ssh import validate_alias
from .models import DesiredHost
from .peer_policy import PolicyValidationError, expected_peers, load_peer_policy


@dataclass(frozen=True)
class RenderInput:
    identity: str
    alias: str | None
    hostname: str | None
    user: str | None
    port: int | None
    state: str
    reason: str
    identity_file: str | None = None

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass(frozen=True)
class TargetRender:
    target_identity: str
    state: str
    text: str = ""
    inputs: tuple[RenderInput, ...] = ()
    reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "target_identity": self.target_identity,
            "state": self.state,
            "reason": self.reason,
            "inputs": [item.as_dict() for item in self.inputs],
            "text": self.text,
        }


def _ssh(host: DesiredHost) -> dict:
    return host.attrs.get("bindings", {}).get("ssh", {})


def _block(alias: str, hostname: str, user: str, port: int) -> str:
    return f"Host {alias}\n    HostName {hostname}\n    User {user}\n    Port {port}\n"


def render_inputs(inputs: tuple[RenderInput, ...] | list[RenderInput]) -> str:
    """Render already-validated inputs in deterministic alias order."""
    by_alias = {item.alias: item for item in inputs}
    output = []
    for alias in sorted(by_alias):
        item = by_alias[alias]
        output.append(_block(alias, item.hostname, item.user, item.port))
        if item.identity_file:
            output[-1] = output[-1].replace(
                f"    Port {item.port}\n",
                f"    Port {item.port}\n    IdentityFile {item.identity_file}\n")
    return "".join(output)


def render_target(config_path, target_identity: str) -> TargetRender:
    """Return an exact preview or structured incomplete result; never writes."""
    try:
        _, hosts = load_topology(config_path)
        policy = load_peer_policy(config_path)
        peer_result = expected_peers(target_identity, hosts, policy)
    except PolicyValidationError as exc:
        return TargetRender(target_identity, "INVALID_POLICY", reason=str(exc))

    if peer_result.state != "OK":
        return TargetRender(target_identity, peer_result.state, reason=peer_result.reason)

    by_identity = {host.identity: host for host in hosts}
    aliases: dict[str, str] = {}
    inputs: list[RenderInput] = []
    errors: list[RenderInput] = []
    for decision in peer_result.peers:
        host = by_identity.get(decision.destination_identity)
        ssh = _ssh(host) if host else {}
        route = desired_route(target_identity, decision.destination_identity, hosts)
        host_aliases = sorted(set(ssh.get("aliases", [])))
        if not host_aliases:
            item = RenderInput(decision.destination_identity, None, route.hostname,
                               ssh.get("user"), route.port, "SSH_ALIAS_MISSING",
                               "topology SSH alias is missing")
            inputs.append(item); errors.append(item); continue
        if route.state != "ROUTABLE":
            item = RenderInput(decision.destination_identity, host_aliases[0], route.hostname,
                               ssh.get("user"), route.port, "ROUTE_UNAVAILABLE",
                               route.reason or "desired route is unavailable")
            inputs.append(item); errors.append(item); continue
        user = ssh.get("user")
        for alias in host_aliases:
            if not validate_alias(alias):
                item = RenderInput(decision.destination_identity, alias, route.hostname, user,
                                   route.port, "INVALID_RENDER_INPUT", "SSH alias syntax is invalid")
                inputs.append(item); errors.append(item); continue
            if alias in aliases and aliases[alias] != decision.destination_identity:
                item = RenderInput(decision.destination_identity, alias, route.hostname, user,
                                   route.port, "INVALID_RENDER_INPUT",
                                   "SSH alias is claimed by multiple expected identities")
                inputs.append(item); errors.append(item); continue
            if not user:
                item = RenderInput(decision.destination_identity, alias, route.hostname, None,
                                   route.port, "SSH_USER_MISSING", "topology SSH user is missing")
                inputs.append(item); errors.append(item); continue
            if route.port is None:
                item = RenderInput(decision.destination_identity, alias, route.hostname, user,
                                   None, "INVALID_RENDER_INPUT", "desired route port is invalid")
                inputs.append(item); errors.append(item); continue
            aliases[alias] = decision.destination_identity
            inputs.append(RenderInput(decision.destination_identity, alias, route.hostname, user,
                                      route.port, "RENDERABLE", "complete desired render inputs",
                                      ssh.get("identity_file") or ssh.get("identityfile")))

    if errors:
        return TargetRender(target_identity, "INCOMPLETE", inputs=tuple(inputs),
                            reason="one or more expected peers cannot be rendered safely")
    text = render_inputs(inputs)
    return TargetRender(target_identity, "RENDERABLE", text=text, inputs=tuple(inputs))
