"""Pure desired SSH route planning from topology intent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import DesiredHost


LOOPBACK = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class DesiredRoute:
    source_identity: str
    destination_identity: str
    state: str
    kind: str | None = None
    hostname: str | None = None
    port: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "source_identity": self.source_identity,
            "destination_identity": self.destination_identity,
            "state": self.state,
            "kind": self.kind,
            "hostname": self.hostname,
            "port": self.port,
            "reason": self.reason,
        }


def _ssh(host: DesiredHost) -> dict:
    return host.attrs.get("bindings", {}).get("ssh", {})


def connection_metadata(source: DesiredHost, destination_identity: str) -> dict:
    """Return explicit source-to-destination SSH client metadata."""
    return (_ssh(source).get("connections", {}).get(destination_identity, {})
            if isinstance(_ssh(source).get("connections", {}), dict) else {})


def _tailscale(host: DesiredHost) -> dict:
    return host.attrs.get("bindings", {}).get("tailscale", {})


def _inactive(host: DesiredHost) -> bool:
    return host.attrs.get("lifecycle") == "retired" or bool(host.attrs.get("superseded_by"))


def _port(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def desired_route(
    source_identity: str,
    destination_identity: str,
    desired: Iterable[DesiredHost],
) -> DesiredRoute:
    """Compute route intent without observations, discovery, or SSH state."""
    hosts = {host.identity: host for host in desired}
    if source_identity not in hosts:
        return DesiredRoute(source_identity, destination_identity, "DESTINATION_UNKNOWN",
                            reason="source identity is not in desired topology")
    destination = hosts.get(destination_identity)
    if destination is None or _inactive(destination):
        return DesiredRoute(source_identity, destination_identity, "DESTINATION_UNKNOWN",
                            reason="destination identity is not an active desired topology identity")

    ssh = _ssh(destination)
    hostname = ssh.get("hostname")
    port = _port(ssh.get("port", 22))
    controller = ssh.get("controller")
    if hostname is not None:
        if not isinstance(hostname, str) or not hostname.strip():
            return DesiredRoute(source_identity, destination_identity, "INVALID_ROUTE",
                                kind="EXPLICIT_OVERRIDE", reason="desired route hostname is invalid")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            return DesiredRoute(source_identity, destination_identity, "INVALID_ROUTE",
                                kind="EXPLICIT_OVERRIDE", reason="desired route port is invalid")
        if controller is not None and controller != source_identity:
            return DesiredRoute(source_identity, destination_identity, "NO_PORTABLE_ROUTE",
                                kind="EXPLICIT_OVERRIDE",
                                reason="desired route is scoped to controller " + str(controller))
        if hostname in LOOPBACK and controller != source_identity:
            return DesiredRoute(source_identity, destination_identity, "NO_PORTABLE_ROUTE",
                                kind="EXPLICIT_OVERRIDE",
                                reason="loopback desired route requires matching source controller")
        return DesiredRoute(source_identity, destination_identity, "ROUTABLE",
                            kind="EXPLICIT_OVERRIDE", hostname=hostname, port=port,
                            reason="explicit desired route applies to source")

    tailscale_name = _tailscale(destination).get("name")
    if tailscale_name:
        return DesiredRoute(source_identity, destination_identity, "ROUTABLE",
                            kind="TAILSCALE_NAME", hostname=tailscale_name, port=port,
                            reason="desired Tailscale name is the portable route identity")
    if not _tailscale(destination).get("node_id"):
        return DesiredRoute(source_identity, destination_identity, "DESTINATION_UNBOUND",
                            reason="destination has no desired Tailscale binding")
    return DesiredRoute(source_identity, destination_identity, "NO_PORTABLE_ROUTE",
                        reason="desired Tailscale binding has no portable name")
