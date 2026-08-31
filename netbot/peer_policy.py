"""Explicit, deterministic expected-peer policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import DesiredHost


class PolicyValidationError(ValueError):
    pass


@dataclass(frozen=True)
class PeerOverride:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True)
class PeerPolicy:
    default: str | None = None
    classes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    overrides: dict[str, PeerOverride] = field(default_factory=dict)


@dataclass(frozen=True)
class PeerDecision:
    destination_identity: str
    reason: str


@dataclass(frozen=True)
class ExpectedPeersResult:
    source_identity: str
    state: str
    peers: tuple[PeerDecision, ...] = ()
    excluded: tuple[PeerDecision, ...] = ()
    reason: str | None = None

    def as_dict(self):
        return {
            "source_identity": self.source_identity,
            "state": self.state,
            "reason": self.reason,
            "peers": [{"identity": p.destination_identity, "reason": p.reason} for p in self.peers],
            "excluded": [{"identity": p.destination_identity, "reason": p.reason} for p in self.excluded],
        }


def _scalar(text: str) -> str:
    value = text.strip().strip("'\"")
    if not value or value.startswith(("-", "#")) or any(ch.isspace() for ch in value):
        raise PolicyValidationError("policy values must be non-empty single tokens")
    return value


def load_peer_policy(path: Path) -> PeerPolicy | None:
    """Parse the explicit peer_policy YAML subset; return None if absent."""
    policy_lines = []
    found = False
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        text = line.strip()
        if indent == 0 and text == "peer_policy:":
            if found:
                raise PolicyValidationError(f"duplicate peer_policy at line {number}")
            found = True
            continue
        if found and indent == 0:
            break
        if found:
            policy_lines.append((number, indent, text))
    if not found:
        return None

    default = None
    classes: dict[str, tuple[str, ...]] = {}
    overrides: dict[str, PeerOverride] = {}
    section = None
    current = None
    field_name = None
    values: list[str] = []

    def finish_field():
        nonlocal field_name, values
        field_name = None
        values = []

    for number, indent, text in policy_lines:
        if indent == 2 and text.startswith("default:"):
            if default is not None:
                raise PolicyValidationError(f"duplicate policy default at line {number}")
            default = _scalar(text.split(":", 1)[1])
            continue
        if indent == 2 and text.endswith(":"):
            finish_field()
            section = text[:-1]
            if section not in {"classes", "overrides"}:
                raise PolicyValidationError(f"unsupported peer_policy section at line {number}")
            current = None
            continue
        if indent == 4 and text.endswith(":") and section:
            finish_field()
            current = _scalar(text[:-1])
            if section == "classes":
                if current in classes:
                    raise PolicyValidationError(f"duplicate class policy at line {number}")
                classes[current] = ()
            else:
                if current in overrides:
                    raise PolicyValidationError(f"duplicate source override at line {number}")
                overrides[current] = PeerOverride()
            continue
        if indent == 6 and text.endswith(":") and section and current is not None:
            finish_field()
            field_name = text[:-1]
            allowed = {"sees"} if section == "classes" else {"include", "exclude"}
            if field_name not in allowed:
                raise PolicyValidationError(f"unsupported peer_policy field at line {number}")
            continue
        if indent == 8 and text.startswith("-") and field_name:
            value = _scalar(text[1:])
            values.append(value)
            if section == "classes":
                classes[current] = tuple(values)
            else:
                old = overrides[current]
                overrides[current] = PeerOverride(
                    include=tuple(values) if field_name == "include" else old.include,
                    exclude=tuple(values) if field_name == "exclude" else old.exclude,
                )
            continue
        raise PolicyValidationError(f"malformed peer_policy at line {number}")

    if default != "topology":
        raise PolicyValidationError("peer_policy.default must be topology")
    return PeerPolicy(default=default, classes=classes, overrides=overrides)


def _active(host: DesiredHost) -> bool:
    return host.attrs.get("lifecycle") != "retired" and not host.attrs.get("superseded_by")


def _bound(host: DesiredHost) -> bool:
    tailscale = host.attrs.get("bindings", {}).get("tailscale", {})
    return bool(tailscale.get("node_id") is not None or tailscale.get("name"))


def distributable_destination(host: DesiredHost) -> bool:
    """Whether a desired identity can enter the distributed SSH namespace."""
    return _active(host) and _bound(host) and bool(
        host.attrs.get("bindings", {}).get("ssh", {}).get("aliases")
    )


def _source_state(source: DesiredHost | None) -> str | None:
    if source is None:
        return "SOURCE_UNKNOWN"
    if source.attrs.get("lifecycle") == "retired":
        return "SOURCE_RETIRED"
    if source.attrs.get("superseded_by"):
        return "SOURCE_SUPERSEDED"
    if not _bound(source):
        return "SOURCE_UNBOUND"
    return None


def expected_peers(source_identity: str, desired: Iterable[DesiredHost], policy: PeerPolicy | None, observed=None) -> ExpectedPeersResult:
    """Evaluate only explicit desired policy; runtime observation is ignored."""
    hosts = {host.identity: host for host in desired}
    source = hosts.get(source_identity)
    if source is None:
        return ExpectedPeersResult(source_identity, "SOURCE_UNKNOWN", reason="source identity is not in desired topology")
    if policy is None:
        return ExpectedPeersResult(source_identity, "POLICY_ABSENT", reason="peer policy is not declared")
    source_state = _source_state(source)
    if source_state:
        return ExpectedPeersResult(source_identity, source_state, reason="source is not an active bound topology identity")
    if policy.default != "topology":
        return ExpectedPeersResult(source_identity, "INVALID_POLICY", reason="unsupported peer policy default")

    selected: dict[str, str] = {}
    source_class = source.attrs.get("class")
    class_filter = policy.classes.get(source_class)
    for host in sorted(hosts.values(), key=lambda item: item.identity):
        if host.identity == source_identity or not distributable_destination(host):
            continue
        if class_filter is None or host.attrs.get("class") in class_filter:
            selected[host.identity] = "TOPOLOGY_DEFAULT"

    override = policy.overrides.get(source_identity, PeerOverride())
    excluded: list[PeerDecision] = []
    for identity in override.include:
        host = hosts.get(identity)
        if identity == source_identity:
            excluded.append(PeerDecision(identity, "SELF"))
        elif host is None or not distributable_destination(host):
            excluded.append(PeerDecision(identity, "UNBOUND/INELIGIBLE"))
        else:
            selected.setdefault(identity, "EXPLICIT_INCLUDE")
    for identity in override.exclude:
        selected.pop(identity, None)
        if identity in hosts and identity != source_identity:
            excluded.append(PeerDecision(identity, "EXPLICIT_EXCLUDE"))
    peers = tuple(PeerDecision(identity, selected[identity]) for identity in sorted(selected))
    return ExpectedPeersResult(source_identity, "OK", peers=peers,
                               excluded=tuple(sorted(excluded, key=lambda item: item.destination_identity)))
