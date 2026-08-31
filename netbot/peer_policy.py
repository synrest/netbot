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
    """Parse only the explicit peer_policy YAML subset; return None if absent."""
    lines = path.read_text().splitlines()
    policy_lines = []
    found = False
    for number, raw in enumerate(lines, 1):
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
            # The policy ends at the next top-level YAML key.
            break
        if found:
            policy_lines.append((number, indent, text))
    if not found:
        return None

    classes: dict[str, tuple[str, ...]] = {}
    overrides: dict[str, PeerOverride] = {}
    section = None
    current = None
    current_field = None
    collected: list[str] = []

    def finish_field():
        nonlocal collected, current_field
        if current_field is None:
            return
        values = tuple(collected)
        if current == "classes":
            if current_field != "sees" or not isinstance(current, tuple):
                pass
        collected = []
        current_field = None

    for number, indent, text in policy_lines:
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
            current_field = text[:-1]
            if section == "classes" and current_field != "sees":
                raise PolicyValidationError(f"unsupported class policy field at line {number}")
            if section == "overrides" and current_field not in {"include", "exclude"}:
                raise PolicyValidationError(f"unsupported source override field at line {number}")
            continue
        if indent == 8 and text.startswith("-") and current_field:
            collected.append(_scalar(text[1:]))
            if section == "classes":
                classes[current] = tuple(collected)
            elif section == "overrides":
                old = overrides[current]
                overrides[current] = PeerOverride(
                    include=tuple(collected) if current_field == "include" else old.include,
                    exclude=tuple(collected) if current_field == "exclude" else old.exclude,
                )
            continue
        raise PolicyValidationError(f"malformed peer_policy at line {number}")
    finish_field()
    return PeerPolicy(classes=classes, overrides=overrides)


def _active(host: DesiredHost) -> bool:
    return host.attrs.get("lifecycle") != "retired" and not host.attrs.get("superseded_by")


def _bound(host: DesiredHost) -> bool:
    bindings = host.attrs.get("bindings", {})
    tailscale = bindings.get("tailscale", {})
    return bool(tailscale.get("node_id") is not None or tailscale.get("name"))


def expected_peers(
    source_identity: str,
    desired: Iterable[DesiredHost],
    policy: PeerPolicy | None,
    observed=None,
) -> ExpectedPeersResult:
    """Evaluate only explicit topology policy; observation is evidence only."""
    hosts = {host.identity: host for host in desired}
    source = hosts.get(source_identity)
    if source is None:
        return ExpectedPeersResult(source_identity, "UNKNOWN_SOURCE", reason="source identity is not in desired topology")
    if policy is None:
        return ExpectedPeersResult(source_identity, "POLICY_ABSENT", reason="peer policy is not declared")
    if not _active(source):
        return ExpectedPeersResult(source_identity, "SOURCE_INACTIVE", reason="source identity is retired or superseded")

    selected: dict[str, str] = {}
    source_class = source.attrs.get("class")
    for host in sorted(hosts.values(), key=lambda item: item.identity):
        if host.identity == source_identity:
            continue
        if not _active(host):
            continue
        if not _bound(host):
            continue
        if source_class in policy.classes and host.attrs.get("class") in policy.classes[source_class]:
            selected[host.identity] = "CLASS_POLICY"

    override = policy.overrides.get(source_identity, PeerOverride())
    excluded = []
    for identity in override.include:
        host = hosts.get(identity)
        if identity == source_identity:
            excluded.append(PeerDecision(identity, "SELF"))
        elif host is None or not _active(host) or not _bound(host):
            excluded.append(PeerDecision(identity, "UNBOUND/INELIGIBLE"))
        else:
            selected.setdefault(identity, "EXPLICIT_INCLUDE")
    for identity in override.exclude:
        selected.pop(identity, None)
        if identity in hosts and identity != source_identity:
            excluded.append(PeerDecision(identity, "EXPLICIT_EXCLUDE"))
    peers = tuple(PeerDecision(identity, selected[identity]) for identity in sorted(selected))
    return ExpectedPeersResult(source_identity, "OK", peers=peers, excluded=tuple(sorted(excluded, key=lambda item: item.destination_identity)))
