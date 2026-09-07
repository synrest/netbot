"""Provider-neutral observations used by the first discovery cycle."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .tailscale import discover


@dataclass(frozen=True)
class DiscoveredPeer:
    provider: str
    provider_node_id: str | None
    advertised_name: str | None
    addresses: list[str] = field(default_factory=list)
    online: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class TailscaleProvider:
    name = "tailscale"

    def __init__(self, executable=None):
        self.executable = executable

    def observe(self) -> tuple[list[DiscoveredPeer], str | None]:
        nodes, error = discover(self.executable)
        peers = [DiscoveredPeer(
            provider=self.name,
            provider_node_id=node.node_id,
            advertised_name=node.name,
            addresses=list(node.addresses),
            online=node.online,
            metadata=dict(node.raw),
            observed_at=node.last_seen,
        ) for node in nodes]
        return peers, error
