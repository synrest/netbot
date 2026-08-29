from dataclasses import dataclass, field
from typing import Any

@dataclass
class DesiredHost:
    identity: str
    attrs: dict[str, Any] = field(default_factory=dict)

@dataclass
class TailscaleNode:
    node_id: str | None
    name: str | None
    dns_name: str | None
    addresses: list[str]
    online: bool | None
    os: str | None
    last_seen: str | None
    raw: dict[str, Any] = field(default_factory=dict)

@dataclass
class Observation:
    status: str
    node: TailscaleNode | None = None
    identity: str | None = None
    confidence: str | None = None
    source: str | None = None

@dataclass
class SSHHost:
    alias: str
    hostname: str | None = None
    user: str | None = None
    port: int | None = None
    identity_files: list[str] = field(default_factory=list)
    source: str = "local ssh config"

@dataclass
class ReconciliationResult:
    run_id: int | None
    hosts: list[dict[str, Any]]
    unknown_nodes: list[dict[str, Any]]
    changes: list[dict[str, Any]]
    error: str | None = None
