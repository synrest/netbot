"""Deterministic, read-only topology proposals from discovery evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Any, Iterable


ALREADY_ACCEPTED = "ALREADY_ACCEPTED"
NEW_IDENTITY_CANDIDATE = "NEW_IDENTITY_CANDIDATE"
EXISTING_IDENTITY_REBIND_CANDIDATE = "EXISTING_IDENTITY_REBIND_CANDIDATE"
RELATIONSHIP_CANDIDATE = "RELATIONSHIP_CANDIDATE"
CONFLICT = "CONFLICT"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    proposal_type: str
    status: str
    candidate_identity: str | None
    source_identity: str | None
    target_entity: str | None
    proposed_alias: str | None
    provider_binding: dict[str, Any] | None
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    current_accepted_state: Any
    proposed_accepted_state: Any
    management_authority: str
    first_seen: str | None
    last_seen: str | None
    observation_count: int

    def as_dict(self):
        return asdict(self)


def _id(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:20]


def _proposal(**values) -> Proposal:
    identity = {key: values.get(key) for key in
                ("proposal_type", "candidate_identity", "source_identity", "target_entity",
                 "proposed_alias", "provider_binding", "supporting_evidence",
                 "contradicting_evidence", "missing_evidence", "current_accepted_state",
                 "proposed_accepted_state")}
    values["proposal_id"] = _id(identity)
    return Proposal(**values)


def _bindings(host) -> dict[str, Any]:
    return host.attrs.get("bindings", {})


def _ssh_aliases(host) -> list[str]:
    return list(_bindings(host).get("ssh", {}).get("aliases", []) or [])


def _accepted(hosts: Iterable[Any]):
    by_provider: dict[tuple[str, str], list[str]] = {}
    by_identity = {}
    for host in hosts:
        by_identity[host.identity] = host
        tailscale = _bindings(host).get("tailscale", {})
        node_id = tailscale.get("node_id")
        if node_id is not None:
            by_provider.setdefault(("tailscale", str(node_id)), []).append(host.identity)
    return by_provider, by_identity


def resolve_observation_to_topology_identity(observation_id: str | None, *,
                                             controller_id: str | None = None,
                                             topology_authority: str | None = None) -> str | None:
    """Correlate only the current controller observation through explicit context."""
    if observation_id and controller_id and topology_authority and observation_id == controller_id:
        return topology_authority
    return None


def _node_evidence(rows: list[dict[str, Any]], run_id: str | None):
    rows = [row for row in rows if run_id is None or row.get("run_id") == run_id]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = row.get("evidence_key")
        if key:
            grouped.setdefault(key, []).append(row)
    return grouped


def _human_names(relationships: list[dict[str, Any]], node: dict[str, Any]) -> tuple[list[str], list[str]]:
    provider_name = node.get("advertised_name")
    addresses = set(node.get("addresses") or [])
    aliases = []
    supporting = []
    for edge in relationships:
        if edge.get("provenance") != "SSH_CONFIG_HUMAN":
            continue
        effective = edge.get("effective") or {}
        destination = edge.get("destination")
        if destination in {provider_name, *addresses} or effective.get("hostname") in {provider_name, *addresses}:
            aliases.append(edge.get("alias"))
            supporting.append(f'HUMAN SSH alias "{edge.get("alias")}" observed from {edge.get("source")}')
    return sorted({x for x in aliases if x}), supporting


def _history_stats(all_nodes: list[dict[str, Any]], key: str):
    matches = [row for row in all_nodes if row.get("evidence_key") == key]
    dates = [row.get("observed_at") for row in matches if row.get("observed_at")]
    return (min(dates) if dates else None, max(dates) if dates else None, len(matches))


def generate_proposals(hosts: list[Any], current_graph: dict[str, Any],
                       historical_evidence: dict[str, Any] | None = None, *,
                       controller_id: str | None = None,
                       topology_authority: str | None = None) -> list[dict[str, Any]]:
    """Return deterministic proposals; this function has no mutation side effects."""
    historical_evidence = historical_evidence or current_graph
    accepted_by_provider, accepted_by_identity = _accepted(hosts)
    current_nodes = current_graph.get("nodes", [])
    current_edges = current_graph.get("relationships", [])
    all_nodes = historical_evidence.get("nodes", [])
    historical_edges = historical_evidence.get("relationships", [])
    proposals: list[Proposal] = []

    # Rebinds are candidates only when two independent continuity facts are
    # present.  Provider names/IPs alone deliberately do not qualify.
    rebinds: dict[str, tuple[str, list[str]]] = {}
    for host in hosts:
        old = _bindings(host).get("tailscale", {}).get("node_id")
        if old is None:
            continue
        old_key = f"tailscale:{old}"
        old_edges = [edge for edge in historical_edges if edge.get("destination") == old_key or
                     edge.get("destination") == str(old)]
        for node in current_nodes:
            new_id = node.get("provider_node_id")
            if node.get("provider") != "tailscale" or new_id is None or str(new_id) == str(old):
                continue
            new_edges = [edge for edge in current_edges if edge.get("destination") in
                         {node.get("evidence_key"), str(new_id), node.get("advertised_name")}]
            facts = []
            old_pairs = {(edge.get("source"), edge.get("alias")): edge for edge in old_edges}
            for edge in new_edges:
                prior = old_pairs.get((edge.get("source"), edge.get("alias")))
                if not prior:
                    continue
                facts.append(f"same SSH alias {edge.get('alias')} from {edge.get('source')}")
                old_effective, new_effective = prior.get("effective") or {}, edge.get("effective") or {}
                if old_effective.get("hostname") and old_effective.get("hostname") == new_effective.get("hostname"):
                    facts.append(f"same effective SSH hostname {new_effective['hostname']}")
                for field in ("host_key_fingerprint", "known_host_fingerprint"):
                    if old_effective.get(field) and old_effective.get(field) == new_effective.get(field):
                        facts.append(f"same {field}")
            if len(set(facts)) >= 2:
                rebinds[f"tailscale:{new_id}"] = (host.identity, sorted(set(facts)))

    for node in current_nodes:
        provider = node.get("provider")
        provider_id = node.get("provider_node_id")
        if not provider or provider_id is None:
            continue
        key = node.get("evidence_key") or f"{provider}:{provider_id}"
        binding = {"provider": provider, "provider_node_id": str(provider_id)}
        matched = accepted_by_provider.get((provider, str(provider_id)), [])
        names, human_support = _human_names(current_edges, node)
        alias = names[0] if len(names) == 1 else (node.get("advertised_name") or key)
        first, last, count = _history_stats(all_nodes, key)
        common = dict(candidate_identity=matched[0] if len(matched) == 1 else None,
                      source_identity=None, target_entity=key, proposed_alias=alias,
                      provider_binding=binding, current_accepted_state=matched or None,
                      proposed_accepted_state=None, management_authority="not-granted-by-proposal",
                      first_seen=first, last_seen=last, observation_count=count,
                      contradicting_evidence=(), missing_evidence=())
        if key in rebinds:
            identity, facts = rebinds[key]
            proposals.append(_proposal(proposal_type=EXISTING_IDENTITY_REBIND_CANDIDATE,
                status=EXISTING_IDENTITY_REBIND_CANDIDATE,
                **{**common, "candidate_identity": identity,
                   "supporting_evidence": tuple(facts) +
                   (f"historical provider identity tailscale:{_bindings(accepted_by_identity[identity]).get('tailscale', {}).get('node_id')}",
                    f"current provider identity {key}"),
                   "missing_evidence": ("explicit operator confirmation",)}))
        elif len(matched) > 1:
            proposals.append(_proposal(proposal_type=CONFLICT, status=CONFLICT,
                **{**common, "supporting_evidence": tuple(human_support),
                   "contradicting_evidence": (f"provider binding matches multiple accepted identities: {', '.join(matched)}",)}))
        elif len(names) > 1:
            proposals.append(_proposal(proposal_type=CONFLICT, status=CONFLICT,
                **{**common, "supporting_evidence": tuple(human_support),
                   "contradicting_evidence": (f"conflicting human aliases: {', '.join(names)}",)}))
        elif matched:
            proposals.append(_proposal(proposal_type=ALREADY_ACCEPTED, status=ALREADY_ACCEPTED,
                supporting_evidence=(f"exact {provider}-scoped node ID {provider_id} is explicitly accepted as {matched[0]}",),
                **common))
        else:
            evidence = list(human_support)
            if node.get("advertised_name"):
                evidence.append(f"provider advertised name: {node['advertised_name']}")
            evidence.append(f"no accepted topology binding matches {provider}:{provider_id}")
            proposals.append(_proposal(proposal_type=NEW_IDENTITY_CANDIDATE,
                status=NEW_IDENTITY_CANDIDATE,
                **{**common, "supporting_evidence": tuple(evidence),
                   "missing_evidence": ("operator identity acceptance",)}))

    accepted_aliases = {(host.identity, alias) for host in hosts for alias in _ssh_aliases(host)}
    for edge in current_edges:
        if edge.get("provenance") != "SSH_CONFIG_HUMAN":
            continue
        source = edge.get("source")
        correlated_source = resolve_observation_to_topology_identity(
            source, controller_id=controller_id, topology_authority=topology_authority)
        alias = edge.get("alias")
        # The accepted topology schema represents the controller's outgoing
        # SSH projection on destination hosts.  Only suppress aliases from a
        # source proven to be the local topology authority; unresolved source
        # namespaces must continue producing proposals.
        if correlated_source == topology_authority and any(alias == accepted_alias
                                                           for _, accepted_alias in accepted_aliases):
            continue
        target = edge.get("destination")
        binding = None
        for node in current_nodes:
            if target in {node.get("evidence_key"), node.get("provider_node_id"), node.get("advertised_name"), *(node.get("addresses") or [])}:
                if node.get("provider_node_id") is not None:
                    binding = {"provider": node.get("provider"), "provider_node_id": str(node.get("provider_node_id"))}
                break
        support = (f'HUMAN SSH alias "{alias}" observed from {source}',
                   f"auth state: {edge.get('auth_state', 'UNKNOWN')}")
        proposals.append(_proposal(proposal_type=RELATIONSHIP_CANDIDATE, status=RELATIONSHIP_CANDIDATE,
            candidate_identity=None, source_identity=source, target_entity=str(target), proposed_alias=alias,
            provider_binding=binding, supporting_evidence=support, contradicting_evidence=(),
            missing_evidence=() if binding else ("objective provider correlation",),
            current_accepted_state=None, proposed_accepted_state={"relationship": "SSH_REPRESENTATION"},
            management_authority="source management authority must be evaluated separately",
            first_seen=edge.get("observed_at"), last_seen=edge.get("observed_at"), observation_count=1))

    return [proposal.as_dict() for proposal in sorted(proposals, key=lambda item: item.proposal_id)]
