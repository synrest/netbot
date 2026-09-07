"""Explicit, stale-checked acceptance of read-only discovery proposals."""

from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
from pathlib import Path

from .proposals import (ALREADY_ACCEPTED, CONFLICT, NEW_IDENTITY_CANDIDATE,
                        filter_actionable_proposals, generate_proposals,
                        rejection_fingerprint)
from ..config import load_topology, load_topology_authority
from ..state import State


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _candidate_text(original: bytes, proposal: dict) -> bytes:
    identity = proposal.get("proposed_alias") or proposal.get("target_entity")
    binding = proposal.get("provider_binding") or {}
    provider_id = binding.get("provider_node_id")
    provider = binding.get("provider")
    if not identity or provider != "tailscale" or provider_id is None:
        raise ValueError("proposal has no supported canonical topology binding")
    state = proposal.get("proposed_accepted_state") or {}
    bindings = state.get("bindings", {})
    ssh = bindings.get("ssh", {})
    block = (f"\n  {identity}:\n"
             "    class: unknown\n"
             "    bindings:\n"
             "      tailscale:\n"
             f"        node_id: \"{provider_id}\"\n"
             f"        name: {proposal.get('proposed_alias') or identity}\n")
    if ssh.get("aliases"):
        block += "      ssh:\n        aliases:\n"
        block += "".join(f"          - {alias}\n" for alias in ssh["aliases"])
        if ssh.get("user"):
            block += f"        user: {ssh['user']}\n"
        if ssh.get("port"):
            block += f"        port: {ssh['port']}\n"
    return original + block.encode("utf-8")


def _atomic_replace(path: Path, content: bytes, mode: int, expected_hash: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("topology path must be a regular non-symlink file")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError("topology parent must be a regular non-symlink directory")
    if _sha(path) != expected_hash:
        raise ValueError("topology changed during acceptance")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def accept_proposal(config: Path, db: Path, proposal_id: str, *, dry_run=False) -> dict:
    """Re-evaluate one proposal and optionally apply one topology mutation."""
    lock_path = config.parent / ".netbot-topology.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = State(db)
        try:
            _, hosts = load_topology(config)
            current_graph = state.discovery_graph()
            all_evidence = state.discovery_evidence()
            proposals = filter_actionable_proposals(
                generate_proposals(hosts, current_graph, all_evidence),
                state.topology_decisions("REJECT"))
            proposal = next((item for item in proposals if item["proposal_id"] == proposal_id), None)
            if proposal is None:
                if state.discovery_acceptance(proposal_id):
                    return {"proposal_id": proposal_id, "result": "ALREADY_ACCEPTED",
                            "topology_changed": False, "reconciliation_performed": False}
                return {"proposal_id": proposal_id, "result": "STALE_PROPOSAL",
                        "topology_changed": False, "reconciliation_performed": False}
            base = {"proposal_id": proposal_id, "proposal_type": proposal["proposal_type"],
                    "proposal": proposal, "topology_changed": False,
                    "reconciliation_performed": False}
            if proposal["proposal_type"] == ALREADY_ACCEPTED:
                base["result"] = "ALREADY_ACCEPTED"; return base
            if proposal["proposal_type"] != NEW_IDENTITY_CANDIDATE:
                base["result"] = "NON_ACTIONABLE"
                base["reason"] = "only NEW_IDENTITY_CANDIDATE acceptance is supported in M5b"
                return base
            if dry_run:
                original = config.read_bytes()
                proposed = _candidate_text(original, proposal)
                base.update({"result": "WOULD_ACCEPT", "dry_run": True,
                             "before_hash": hashlib.sha256(original).hexdigest(),
                             "after_hash": hashlib.sha256(proposed).hexdigest(),
                             "intended_topology": proposed.decode("utf-8")})
                return base
            original = config.read_bytes()
            before_hash = hashlib.sha256(original).hexdigest()
            if _sha(config) != before_hash:
                base.update(result="STALE_PROPOSAL"); return base
            proposed = _candidate_text(original, proposal)
            fd, name = tempfile.mkstemp(prefix=f".{config.name}.validate.", dir=config.parent)
            temp = Path(name)
            try:
                os.write(fd, proposed)
                os.close(fd)
                load_topology(temp)
            except Exception as exc:
                try: os.close(fd)
                except OSError: pass
                base.update(result="TOPOLOGY_WRITE_FAILED", error=str(exc)); return base
            finally:
                if temp.exists(): temp.unlink()
            _atomic_replace(config, proposed, config.stat().st_mode & 0o777, before_hash)
            after_hash = _sha(config)
            audit = {"proposal_id": proposal_id, "proposal_type": proposal["proposal_type"],
                     "controller_id": state.controller_identity(), "topology_hash_before": before_hash,
                     "topology_hash_after": after_hash, "result": "ACCEPTED",
                     "discovery_run_id": current_graph.get("run_id")}
            try:
                state.record_discovery_acceptance(audit)
            except Exception as exc:
                base.update(result="TOPOLOGY_UPDATED_AUDIT_FAILED", topology_changed=True,
                            before_hash=before_hash, after_hash=after_hash, audit_error=str(exc))
                return base
            base.update(result="ACCEPTED", topology_changed=True, before_hash=before_hash,
                        after_hash=after_hash, audit_result="RECORDED")
            return base
        finally:
            state.close()


def _proposal_references(proposal: dict, graph: dict) -> set[str]:
    """Return exact human references exposed by one current proposal."""
    references = {value for value in (proposal.get("proposed_alias"),
                                      proposal.get("target_entity"),
                                      proposal.get("candidate_identity")) if value}
    target = proposal.get("target_entity")
    for node in graph.get("nodes", []):
        if node.get("evidence_key") != target:
            continue
        for value in (node.get("advertised_name"), node.get("provider_node_id")):
            if value:
                references.add(str(value))
    return references


def accept_node(config: Path, db: Path, node: str, *, dry_run=False) -> dict:
    """Resolve one exact human node reference, then use accept_proposal."""
    state = State(db)
    try:
        _, hosts = load_topology(config)
        graph = state.discovery_graph()
        evidence = state.discovery_evidence()
        proposals = filter_actionable_proposals(generate_proposals(
            hosts, graph, evidence,
            controller_id=state.controller_identity(create=False),
            topology_authority=load_topology_authority(config)),
            state.topology_decisions("REJECT"))
    finally:
        state.close()

    matching = [item for item in proposals if node in _proposal_references(item, graph)]
    candidates = [item for item in matching if item["proposal_type"] == NEW_IDENTITY_CANDIDATE]
    if len(candidates) > 1:
        return {"schema": "netbot.cli/v1", "command": "accept", "requested_node": node,
                "result": "AMBIGUOUS", "reason": f"multiple current candidates match '{node}'",
                "topology_changed": False, "reconciliation_performed": False}
    if len(candidates) == 1:
        result = accept_proposal(config, db, candidates[0]["proposal_id"], dry_run=dry_run)
        result.update({"schema": "netbot.cli/v1", "command": "accept", "requested_node": node,
                       "resolved_proposal_id": candidates[0]["proposal_id"],
                       "canonical_identity": candidates[0].get("proposed_alias")})
        return result
    if any(item["proposal_type"] == CONFLICT for item in matching):
        result, reason = "CONFLICT", "the current observation conflicts with accepted topology"
    elif any(item["proposal_type"] != ALREADY_ACCEPTED for item in matching):
        result, reason = "NON_ACTIONABLE", "the current proposal type cannot be accepted"
    elif matching:
        result, reason = "ALREADY_ACCEPTED", "the identity is already represented in accepted topology"
    elif any(node == host.identity or node in {
             alias for alias in host.attrs.get("bindings", {}).get("ssh", {}).get("aliases", [])
             } for host in hosts):
        result, reason = "ALREADY_ACCEPTED", "the identity is already represented in accepted topology"
    else:
        result, reason = "NO_MATCH", f"no actionable observed machine named '{node}'"
    return {"schema": "netbot.cli/v1", "command": "accept", "requested_node": node,
            "result": result, "reason": reason, "topology_changed": False,
            "reconciliation_performed": False}


def reject_proposal(config: Path, db: Path, proposal_id: str, *, reason=None) -> dict:
    """Reject one currently actionable candidate without changing topology."""
    lock_path = config.parent / ".netbot-topology.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = State(db)
        try:
            _, hosts = load_topology(config)
            graph = state.discovery_graph()
            raw = generate_proposals(hosts, graph, state.discovery_evidence())
            fingerprint = next((rejection_fingerprint(item) for item in raw
                                if item.get("proposal_id") == proposal_id), None)
            decisions = state.topology_decisions("REJECT")
            proposals = filter_actionable_proposals(raw, decisions)
            proposal = next((item for item in proposals if item.get("proposal_id") == proposal_id), None)
            base = {"proposal_id": proposal_id, "proposal_type":
                    (proposal or {}).get("proposal_type"), "topology_changed": False,
                    "reconciliation_performed": False}
            if proposal is None:
                if fingerprint and fingerprint["fingerprint"] in {row.get("evidence_fingerprint") for row in decisions}:
                    base.update(result="ALREADY_REJECTED", rejection_fingerprint=fingerprint["fingerprint"],
                                fingerprint_version=fingerprint["version"])
                else:
                    base.update(result="STALE_PROPOSAL")
                return base
            if proposal.get("proposal_type") != NEW_IDENTITY_CANDIDATE:
                base.update(result="NON_ACTIONABLE", reason="only NEW_IDENTITY_CANDIDATE rejection is supported")
                return base
            if not fingerprint:
                base.update(result="NON_ACTIONABLE", reason="proposal has no supported strong identity")
                return base
            decision = state.record_topology_decision({
                "decision_type": "REJECT", "evidence_fingerprint": fingerprint["fingerprint"],
                "fingerprint_version": fingerprint["version"],
                "proposal_type": proposal["proposal_type"], "proposal_id": proposal_id,
                "subject_reference": proposal.get("proposed_alias") or proposal.get("target_entity") or proposal_id,
                "reason": reason})
            return {**base, "result": "REJECTED", "proposal": proposal,
                    "rejection_fingerprint": fingerprint["fingerprint"],
                    "fingerprint_version": fingerprint["version"], "decision": decision,
                    "audit_result": "RECORDED"}
        finally:
            state.close()


def reject_node(config: Path, db: Path, node: str, *, reason=None) -> dict:
    """Resolve one exact current actionable candidate for rejection."""
    state = State(db)
    try:
        _, hosts = load_topology(config)
        graph = state.discovery_graph()
        raw = generate_proposals(hosts, graph, state.discovery_evidence(),
                                 controller_id=state.controller_identity(create=False),
                                 topology_authority=load_topology_authority(config))
        decisions = state.topology_decisions("REJECT")
        proposals = filter_actionable_proposals(raw, decisions)
        raw_matching = [item for item in raw if node in _proposal_references(item, graph)]
        matching = [item for item in proposals if node in _proposal_references(item, graph)]
    finally:
        state.close()
    candidates = [item for item in matching if item.get("proposal_type") == NEW_IDENTITY_CANDIDATE]
    base = {"schema": "netbot.cli/v1", "command": "reject", "requested_node": node,
            "topology_changed": False, "reconciliation_performed": False}
    if len(candidates) > 1:
        return {**base, "result": "AMBIGUOUS", "reason": f"multiple current candidates match '{node}'"}
    if len(candidates) == 1:
        result = reject_proposal(config, db, candidates[0]["proposal_id"], reason=reason)
        return {**result, **base, "resolved_proposal_id": candidates[0]["proposal_id"],
                "canonical_identity": candidates[0].get("proposed_alias")}
    rejected = {row.get("evidence_fingerprint") for row in decisions}
    if any((fingerprint := rejection_fingerprint(item)) and
           fingerprint["fingerprint"] in rejected for item in raw_matching):
        return {**base, "result": "ALREADY_REJECTED",
                "reason": "the current identity evidence was already rejected"}
    if any(item.get("proposal_type") == CONFLICT for item in matching):
        result, detail = "CONFLICT", "the current observation conflicts with accepted topology"
    elif matching:
        result, detail = "NON_ACTIONABLE", "the current proposal type cannot be rejected"
    elif any(node == host.identity for host in hosts):
        result, detail = "ALREADY_ACCEPTED", "the identity is already represented in accepted topology"
    else:
        result, detail = "NO_MATCH", f"no actionable observed machine named '{node}'"
    return {**base, "result": result, "reason": detail}
