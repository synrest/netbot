"""Explicit, stale-checked acceptance of read-only discovery proposals."""

from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
from pathlib import Path

from .proposals import (ALREADY_ACCEPTED, CONFLICT, NEW_IDENTITY_CANDIDATE,
                        generate_proposals)
from ..config import load_topology
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
            proposals = generate_proposals(hosts, current_graph, all_evidence)
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
