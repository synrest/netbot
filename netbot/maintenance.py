"""One-shot autonomous maintenance orchestration."""

from __future__ import annotations

import fcntl
from collections import Counter
from pathlib import Path

from .config import load_topology, load_topology_authority
from .controller_reconcile import reconcile_controller
from .discovery.cycle import run_cycle
from .discovery.proposals import generate_proposals
from .state import State
from .events import record_maintenance_events


def _proposal_summary(items):
    counts = Counter(item.get("proposal_type") for item in items)
    counts.pop(None, None)
    pending = {"NEW_IDENTITY_CANDIDATE", "RELATIONSHIP_CANDIDATE",
               "EXISTING_IDENTITY_REBIND_CANDIDATE", "CONFLICT", "INSUFFICIENT_EVIDENCE"}
    return {"total": len(items), "counts": dict(sorted(counts.items())),
            "actionable_proposals": sum(counts.get(kind, 0) for kind in pending),
            "items": items}


def _aggregate(discovery, reconciliation):
    if discovery.get("status") in {"BLOCKED", "PERSISTENCE_FAILED", "FAILED"}:
        return "BLOCKED" if discovery.get("status") == "BLOCKED" else "FAILED"
    if reconciliation.get("status") in {"BLOCKED", "FAILED"}:
        return reconciliation["status"]
    if discovery.get("status") == "PARTIAL" or reconciliation.get("status") == "PARTIAL":
        return "PARTIAL"
    return "OK"


def run_maintenance(config_path: Path, db_path: Path, *, dry_run=False,
                    runtime: Path | None = None, cycle_runner=run_cycle,
                    reconcile_runner=reconcile_controller):
    runtime = runtime or (db_path.parent / "run")
    runtime.mkdir(parents=True, exist_ok=True)
    lock_path = runtime / "maintenance.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "BLOCKED", "reason": "maintenance run already active",
                    "dry_run": dry_run, "discovery": {}, "proposals": _proposal_summary([]),
                    "reconciliation": {}, "summary": {}, "topology_changed": False,
                    "proposal_acceptance_performed": False}

        discovery = cycle_runner(config_path, db_path, dry_run=dry_run, runtime=runtime)
        if discovery.get("status") in {"BLOCKED", "PERSISTENCE_FAILED", "FAILED"}:
            return {"status": _aggregate(discovery, {}), "dry_run": dry_run,
                    "discovery": discovery, "proposals": _proposal_summary([]),
                    "reconciliation": {}, "summary": {"discovery_status": discovery.get("status")},
                    "topology_changed": False, "proposal_acceptance_performed": False}

        state = State(db_path)
        try:
            _, hosts = load_topology(config_path)
            graph = discovery.get("crawl", state.discovery_graph())
            history = state.discovery_evidence()
            proposals = generate_proposals(
                hosts, graph, history,
                controller_id=discovery.get("controller_id") or state.controller_identity(create=False),
                topology_authority=load_topology_authority(config_path))
        finally:
            state.close()

        reconciliation = reconcile_runner(config_path, db_path, dry_run=dry_run)
        event_error = None
        if not dry_run:
            try:
                event_state = State(db_path)
                record_maintenance_events(event_state, discovery, proposals, reconciliation)
                event_state.close()
            except Exception as exc:
                event_error = str(exc)
        rs = reconciliation.get("summary", {})
        summary = {
            "discovery_status": discovery.get("status"),
            "proposal_count": len(proposals),
            "actionable_proposals": _proposal_summary(proposals)["actionable_proposals"],
            "reconcile_changed": rs.get("changed", 0),
            "reconcile_unchanged": rs.get("unchanged", 0),
            "reconcile_unavailable": rs.get("unavailable", 0),
            "reconcile_blocked": rs.get("blocked", 0),
            "reconcile_failed": rs.get("failed", 0),
        }
        result_status = "FAILED" if event_error else _aggregate(discovery, reconciliation)
        result = {"status": result_status, "dry_run": dry_run,
                "discovery": discovery, "proposals": _proposal_summary(proposals),
                "reconciliation": reconciliation, "summary": summary,
                "topology_changed": False, "proposal_acceptance_performed": False}
        if event_error:
            result["event_persistence_error"] = event_error
        return result
