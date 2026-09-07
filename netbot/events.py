"""Meaningful durable transitions derived from existing maintenance results."""
from __future__ import annotations

import hashlib
import json


SEVERITY = {
    "NEW_TOPOLOGY_PROPOSAL": "ATTENTION", "TOPOLOGY_CONFLICT": "ERROR",
    "MANAGED_STATE_CHANGED": "INFO", "MANAGED_STATE_DRIFT": "ATTENTION",
    "RECONCILE_FAILED": "ERROR", "TARGET_UNAVAILABLE": "ATTENTION",
    "TARGET_RECOVERED": "INFO", "PROVIDER_FAILED": "ATTENTION",
    "PROVIDER_RECOVERED": "INFO",
}


def _emit(state, event_type, subject, stable_key, summary, details=None):
    return state.record_event(event_type, SEVERITY[event_type], subject, stable_key,
                              summary, details, condition=True)


def _resolve_legacy_controller_events(state, controller_id, canonical_controller, accepted_aliases):
    """Resolve only old UUID-sourced relationship attention proven redundant."""
    if not controller_id or not canonical_controller or not accepted_aliases:
        return
    rows = state.db.execute("""SELECT stable_key,summary,details_json FROM events
        WHERE event_type='NEW_TOPOLOGY_PROPOSAL' AND resolved_at IS NULL
          AND subject_identity=?""", (controller_id,)).fetchall()
    for row in rows:
        try:
            details = json.loads(row[2] or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        if details.get("proposal_type") != "RELATIONSHIP_CANDIDATE":
            continue
        alias = str(row[1] or "").split(": ", 1)[-1]
        if alias in accepted_aliases:
            state.resolve_event(row[0])


def record_maintenance_events(state, discovery, proposals, reconciliation, *,
                               canonical_controller=None, accepted_aliases=()):
    """Persist transitions after a non-dry maintenance result is complete."""
    created = []
    provider = discovery.get("provider", {})
    provider_key = f"provider-failed:{provider.get('name', 'unknown')}"
    if provider.get("error"):
        item = _emit(state, "PROVIDER_FAILED", provider.get("name"), provider_key,
                     f"Discovery provider {provider.get('name')} failed", {"error": provider["error"]})
        if item["created"]: created.append(item["event_id"])
    else:
        previous = state.resolve_event(provider_key)
        if previous:
            item = _emit(state, "PROVIDER_RECOVERED", provider.get("name"),
                         f"provider-recovered:{provider.get('name')}:{previous['event_id']}",
                         f"Discovery provider {provider.get('name')} recovered")
            if item["created"]: created.append(item["event_id"])

    for proposal in proposals:
        kind = proposal.get("proposal_type")
        if kind not in {"CONFLICT", "NEW_IDENTITY_CANDIDATE", "EXISTING_IDENTITY_REBIND_CANDIDATE", "RELATIONSHIP_CANDIDATE", "INSUFFICIENT_EVIDENCE"}:
            continue
        event_type = "TOPOLOGY_CONFLICT" if kind == "CONFLICT" else "NEW_TOPOLOGY_PROPOSAL"
        item = _emit(state, event_type, proposal.get("candidate_identity") or proposal.get("source_identity"),
                     f"proposal:{proposal.get('proposal_id')}",
                     f"{kind}: {proposal.get('proposed_alias') or proposal.get('candidate_identity') or proposal.get('proposal_id')}",
                     {"proposal_id": proposal.get("proposal_id"), "proposal_type": kind})
        if item["created"]: created.append(item["event_id"])

    _resolve_legacy_controller_events(state, discovery.get("controller_id"),
                                      canonical_controller, set(accepted_aliases))

    for target in reconciliation.get("targets", []):
        identity = target.get("target_identity")
        result = target.get("result")
        state_name = target.get("state")
        if result == "TARGET_UNAVAILABLE" or state_name == "TARGET_UNAVAILABLE":
            key = f"target-unavailable:{identity}"
            item = _emit(state, "TARGET_UNAVAILABLE", identity, key, f"Target {identity} is unavailable")
            if item["created"]: created.append(item["event_id"])
            continue
        unavailable_key = f"target-unavailable:{identity}"
        previous = state.resolve_event(unavailable_key)
        if previous:
            occurrence = state.event_occurrence(unavailable_key)
            item = _emit(state, "TARGET_RECOVERED", identity,
                         f"target-recovered:{identity}:{previous['event_id']}:{occurrence}",
                         f"Target {identity} recovered")
            if item["created"]: created.append(item["event_id"])
        if result in {"WRITE_VERIFIED", "INSTALLED", "CREATED", "REPLACED", "REMOVED"}:
            desired = target.get("desired_content") or (target.get("apply") or {}).get("content_hash") or result
            digest = hashlib.sha256(str(desired).encode()).hexdigest()[:16]
            item = _emit(state, "MANAGED_STATE_CHANGED", identity, f"managed-change:{identity}:{digest}",
                         f"Managed SSH state changed for {identity}", {"result": result})
            if item["created"]: created.append(item["event_id"])
        elif state_name in {"DRIFTED", "OWNERSHIP_UNKNOWN", "OWNERSHIP_MISMATCH", "FOREIGN_CONTROLLER", "UNMARKED_EXISTING"}:
            item = _emit(state, "MANAGED_STATE_DRIFT", identity, f"managed-drift:{identity}:{state_name}",
                         f"Managed SSH state requires attention for {identity}", {"state": state_name})
            if item["created"]: created.append(item["event_id"])
        elif result in {"FAILED", "WRITE_FAILED", "WRITE_VERIFICATION_FAILED", "OWNERSHIP_UNPROVEN"}:
            item = _emit(state, "RECONCILE_FAILED", identity, f"reconcile-failed:{identity}:{result}",
                         f"Reconciliation failed for {identity}", {"result": result})
            if item["created"]: created.append(item["event_id"])
    state.commit_events()
    return created
