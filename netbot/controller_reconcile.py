"""Controller-level orchestration for existing SSH target reconciliation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .apply_target import apply_target, build_apply_plan
from .config import load_topology
from .discovery.remote_ssh import validate_alias
from .state import State


def _eligible(host) -> bool:
    if host.attrs.get("lifecycle") == "retired" or host.attrs.get("superseded_by"):
        return False
    ssh = host.attrs.get("bindings", {}).get("ssh", {})
    aliases = ssh.get("aliases", [])
    return len(aliases) == 1 and validate_alias(aliases[0])


def _target_result(plan, *, dry_run: bool, applied: dict[str, Any] | None = None) -> dict[str, Any]:
    data = plan.as_dict()
    data["result"] = ("NO_CHANGE" if plan.action == "NO_CHANGE" else
                       plan.state if plan.action == "BLOCKED" else
                       (applied or {}).get("result", "PLANNED"))
    data["dry_run"] = dry_run
    if applied:
        data["apply"] = applied
    return data


def reconcile_controller(config_path: Path, db_path: Path, *, target: str | None = None,
                         dry_run: bool = False) -> dict[str, Any]:
    """Observe, plan, and optionally apply existing authorized SSH plans."""
    try:
        _, hosts = load_topology(config_path)
        eligible = [host.identity for host in hosts if _eligible(host)]
        state = State(db_path)
        controller_id = state.controller_identity(create=False)
        state.close()
        if target is not None:
            if target not in eligible:
                return {"controller_id": controller_id, "dry_run": dry_run, "status": "BLOCKED", "targets": [],
                        "summary": {"total": 0, "changed": 0, "unchanged": 0,
                                     "blocked": 1, "unavailable": 0, "failed": 0},
                        "reason": "target is not an active SSH-representable topology identity"}
            eligible = [target]
    except Exception as exc:
        return {"controller_id": None, "dry_run": dry_run, "status": "BLOCKED", "targets": [],
                "summary": {"total": 0, "changed": 0, "unchanged": 0,
                             "blocked": 0, "unavailable": 0, "failed": 1},
                "reason": f"controller reconciliation could not start: {exc}"}

    results = []
    for identity in eligible:
        try:
            plan = build_apply_plan(config_path, identity, db_path=db_path)
            applied = None if dry_run or plan.action in {"BLOCKED", "NO_CHANGE"} else apply_target(plan, config_path)
            results.append(_target_result(plan, dry_run=dry_run, applied=applied))
        except Exception as exc:
            results.append({"target_identity": identity, "state": "FAILED", "action": "BLOCKED",
                            "result": "FAILED", "reason": str(exc), "dry_run": dry_run})

    summary = {"total": len(results), "changed": 0, "unchanged": 0,
               "blocked": 0, "unavailable": 0, "failed": 0}
    for item in results:
        result = item.get("result")
        state_name = item.get("state")
        if result == "NO_CHANGE":
            summary["unchanged"] += 1
        elif state_name in {"TARGET_UNAVAILABLE", "UNAVAILABLE"} or result == "TARGET_UNAVAILABLE":
            summary["unavailable"] += 1
        elif result in {"FAILED", "WRITE_FAILED", "WRITE_VERIFICATION_FAILED", "OWNERSHIP_UNPROVEN"}:
            summary["failed"] += 1
        elif item.get("action") == "BLOCKED":
            summary["blocked"] += 1
        else:
            summary["changed"] += 1
    status = "OK" if not any(summary[key] for key in ("blocked", "unavailable", "failed")) else "PARTIAL"
    return {"controller_id": controller_id, "dry_run": dry_run, "status": status,
            "targets": results, "summary": summary}
