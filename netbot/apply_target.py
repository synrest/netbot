"""Ownership-aware, atomic application of one target SSH fragment."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .config import load_topology, load_topology_authority
from .discovery.remote_ssh import validate_alias
from .peer_policy import PolicyValidationError
from .render_target import render_inputs, render_target
from .target_view import SSHView, build_ssh_view


MANAGED_PATH = "~/.ssh/config.d/50-netbot.conf"
READ_COMMAND = 'if [ -f "$HOME/.ssh/config.d/50-netbot.conf" ]; then cat "$HOME/.ssh/config.d/50-netbot.conf"; else exit 3; fi'
REMOVE_COMMAND = 'if [ -f "$HOME/.ssh/config.d/50-netbot.conf" ]; then rm "$HOME/.ssh/config.d/50-netbot.conf"; fi'
WRITE_COMMAND = '''set -eu
if [ ! -d "$HOME/.ssh" ]; then exit 41; fi
mkdir -p "$HOME/.ssh/config.d"
tmp=$(mktemp "$HOME/.ssh/config.d/.50-netbot.XXXXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM
umask 077
cat > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$HOME/.ssh/config.d/50-netbot.conf"
trap - EXIT HUP INT TERM
'''


@dataclass(frozen=True)
class TargetApplyPlan:
    target_identity: str
    state: str
    action: str
    managed_peers: tuple[str, ...] = ()
    human_peers: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    desired_content: str = ""
    current_managed_content: str | None = None
    reason: str | None = None
    transport_alias: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {"managed_path": MANAGED_PATH}


def _transport_alias(config_path, target_identity: str) -> str | None:
    _, hosts = load_topology(config_path)
    target = next((host for host in hosts if host.identity == target_identity), None)
    aliases = target.attrs.get("bindings", {}).get("ssh", {}).get("aliases", []) if target else []
    if len(aliases) != 1 or not validate_alias(aliases[0]):
        return None
    return aliases[0]


def _remote(runner: Callable[..., Any], transport_alias: str, command: str, *, input_text=None):
    try:
        return runner(
            ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
             "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
             "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", transport_alias, command],
            text=True, capture_output=True, check=False, timeout=10,
            **({"input": input_text} if input_text is not None else {}),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)


def _read_managed(runner, transport_alias):
    result = _remote(runner, transport_alias, READ_COMMAND)
    if isinstance(result, tuple):
        return "REMOTE_READ_ERROR", None, result[1]
    if result.returncode == 0:
        return "OK", result.stdout, None
    if result.returncode == 3:
        return "ABSENT", None, None
    return "REMOTE_READ_ERROR", None, (result.stderr or "remote managed-file read failed").strip()


def build_apply_plan(config_path, target_identity: str, *, runner=subprocess.run) -> TargetApplyPlan:
    """Build a complete plan; no remote write is performed."""
    if load_topology_authority(config_path) == target_identity:
        return TargetApplyPlan(target_identity, "LOCAL_TARGET_NOT_IMPLEMENTED", "BLOCKED",
                               reason="local target application is not implemented")
    transport = _transport_alias(config_path, target_identity)
    if transport is None:
        return TargetApplyPlan(target_identity, "SOURCE_ERROR", "BLOCKED",
                               reason="target requires exactly one validated SSH transport alias")
    try:
        view = build_ssh_view(config_path, target_identity, [], runner=runner)
    except PolicyValidationError as exc:
        return TargetApplyPlan(target_identity, "POLICY_ERROR", "BLOCKED", reason=str(exc))
    if view.status in {"POLICY_ABSENT", "INVALID_POLICY", "SOURCE_UNKNOWN", "SOURCE_RETIRED",
                       "SOURCE_SUPERSEDED", "SOURCE_UNBOUND"}:
        return TargetApplyPlan(target_identity, view.status, "BLOCKED", reason=view.reason)
    if view.status == "UNKNOWN":
        return TargetApplyPlan(target_identity, "SOURCE_ERROR", "BLOCKED", reason=view.reason)
    if view.status == "UNAVAILABLE":
        return TargetApplyPlan(target_identity, "TARGET_UNAVAILABLE", "BLOCKED", reason=view.reason)

    conflicts = tuple(f"{item.identity}:{item.reason}" for item in view.relationships
                      if item.state == "CONFLICT")
    if conflicts:
        return TargetApplyPlan(target_identity, "CONFLICT", "BLOCKED", conflicts=conflicts,
                               reason="explicit human/topology SSH conflict blocks apply")
    unknown = tuple(f"{item.identity}:{item.reason}" for item in view.relationships
                    if item.state == "UNKNOWN")
    if unknown:
        return TargetApplyPlan(target_identity, "OWNERSHIP_UNKNOWN", "BLOCKED", conflicts=unknown,
                               reason="SSH ownership could not be proven safely")
    unavailable = tuple(item.identity for item in view.relationships if item.state == "UNAVAILABLE")
    if unavailable:
        return TargetApplyPlan(target_identity, "TARGET_UNAVAILABLE", "BLOCKED", conflicts=unavailable,
                               reason="target SSH observation is unavailable")
    route_failures = tuple(f"{item.identity}:{item.reason}" for item in view.relationships
                           if item.state == "NOT_ROUTABLE_FROM_TARGET")
    if route_failures:
        return TargetApplyPlan(target_identity, "RENDER_ERROR", "BLOCKED", conflicts=route_failures,
                               reason="expected peer has no safe desired route")

    rendered = render_target(config_path, target_identity)
    if rendered.state != "RENDERABLE":
        return TargetApplyPlan(target_identity, "RENDER_ERROR", "BLOCKED", reason=rendered.reason,
                               managed_peers=tuple(item.identity for item in view.relationships
                                                   if item.state in {"MISSING", "VALID_MANAGED"}))
    human = tuple(sorted(item.identity for item in view.relationships if item.state == "VALID_MANUAL"))
    managed = tuple(sorted(item.identity for item in view.relationships
                           if item.state in {"MISSING", "VALID_MANAGED"} and item.provenance in {"ABSENT", "MANAGED"}))
    managed_aliases = {item.alias for item in rendered.inputs if item.identity in managed and item.state == "RENDERABLE"}
    desired = render_inputs(tuple(item for item in rendered.inputs if item.alias in managed_aliases))
    read_state, current, reason = _read_managed(runner, transport)
    if read_state == "REMOTE_READ_ERROR":
        return TargetApplyPlan(target_identity, "REMOTE_READ_ERROR", "BLOCKED", managed_peers=managed,
                               human_peers=human, desired_content=desired, reason=reason)
    if not desired:
        action = "REMOVE" if current is not None else "NO_CHANGE"
    elif current is None:
        action = "CREATE"
    elif current != desired:
        action = "REPLACE"
    else:
        action = "NO_CHANGE"
    return TargetApplyPlan(target_identity, "READY", action, managed, human, (), desired, current,
                           transport_alias=transport)


def apply_target(plan: TargetApplyPlan, config_path=None, *, runner=subprocess.run) -> dict[str, Any]:
    """Apply a previously built plan and verify bytes and target view."""
    result = plan.as_dict()
    if plan.action == "BLOCKED":
        return result
    if plan.action == "NO_CHANGE":
        result.update({"result": "NO_CHANGE", "verification": "NOT_NEEDED"})
        return result
    transport = plan.transport_alias
    if not transport:
        return {**result, "result": "REMOTE_READ_ERROR", "reason": "missing target transport"}
    command = REMOVE_COMMAND if plan.action == "REMOVE" else WRITE_COMMAND
    remote = _remote(runner, transport, command, input_text=None if plan.action == "REMOVE" else plan.desired_content)
    if isinstance(remote, tuple) or remote.returncode != 0:
        return {**result, "result": "WRITE_FAILED", "reason": remote[1] if isinstance(remote, tuple) else (remote.stderr or "remote write failed").strip()}
    read_state, current, reason = _read_managed(runner, transport)
    verified = (plan.action == "REMOVE" and read_state == "ABSENT") or \
               (plan.action != "REMOVE" and read_state == "OK" and current == plan.desired_content)
    if not verified:
        return {**result, "result": "WRITE_VERIFICATION_FAILED", "reason": reason or "managed file bytes differ"}
    if config_path is None:
        return {**result, "result": "WRITE_VERIFIED", "view_verification": "NOT_RUN"}
    view = build_ssh_view(config_path, plan.target_identity, [], runner=runner)
    if view.status == "UNAVAILABLE":
        return {**result, "result": "WRITE_VERIFIED", "view_verification": "VIEW_UNAVAILABLE",
                "view_reason": view.reason}
    return {**result, "result": "WRITE_VERIFIED", "view_verification": "VIEW_VERIFIED",
            "post_view": view.as_dict()}
