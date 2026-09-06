"""Ownership-aware, atomic application of one target SSH fragment."""

from __future__ import annotations

import subprocess
import json
import tempfile
import atexit
import os
import hashlib
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable

from .config import load_topology, load_topology_authority
from .discovery.remote_ssh import validate_alias
from .peer_policy import PolicyValidationError
from .render_target import render_inputs, render_target
from .target_view import SSHView, build_ssh_view


MANAGED_PATH = "~/.ssh/config.d/50-netbot.conf"
MANAGED_MARKER = "# netbot-managed: ssh-topology"
CONTROLLER_MARKER = "# netbot-controller: "
READ_COMMAND = 'if [ -L "$HOME/.ssh" ]; then exit 43; fi; if [ -L "$HOME/.ssh/config.d" ]; then exit 44; fi; if [ -L "$HOME/.ssh/config.d/50-netbot.conf" ]; then exit 45; fi; if [ -e "$HOME/.ssh/config.d/50-netbot.conf" ] && [ ! -f "$HOME/.ssh/config.d/50-netbot.conf" ]; then exit 46; fi; if [ -f "$HOME/.ssh/config.d/50-netbot.conf" ]; then cat "$HOME/.ssh/config.d/50-netbot.conf"; else exit 3; fi'
REMOVE_COMMAND = 'if [ -f "$HOME/.ssh/config.d/50-netbot.conf" ]; then rm "$HOME/.ssh/config.d/50-netbot.conf"; fi'
WRITE_COMMAND = '''set -eu
if [ ! -d "$HOME/.ssh" ]; then exit 41; fi
if [ -L "$HOME/.ssh" ]; then exit 43; fi
if [ -L "$HOME/.ssh/config.d" ]; then exit 44; fi
mkdir -p "$HOME/.ssh/config.d"
if [ -L "$HOME/.ssh/config.d/50-netbot.conf" ]; then exit 45; fi
if [ -e "$HOME/.ssh/config.d/50-netbot.conf" ] && [ ! -f "$HOME/.ssh/config.d/50-netbot.conf" ]; then exit 46; fi
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
    transport_spec: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("transport_spec", None)
        return result | {"managed_path": MANAGED_PATH}


def _transport_alias(config_path, target_identity: str) -> str | None:
    _, hosts = load_topology(config_path)
    target = next((host for host in hosts if host.identity == target_identity), None)
    aliases = target.attrs.get("bindings", {}).get("ssh", {}).get("aliases", []) if target else []
    if len(aliases) != 1 or not validate_alias(aliases[0]):
        return None
    return aliases[0]


def _remote(runner: Callable[..., Any], transport_alias: str, command: str, *, input_text=None,
            transport_spec: dict[str, Any] | None = None):
    temporary = None
    try:
        if transport_spec and transport_spec.get("local"):
            env = os.environ.copy()
            env["HOME"] = transport_spec.get("home", str(Path.home()))
            return runner(["/bin/sh", "-c", command], env=env, text=True,
                          capture_output=True, check=False, timeout=10,
                          **({"input": input_text} if input_text is not None else {}))
        if transport_spec:
            temporary = tempfile.NamedTemporaryFile("w", prefix="netbot-bootstrap-known-hosts-", delete=True)
            for key in transport_spec["host_keys"]:
                temporary.write(f"{transport_spec['endpoint']} {key['key_type']} {key['key_data']}\n")
            temporary.flush()
            argv = ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                    "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
                    "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
                    "-i", transport_spec["identity_file"],
                    "-o", f"UserKnownHostsFile={temporary.name}",
                    f"{transport_spec['user']}@{transport_spec['endpoint']}", command]
        else:
            argv = ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                    "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
                    "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", transport_alias, command]
        return runner(
            argv,
            text=True, capture_output=True, check=False, timeout=10,
            **({"input": input_text} if input_text is not None else {}),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    finally:
        if temporary is not None:
            temporary.close()


def _read_managed(runner, transport_alias, transport_spec=None):
    result = _remote(runner, transport_alias, READ_COMMAND, transport_spec=transport_spec)
    if isinstance(result, tuple):
        return "REMOTE_READ_ERROR", None, result[1]
    if result.returncode == 0:
        return "OK", result.stdout, None
    if result.returncode == 3:
        return "ABSENT", None, None
    return "REMOTE_READ_ERROR", None, (result.stderr or "remote managed-file read failed").strip()


def _state_path(config_path):
    return Path(config_path).parent.parent / "state" / "netbot.sqlite3"


def _ownership_state(config_path, target_identity, current, target_node_id=None, *, create_identity=False, db_path=None):
    from .state import State
    state = State(Path(db_path) if db_path else _state_path(config_path))
    record = state.managed_ssh_ownership(target_identity)
    controller_id = state.controller_identity(create=create_identity)
    state.close()
    if current is None:
        return "ABSENT", record, controller_id
    lines = (current.splitlines() if current is not None else [])
    marker = next((line[len(CONTROLLER_MARKER):].strip() for line in lines if line.startswith(CONTROLLER_MARKER)), None)
    marked = MANAGED_MARKER in lines and marker
    digest = hashlib.sha256(current.encode()).hexdigest()
    current_node_id = str(target_node_id) if target_node_id is not None else None
    record_matches = bool(record and controller_id and
                          record.get("controller_id") == controller_id and
                          record.get("managed_path") == MANAGED_PATH and
                          record.get("target_identity") == target_identity and
                          (str(record.get("target_node_id")) if record.get("target_node_id") is not None else None) == current_node_id)
    if not marked:
        if record_matches and record.get("content_hash") == digest:
            return "OWNED", record, controller_id
        if record_matches:
            return "DRIFTED", record, controller_id
        return "UNMARKED_EXISTING", record, controller_id
    if controller_id and marker != controller_id:
        return "FOREIGN_CONTROLLER", record, controller_id
    if not record:
        return "UNCLAIMED_MARKED", record, controller_id
    recorded_node_id = record.get("target_node_id")
    if (record.get("controller_id") != marker or record.get("managed_path") != MANAGED_PATH or
            record.get("target_identity") != target_identity or recorded_node_id != current_node_id):
        return "OWNERSHIP_MISMATCH", record, controller_id
    if record.get("content_hash") != digest:
        return "DRIFTED", record, controller_id
    return "OWNED", record, controller_id


def _managed_content(controller_id, content):
    return f"{MANAGED_MARKER}\n{CONTROLLER_MARKER}{controller_id}\n" + content


def _managed_identity_files(content: str | None) -> dict[str, str]:
    """Read only explicit per-alias IdentityFile metadata from the fragment."""
    result: dict[str, str] = {}
    alias = None
    for raw in (content or "").splitlines():
        line = raw.strip()
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip()
        if key == "host" and "*" not in value and "?" not in value:
            alias = value
        elif key == "identityfile" and alias and value:
            result[alias] = value
    return result


def resolve_observation_transport(config_path, target_identity: str, db_path=None) -> dict[str, Any] | None:
    """Load only a positively verified ordinary-SSH bootstrap handoff."""
    if load_topology_authority(config_path) == target_identity:
        return {"local": True, "home": str(Path.home()), "source": "local-filesystem"}
    _, hosts = load_topology(config_path)
    target = next((host for host in hosts if host.identity == target_identity), None)
    if target is None:
        return None
    ssh = target.attrs.get("bindings", {}).get("ssh", {})
    tailscale = target.attrs.get("bindings", {}).get("tailscale", {})
    user = ssh.get("user")
    endpoint = tailscale.get("name")
    if not user or not endpoint:
        return None
    db = Path(db_path) if db_path else Path(config_path).parent.parent / "state" / "netbot.sqlite3"
    try:
        from .state import State
        state = State(db)
        observation = state.latest_bootstrap_observation(target_identity, tailscale.get("node_id"))
        state.close()
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    ordinary = (observation or {}).get("ordinary_ssh", {})
    keys = (observation or {}).get("host_key_material")
    if ((observation or {}).get("state") != "managed" or
            ordinary.get("success") is not True or ordinary.get("user") != user or
            ordinary.get("host_key_state") != "match" or not isinstance(keys, list) or not keys):
        return None
    identity_file = Path.home() / ".ssh" / "id_ed25519_arasaka"
    if not identity_file.is_file():
        return None
    known_hosts = tempfile.NamedTemporaryFile("w", prefix="netbot-bootstrap-known-hosts-", delete=False)
    for key in keys:
        if not isinstance(key, dict) or not key.get("key_type") or not key.get("key_data"):
            known_hosts.close(); os.unlink(known_hosts.name); return None
        known_hosts.write(f"{endpoint} {key['key_type']} {key['key_data']}\n")
    known_hosts.close()
    atexit.register(lambda path=known_hosts.name: os.path.exists(path) and os.unlink(path))
    return {"endpoint": endpoint, "user": user, "port": 22,
            "identity_file": str(identity_file), "known_hosts_file": known_hosts.name,
            "host_keys": keys, "source": "verified-bootstrap-ordinary-ssh"}


def build_apply_plan(config_path, target_identity: str, *, runner=subprocess.run, db_path=None) -> TargetApplyPlan:
    """Build a complete plan; no remote write is performed."""
    transport = _transport_alias(config_path, target_identity)
    if transport is None:
        return TargetApplyPlan(target_identity, "SOURCE_ERROR", "BLOCKED",
                               reason="target requires exactly one validated SSH transport alias")
    bootstrap_transport = resolve_observation_transport(config_path, target_identity, db_path)
    try:
        view = build_ssh_view(config_path, target_identity, runner=runner, transport=bootstrap_transport)
    except PolicyValidationError as exc:
        return TargetApplyPlan(target_identity, "POLICY_ERROR", "BLOCKED", reason=str(exc))
    if view.status in {"POLICY_ABSENT", "INVALID_POLICY", "SOURCE_UNKNOWN", "SOURCE_RETIRED",
                       "SOURCE_SUPERSEDED", "SOURCE_UNBOUND"}:
        return TargetApplyPlan(target_identity, view.status, "BLOCKED", reason=view.reason,
                               transport_alias=transport, transport_spec=bootstrap_transport)
    if view.status == "UNKNOWN":
        return TargetApplyPlan(target_identity, "SOURCE_ERROR", "BLOCKED", reason=view.reason,
                               transport_alias=transport, transport_spec=bootstrap_transport)
    if view.status == "UNAVAILABLE":
        return TargetApplyPlan(target_identity, "TARGET_UNAVAILABLE", "BLOCKED", reason=view.reason,
                               transport_alias=transport, transport_spec=bootstrap_transport)

    read_state, current, reason = _read_managed(runner, transport, bootstrap_transport)
    if read_state == "REMOTE_READ_ERROR":
        return TargetApplyPlan(target_identity, "REMOTE_READ_ERROR", "BLOCKED", reason=reason,
                               transport_alias=transport, transport_spec=bootstrap_transport)
    preserved_identity_files = _managed_identity_files(current)
    rendered = render_target(config_path, target_identity)
    if rendered.state != "RENDERABLE":
        return TargetApplyPlan(target_identity, "RENDER_ERROR", "BLOCKED", reason=rendered.reason,
                               managed_peers=tuple(item.identity for item in view.relationships
                                                   if item.state in {"MISSING", "VALID_MANAGED"}),
                               transport_alias=transport, transport_spec=bootstrap_transport)
    # An explicit human relationship may remain UNKNOWN/CONFLICT without
    # making an unrelated managed alias unsafe: it is never copied into the
    # managed fragment. Ambiguous managed/topology claims still block.
    conflicts = tuple(f"{item.identity}:{item.reason}" for item in view.relationships
                      if item.state == "CONFLICT" and item.provenance != "EXPLICIT")
    if conflicts:
        return TargetApplyPlan(target_identity, "CONFLICT", "BLOCKED", conflicts=conflicts,
                               reason="explicit human/topology SSH conflict blocks apply",
                               transport_alias=transport, transport_spec=bootstrap_transport)
    unknown = tuple(f"{item.identity}:{item.reason}" for item in view.relationships
                    if item.state == "UNKNOWN" and item.provenance != "EXPLICIT")
    if unknown:
        return TargetApplyPlan(target_identity, "OWNERSHIP_UNKNOWN", "BLOCKED", conflicts=unknown,
                               reason="SSH ownership could not be proven safely",
                               transport_alias=transport, transport_spec=bootstrap_transport)
    unavailable = tuple(item.identity for item in view.relationships if item.state == "UNAVAILABLE")
    if unavailable:
        return TargetApplyPlan(target_identity, "TARGET_UNAVAILABLE", "BLOCKED", conflicts=unavailable,
                               reason="target SSH observation is unavailable", transport_alias=transport,
                               transport_spec=bootstrap_transport)
    route_failures = tuple(f"{item.identity}:{item.reason}" for item in view.relationships
                           if item.state == "NOT_ROUTABLE_FROM_TARGET")
    if route_failures:
        return TargetApplyPlan(target_identity, "RENDER_ERROR", "BLOCKED", conflicts=route_failures,
                               reason="expected peer has no safe desired route", transport_alias=transport,
                               transport_spec=bootstrap_transport)

    human = tuple(sorted(item.identity for item in view.relationships if item.state == "VALID_MANUAL"))
    managed = tuple(sorted(item.identity for item in view.relationships
                           if item.state in {"MISSING", "VALID_MANAGED"} and item.provenance in {"ABSENT", "MANAGED"}))
    managed_aliases = {item.alias for item in rendered.inputs if item.identity in managed and item.state == "RENDERABLE"}
    desired_inputs = tuple(replace(item, identity_file=item.identity_file or preserved_identity_files.get(item.alias))
                           for item in rendered.inputs if item.alias in managed_aliases)
    desired = render_inputs(desired_inputs)
    target_node_id = next((host.attrs.get("bindings", {}).get("tailscale", {}).get("node_id")
                           for host in load_topology(config_path)[1] if host.identity == target_identity), None)
    ownership, record, controller_id = _ownership_state(config_path, target_identity, current, target_node_id, db_path=db_path)
    if current is None and controller_id is None:
        controller_id = "unprovisioned"
    if desired:
        desired = _managed_content(controller_id, desired)
    if current is not None and ownership != "OWNED" and desired != current:
        return TargetApplyPlan(target_identity, ownership, "BLOCKED", managed_peers=managed,
                               human_peers=human, desired_content=desired, current_managed_content=current,
                               reason="managed SSH file ownership is not proven for this controller",
                               transport_alias=transport, transport_spec=bootstrap_transport)
    if not desired:
        action = "REMOVE" if current is not None else "NO_CHANGE"
    elif current is None:
        action = "CREATE"
    elif current != desired:
        action = "REPLACE"
    else:
        action = "NO_CHANGE"
    if action == "REMOVE" and ownership != "OWNED":
        return TargetApplyPlan(target_identity, ownership, "BLOCKED", managed_peers=managed,
                               human_peers=human, current_managed_content=current,
                               reason="managed SSH file ownership is not proven for this controller",
                               transport_alias=transport, transport_spec=bootstrap_transport)
    return TargetApplyPlan(target_identity, "READY", action, managed, human, (), desired, current,
                           transport_alias=transport, transport_spec=bootstrap_transport)


def apply_target(plan: TargetApplyPlan, config_path=None, *, runner=subprocess.run) -> dict[str, Any]:
    """Apply a previously built plan and verify bytes and target view."""
    result = plan.as_dict()
    if plan.action == "BLOCKED":
        return result
    if plan.action == "NO_CHANGE":
        result.update({"result": "NO_CHANGE", "verification": "NOT_NEEDED"})
        return result
    if (plan.desired_content.startswith(MANAGED_MARKER + "\n") and
            CONTROLLER_MARKER + "unprovisioned\n" in plan.desired_content):
        from .state import State
        state = State(_state_path(config_path)); controller_id = state.controller_identity(create=True); state.close()
        plan = replace(plan, desired_content=plan.desired_content.replace(
            MANAGED_MARKER + "\n" + CONTROLLER_MARKER + "unprovisioned\n",
            MANAGED_MARKER + "\n" + CONTROLLER_MARKER + controller_id + "\n", 1))
    result = plan.as_dict()
    transport = plan.transport_alias
    if not transport:
        return {**result, "result": "REMOTE_READ_ERROR", "reason": "missing target transport"}
    command = REMOVE_COMMAND if plan.action == "REMOVE" else WRITE_COMMAND
    remote = _remote(runner, transport, command, input_text=None if plan.action == "REMOVE" else plan.desired_content,
                     transport_spec=plan.transport_spec)
    if isinstance(remote, tuple) or remote.returncode != 0:
        return {**result, "result": "WRITE_FAILED", "reason": remote[1] if isinstance(remote, tuple) else (remote.stderr or "remote write failed").strip()}
    read_state, current, reason = _read_managed(runner, transport, plan.transport_spec)
    verified = (plan.action == "REMOVE" and read_state == "ABSENT") or \
               (plan.action != "REMOVE" and read_state == "OK" and current == plan.desired_content)
    if not verified:
        return {**result, "result": "WRITE_VERIFICATION_FAILED", "reason": reason or "managed file bytes differ"}
    if plan.action != "REMOVE":
        from .state import State
        target_node_id = next((host.attrs.get("bindings", {}).get("tailscale", {}).get("node_id")
                               for host in load_topology(config_path)[1] if host.identity == plan.target_identity), None)
        controller_id = next((line[len(CONTROLLER_MARKER):].strip() for line in plan.desired_content.splitlines()
                              if line.startswith(CONTROLLER_MARKER)), None)
        try:
            state = State(_state_path(config_path))
            state.save_managed_ssh_ownership(plan.target_identity, controller_id, MANAGED_PATH,
                                             target_node_id, hashlib.sha256(plan.desired_content.encode()).hexdigest(),
                                             datetime.now(timezone.utc).isoformat())
            state.close()
        except Exception as exc:
            return {**result, "result": "OWNERSHIP_UNPROVEN", "reason": f"managed write verified but ownership persistence failed: {exc}"}
    else:
        from .state import State
        state = State(_state_path(config_path)); state.remove_managed_ssh_ownership(plan.target_identity); state.close()
    if config_path is None:
        return {**result, "result": "WRITE_VERIFIED", "view_verification": "NOT_RUN"}
    view = build_ssh_view(config_path, plan.target_identity, runner=runner, transport=plan.transport_spec)
    if view.status == "UNAVAILABLE":
        return {**result, "result": "WRITE_VERIFIED", "view_verification": "VIEW_UNAVAILABLE",
                "view_reason": view.reason}
    return {**result, "result": "WRITE_VERIFIED", "view_verification": "VIEW_VERIFIED",
            "post_view": view.as_dict()}
