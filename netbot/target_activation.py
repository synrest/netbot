"""Explicit activation of the Netbot SSH include substrate on one target."""

from __future__ import annotations

import subprocess
import hashlib
import shlex
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .apply_target import MANAGED_PATH, _remote, resolve_observation_transport

INCLUDE = "Include ~/.ssh/config.d/*"
CONFIG_PATH = "~/.ssh/config"
INSPECT_COMMAND = '''if [ -L "$HOME/.ssh" ] || [ -L "$HOME/.ssh/config" ]; then exit 43; fi
if [ -e "$HOME/.ssh/config" ] && [ ! -f "$HOME/.ssh/config" ]; then exit 46; fi
if [ -L "$HOME/.ssh/config.d" ]; then exit 44; fi
if [ -e "$HOME/.ssh/config.d" ] && [ ! -d "$HOME/.ssh/config.d" ]; then exit 45; fi
if [ -f "$HOME/.ssh/config" ]; then echo NETBOT_CONFIG_PRESENT; cat "$HOME/.ssh/config"; else echo NETBOT_CONFIG_ABSENT; fi
if [ -d "$HOME/.ssh/config.d" ]; then echo NETBOT_CONFIG_D_PRESENT; ls -1 "$HOME/.ssh/config.d"; else echo NETBOT_CONFIG_D_ABSENT; fi'''
CREATE_COMMAND = '''set -eu
if [ -e "$HOME/.ssh/config" ]; then exit 42; fi
if [ ! -d "$HOME/.ssh" ]; then mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; fi
if [ -e "$HOME/.ssh/config" ]; then exit 42; fi
umask 077
tmp=$(mktemp "$HOME/.ssh/.config.netbot.XXXXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM
printf '%s\n' 'Include ~/.ssh/config.d/*' > "$tmp"
chmod 600 "$tmp"
if [ -e "$HOME/.ssh/config" ]; then exit 42; fi
mv "$tmp" "$HOME/.ssh/config"
trap - EXIT HUP INT TERM
'''


def _insert_command(expected_hash: str, original_hash: str, verify_alias: str | None) -> str:
    alias_check = "true"
    if verify_alias:
        alias = shlex.quote(verify_alias)
        alias_check = f'/usr/bin/ssh -G -F "$HOME/.ssh/config" {alias} >/dev/null 2>&1'
    expected = shlex.quote(expected_hash)
    original = shlex.quote(original_hash)
    return f'''set -eu
if [ -L "$HOME/.ssh" ] || [ -L "$HOME/.ssh/config" ]; then exit 43; fi
if [ ! -f "$HOME/.ssh/config" ]; then exit 42; fi
if [ -e "$HOME/.ssh/config" ] && [ ! -f "$HOME/.ssh/config" ]; then exit 46; fi
if [ -L "$HOME/.ssh/config.d" ]; then exit 44; fi
created_dir=0
if [ ! -d "$HOME/.ssh/config.d" ]; then mkdir -p "$HOME/.ssh/config.d"; chmod 700 "$HOME/.ssh/config.d"; created_dir=1; fi
if [ -e "$HOME/.ssh/config.d" ] && [ ! -d "$HOME/.ssh/config.d" ]; then exit 45; fi
if command -v sha256sum >/dev/null 2>&1; then current_hash=$(sha256sum "$HOME/.ssh/config" | awk '{{print $1}}'); else current_hash=$(shasum -a 256 "$HOME/.ssh/config" | awk '{{print $1}}'); fi
if [ "$current_hash" != {expected} ]; then [ "$created_dir" -eq 0 ] || rmdir "$HOME/.ssh/config.d" 2>/dev/null || true; exit 47; fi
backup=$(mktemp "$HOME/.ssh/.config.netbot.rollback.XXXXXXXX")
tmp=$(mktemp "$HOME/.ssh/.config.netbot.XXXXXXXX")
trap 'rm -f "$tmp" "$backup"' EXIT HUP INT TERM
cp "$HOME/.ssh/config" "$backup"
umask 077
cat > "$tmp"
chmod 600 "$tmp"
if command -v sha256sum >/dev/null 2>&1; then current_hash=$(sha256sum "$HOME/.ssh/config" | awk '{{print $1}}'); else current_hash=$(shasum -a 256 "$HOME/.ssh/config" | awk '{{print $1}}'); fi
if [ "$current_hash" != {expected} ]; then
  [ "$created_dir" -eq 0 ] || rmdir "$HOME/.ssh/config.d" 2>/dev/null || true
  exit 47
fi
mv "$tmp" "$HOME/.ssh/config"
if ! grep -Fqx 'Include ~/.ssh/config.d/*' "$HOME/.ssh/config" || ! {alias_check}; then
  if [ -L "$HOME/.ssh/config" ] || [ ! -f "$HOME/.ssh/config" ]; then exit 51; fi
  if command -v sha256sum >/dev/null 2>&1; then current_hash=$(sha256sum "$HOME/.ssh/config" | awk '{{print $1}}'); else current_hash=$(shasum -a 256 "$HOME/.ssh/config" | awk '{{print $1}}'); fi
  if [ "$current_hash" = {original} ]; then
    [ "$created_dir" -eq 0 ] || rmdir "$HOME/.ssh/config.d" 2>/dev/null || true
    exit 48
  fi
  if [ "$current_hash" != {expected} ]; then exit 50; fi
  restore_tmp=$(mktemp "$HOME/.ssh/.config.netbot.restore.XXXXXXXX")
  cp "$backup" "$restore_tmp"
  chmod 600 "$restore_tmp"
  mv "$restore_tmp" "$HOME/.ssh/config"
  if command -v sha256sum >/dev/null 2>&1; then restored_hash=$(sha256sum "$HOME/.ssh/config" | awk '{{print $1}}'); else restored_hash=$(shasum -a 256 "$HOME/.ssh/config" | awk '{{print $1}}'); fi
  if [ "$restored_hash" != {original} ]; then exit 49; fi
  if ! {alias_check}; then exit 49; fi
  [ "$created_dir" -eq 0 ] || rmdir "$HOME/.ssh/config.d" 2>/dev/null || true
  exit 48
fi
rm -f "$backup"
trap - EXIT HUP INT TERM
'''


@dataclass(frozen=True)
class TargetActivationPlan:
    target_identity: str
    state: str
    action: str
    target_path: str = CONFIG_PATH
    desired_content: str = ""
    reason: str | None = None
    transport_source: str | None = None
    transport_alias: str | None = None
    safety: str | None = None
    authorization: str = "not-required"
    config_d_action: str = "NO_CHANGE"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {"managed_path": MANAGED_PATH}


def _parse_inspection(output: str) -> tuple[str, str | None, list[str], bool]:
    lines = output.splitlines()
    if "NETBOT_CONFIG_ABSENT" in lines:
        config_state, content = "CONFIG_ABSENT", ""
    elif "NETBOT_CONFIG_PRESENT" in lines:
        start = lines.index("NETBOT_CONFIG_PRESENT") + 1
        end = next((i for i in range(start, len(lines)) if lines[i].startswith("NETBOT_CONFIG_D_")), len(lines))
        config_state, content = "CONFIG_PRESENT", "\n".join(lines[start:end]) + ("\n" if end > start else "")
    else:
        return "UNAVAILABLE", "target config inspection was malformed", [], False
    directory = "NETBOT_CONFIG_D_PRESENT" if "NETBOT_CONFIG_D_PRESENT" in lines else "NETBOT_CONFIG_D_ABSENT"
    names = lines[lines.index(directory) + 1:] if directory in lines else []
    return config_state, content, names, directory == "NETBOT_CONFIG_D_PRESENT"


def _include_state(content: str) -> str:
    exact: list[bool] = []
    before_match = True
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith("match "):
            return "INCLUDE_CONFLICT"
        if lowered.startswith("host "):
            before_match = False
        if lowered.startswith("include "):
            if line == INCLUDE:
                exact.append(before_match)
            else:
                return "INCLUDE_CONFLICT"
    if exact and not all(exact):
        return "INCLUDE_CONFLICT"
    return "ACTIVE" if exact else "INCLUDE_MISSING"


def _inspect(runner, transport):
    result = _remote(runner, transport["alias"], INSPECT_COMMAND, transport_spec=transport.get("spec"))
    if isinstance(result, tuple):
        return "UNAVAILABLE", result[1], "", [], False
    if result.returncode != 0:
        return "UNAVAILABLE", (result.stderr or "target config inspection failed").strip(), "", [], False
    state, content, names, directory_present = _parse_inspection(result.stdout or "")
    if state == "UNAVAILABLE":
        return state, content, "", names, directory_present
    return state, None, content, names, directory_present


def build_activation_plan(config_path, target_identity: str, *, db_path=None,
                          runner: Callable[..., Any] = subprocess.run,
                          authorize_existing_config: bool = False) -> TargetActivationPlan:
    spec = resolve_observation_transport(config_path, target_identity, db_path)
    transport = {"alias": target_identity, "spec": spec}
    source = spec.get("source") if spec else "normal-alias"
    state, reason, content, names, directory_present = _inspect(runner, transport)
    if state == "UNAVAILABLE":
        return TargetActivationPlan(target_identity, state, "BLOCKED", reason=reason,
                                    transport_source=source, transport_alias=target_identity)
    if state == "CONFIG_ABSENT":
        return TargetActivationPlan(target_identity, state, "CREATE_SUBSTRATE",
                                    desired_content=INCLUDE + "\n", transport_source=source,
                                    transport_alias=target_identity)
    include = _include_state(content or "")
    if include == "ACTIVE":
        return TargetActivationPlan(target_identity, "ACTIVE", "NO_CHANGE",
                                    transport_source=source, transport_alias=target_identity)
    if include == "INCLUDE_CONFLICT":
        return TargetActivationPlan(target_identity, include, "BLOCKED",
                                    reason="existing SSH config has unsupported or unsafe Include ordering",
                                    transport_source=source, transport_alias=target_identity,
                                    safety="EXISTING_CONFIG_INCLUDE_ORDER_CONFLICT",
                                    authorization="supplied" if authorize_existing_config else "not-supplied")
    if authorize_existing_config:
        desired = INCLUDE + "\n" + (content or "")
        return TargetActivationPlan(target_identity, "READY", "INSERT_INCLUDE",
                                    desired_content=desired,
                                    reason="operator authorized safe top-of-file Include insertion",
                                    transport_source=source, transport_alias=target_identity,
                                    safety="EXISTING_CONFIG_SAFE_FOR_INCLUDE",
                                    authorization="supplied",
                                    config_d_action="CREATE" if not directory_present else "NO_CHANGE")
    return TargetActivationPlan(target_identity, include, "BLOCKED",
                                reason="existing human SSH config requires explicit operator authorization",
                                transport_source=source, transport_alias=target_identity,
                                safety="EXISTING_CONFIG_SAFE_FOR_INCLUDE",
                                authorization="required")


def activate_target(plan: TargetActivationPlan, config_path, *, db_path=None,
                    runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    result = plan.as_dict()
    if plan.action not in {"CREATE_SUBSTRATE", "INSERT_INCLUDE"}:
        return result
    spec = resolve_observation_transport(config_path, plan.target_identity, db_path)
    if not spec:
        return {**result, "result": "UNAVAILABLE", "reason": "verified target transport unavailable"}
    command = CREATE_COMMAND
    if plan.action == "INSERT_INCLUDE":
        original_content = plan.desired_content.split(INCLUDE + "\n", 1)[1]
        current_hash = hashlib.sha256(plan.desired_content.encode()).hexdigest()
        original_hash = hashlib.sha256(original_content.encode()).hexdigest()
        command = _insert_command(current_hash, original_hash, plan.transport_alias)
    remote = _remote(runner, plan.target_identity, command, input_text=plan.desired_content if plan.action == "INSERT_INCLUDE" else None,
                     transport_spec=spec)
    if isinstance(remote, tuple) or remote.returncode != 0:
        remote_code = None if isinstance(remote, tuple) else remote.returncode
        if remote_code == 50:
            return {**result, "result": "ACTIVATION_ROLLBACK_BLOCKED_BY_CONCURRENT_CHANGE",
                    "rollback_state": "ACTIVATION_ROLLBACK_BLOCKED_BY_CONCURRENT_CHANGE",
                    "reason": "rollback refused because human SSH config changed during activation"}
        if remote_code == 49:
            return {**result, "result": "ACTIVATION_ROLLBACK_FAILED",
                    "rollback_state": "ACTIVATION_ROLLBACK_FAILED",
                    "reason": "rollback was attempted but exact restoration or verification failed"}
        return _recover_activation(plan, config_path, db_path, runner,
                                   remote[1] if isinstance(remote, tuple) else (remote.stderr or "substrate creation failed").strip(),
                                   result)
    check = _remote(runner, plan.target_identity, "cat \"$HOME/.ssh/config\"", transport_spec=spec)
    if isinstance(check, tuple) or check.returncode != 0 or check.stdout != plan.desired_content:
        return _recover_activation(plan, config_path, db_path, runner,
                                   "activation bytes differ", result)
    return {**result, "result": "WRITE_VERIFIED"}


def _recover_activation(plan, config_path, db_path, runner, failure_reason, result):
    """Classify an ambiguous activation outcome without mutating the target."""
    spec = resolve_observation_transport(config_path, plan.target_identity, db_path)
    if not spec:
        return {**result, "result": "ACTIVATION_STATE_INDETERMINATE",
                "commit_state": "COMMIT_OUTCOME_UNKNOWN", "reason": failure_reason,
                "recovery": "transport unavailable"}
    state, reason, content, _, _ = _inspect(runner, {"alias": plan.target_identity, "spec": spec})
    expected = plan.desired_content
    if plan.action == "INSERT_INCLUDE":
        original = expected.split(INCLUDE + "\n", 1)[1]
        original_present = state == "CONFIG_PRESENT" and content == original
    else:
        original_present = state == "CONFIG_ABSENT"
    expected_present = state == "CONFIG_PRESENT" and content == expected and _include_state(content) == "ACTIVE"
    if expected_present:
        return {**result, "result": "WRITE_VERIFIED",
                "commit_state": "COMMITTED_AND_VERIFIED",
                "reason": "remote commit completed; recovery observed exact expected activation",
                "recovery": "verified"}
    if original_present:
        return {**result, "result": "WRITE_FAILED",
                "commit_state": "NOT_COMMITTED",
                "reason": failure_reason,
                "recovery": "verified original state restored"}
    return {**result, "result": "ACTIVATION_STATE_INDETERMINATE",
            "commit_state": "COMMIT_OUTCOME_UNKNOWN", "reason": failure_reason,
            "recovery": reason or "recovery observed neither exact original nor expected bytes"}
