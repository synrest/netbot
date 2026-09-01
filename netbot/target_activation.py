"""Explicit activation of the Netbot SSH include substrate on one target."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .apply_target import MANAGED_PATH, _remote, resolve_observation_transport

INCLUDE = "Include ~/.ssh/config.d/*"
CONFIG_PATH = "~/.ssh/config"
INSPECT_COMMAND = '''if [ -f "$HOME/.ssh/config" ]; then echo NETBOT_CONFIG_PRESENT; cat "$HOME/.ssh/config"; else echo NETBOT_CONFIG_ABSENT; fi
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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {"managed_path": MANAGED_PATH}


def _parse_inspection(output: str) -> tuple[str, str | None, list[str]]:
    lines = output.splitlines()
    if "NETBOT_CONFIG_ABSENT" in lines:
        config_state, content = "CONFIG_ABSENT", ""
    elif "NETBOT_CONFIG_PRESENT" in lines:
        start = lines.index("NETBOT_CONFIG_PRESENT") + 1
        end = next((i for i in range(start, len(lines)) if lines[i].startswith("NETBOT_CONFIG_D_")), len(lines))
        config_state, content = "CONFIG_PRESENT", "\n".join(lines[start:end]) + ("\n" if end > start else "")
    else:
        return "UNAVAILABLE", "target config inspection was malformed", []
    directory = "NETBOT_CONFIG_D_PRESENT" if "NETBOT_CONFIG_D_PRESENT" in lines else "NETBOT_CONFIG_D_ABSENT"
    names = lines[lines.index(directory) + 1:] if directory in lines else []
    return config_state, content, names


def _include_state(content: str) -> str:
    exact: list[bool] = []
    before_match = True
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("host ", "match ")):
            before_match = False
        if lowered.startswith("include "):
            if line == INCLUDE:
                exact.append(before_match)
            elif before_match:
                return "INCLUDE_MISSING"
    if len(exact) > 1 or (exact and not exact[0]):
        return "INCLUDE_CONFLICT"
    return "ACTIVE" if exact else "INCLUDE_MISSING"


def _inspect(runner, transport):
    result = _remote(runner, transport["alias"], INSPECT_COMMAND, transport_spec=transport.get("spec"))
    if isinstance(result, tuple):
        return "UNAVAILABLE", result[1], ""
    if result.returncode != 0:
        return "UNAVAILABLE", (result.stderr or "target config inspection failed").strip(), ""
    state, content, _ = _parse_inspection(result.stdout or "")
    if state == "UNAVAILABLE":
        return state, content, ""
    return state, None, content


def build_activation_plan(config_path, target_identity: str, *, db_path=None,
                          runner: Callable[..., Any] = subprocess.run) -> TargetActivationPlan:
    spec = resolve_observation_transport(config_path, target_identity, db_path)
    transport = {"alias": target_identity, "spec": spec}
    source = spec.get("source") if spec else "normal-alias"
    state, reason, content = _inspect(runner, transport)
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
    return TargetActivationPlan(target_identity, include, "BLOCKED",
                                reason="existing human SSH config requires explicit operator authorization",
                                transport_source=source, transport_alias=target_identity)


def activate_target(plan: TargetActivationPlan, config_path, *, db_path=None,
                    runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    result = plan.as_dict()
    if plan.action != "CREATE_SUBSTRATE":
        return result
    spec = resolve_observation_transport(config_path, plan.target_identity, db_path)
    if not spec:
        return {**result, "result": "UNAVAILABLE", "reason": "verified target transport unavailable"}
    remote = _remote(runner, plan.target_identity, CREATE_COMMAND, transport_spec=spec)
    if isinstance(remote, tuple) or remote.returncode != 0:
        return {**result, "result": "WRITE_FAILED", "reason": remote[1] if isinstance(remote, tuple) else (remote.stderr or "substrate creation failed").strip()}
    check = _remote(runner, plan.target_identity, "cat \"$HOME/.ssh/config\"", transport_spec=spec)
    if isinstance(check, tuple) or check.returncode != 0 or check.stdout != plan.desired_content:
        return {**result, "result": "WRITE_VERIFICATION_FAILED", "reason": "activation bytes differ"}
    return {**result, "result": "WRITE_VERIFIED"}
