"""Narrow, read-only SSH observation of a managed host."""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from .ssh import effective_config
from ..config import load_topology


ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_AWK_PROVENANCE = r'''
BEGIN { exact = 0; wildcard = 0; includes = 0; invalid = 0 }
{
  line = $0
  sub(/^[ \t]+/, "", line)
  if (line == "" || line ~ /^#/) next
  n = split(line, fields, /[ \t]+/)
  key = tolower(fields[1])
  if (key == "include") { includes = 1; next }
  if (line == "NETBOT_INCLUDE_ERROR") { includes = 1; next }
  if (key == "host") {
    if (n < 2) { invalid = 1; next }
    for (i = 2; i <= n; i++) {
      if (fields[i] == candidate) exact++
      if (fields[i] ~ /[*?!]/) wildcard = 1
    }
  }
}
END {
  print "EXACT " exact
  print "WILDCARD " wildcard
  print "INCLUDE " includes
  print "INVALID " invalid
}
'''


@dataclass(frozen=True)
class RemoteSSHObservation:
    target_identity: str
    transport_alias: str | None
    transport_user: str | None
    transport_port: int | None
    candidate_alias: str
    provenance: str
    effective: dict[str, Any]
    status: str
    reason: str | None = None
    managed_provenance: str = "ABSENT"
    managed_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_alias(alias: str) -> bool:
    return isinstance(alias, str) and bool(ALIAS_RE.fullmatch(alias))


def _quote(value: str) -> str:
    return shlex.quote(value)


def _provenance_command(candidate: str) -> str:
    # This is deliberately a fixed reader: only the user's SSH config and its
    # canonical config.d include are examined.  The shell expansion preserves
    # include position, skips the Netbot-owned file for human provenance, and
    # fails closed for unsupported, unreadable, or cyclic includes.
    awk = _quote(_AWK_PROVENANCE)
    return (
        "if [ -n \"${ZSH_VERSION-}\" ]; then setopt NULL_GLOB; fi; "
        "seen=\"\"; depth_limit=8; "
        "netbot_emit_file() { "
        "file=\"$1\"; depth=\"$2\"; "
        "case \"$file\" in *[![:print:]]*|*[[:space:]]*) printf '%%s\\n' NETBOT_INCLUDE_ERROR; return;; esac; "
        "case \" $seen \" in *\" $file \"*) printf '%%s\\n' NETBOT_INCLUDE_ERROR; return;; esac; "
        "case \"$depth\" in 0|1|2|3|4|5|6|7|8) ;; *) printf '%%s\\n' NETBOT_INCLUDE_ERROR; return;; esac; "
        "[ -r \"$file\" ] || { printf '%%s\\n' NETBOT_INCLUDE_ERROR; return; }; "
        "seen=\"$seen$file \"; "
        "while IFS= read -r raw || [ -n \"$raw\" ]; do "
        "line=\"$raw\"; while [ -n \"$line\" ]; do first=\"${line%%\"${line#?}\"}\"; case \"$first\" in [[:space:]]) line=\"${line#?}\" ;; *) break ;; esac; done; "
        "while [ -n \"$line\" ]; do last=\"${line#\"${line%%?}\"}\"; case \"$last\" in [[:space:]]) line=\"${line%%?}\" ;; *) break ;; esac; done; "
        "case \"$line\" in "
        "'Include ~/.ssh/config.d/*') "
        "for included in \"$HOME/.ssh/config.d\"/*; do "
        "[ -f \"$included\" ] || continue; "
        "case \"${included##*/}\" in 50-netbot.conf) continue;; esac; "
        "netbot_emit_file \"$included\" $((depth + 1)); "
        "done ;; "
        "'Include ~/.ssh/config.d/50-netbot.conf') ;; "
        "Include\\ *) printf '%%s\\n' NETBOT_INCLUDE_ERROR ;; "
        "*) printf '%%s\\n' \"$raw\" ;; "
        "esac; done < \"$file\"; "
        "seen=\"${seen%%$file }\"; "
        "}; "
        "if [ -f \"$HOME/.ssh/config\" ]; then netbot_emit_file \"$HOME/.ssh/config\" 0; "
        "elif [ -d \"$HOME/.ssh/config.d\" ]; then "
        "for file in \"$HOME/.ssh/config.d\"/*; do [ -f \"$file\" ] || continue; "
        "case \"${file##*/}\" in 50-netbot.conf) continue;; esac; netbot_emit_file \"$file\" 0; done; fi | "
        "/usr/bin/awk -v candidate=%s %s"
    ) % (_quote(candidate), awk)


def _managed_provenance_command(candidate: str) -> str:
    """Read only the Netbot-owned SSH fragment for managed ownership."""
    awk = _quote(_AWK_PROVENANCE)
    return (
        "NETBOT_MANAGED_PROVENANCE=1; "
        "if [ -f \"$HOME/.ssh/config.d/50-netbot.conf\" ]; then "
        "/usr/bin/awk -v candidate=%s %s \"$HOME/.ssh/config.d/50-netbot.conf\"; "
        "else printf 'EXACT 0\\nWILDCARD 0\\nINCLUDE 0\\nINVALID 0\\n'; fi"
    ) % (_quote(candidate), awk)


def _parse_effective(output: str) -> tuple[dict[str, Any] | None, str | None]:
    values: dict[str, Any] = {
        "hostname": None,
        "user": None,
        "port": None,
        "proxyjump": None,
        "proxycommand": None,
        "identityfile": [],
    }
    try:
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts
            if key in {"hostname", "user", "proxyjump", "proxycommand"}:
                values[key] = value
            elif key == "port":
                values[key] = int(value)
            elif key == "identityfile":
                values["identityfile"].append(value)
    except (TypeError, ValueError):
        return None, "malformed effective SSH output"
    if not values["hostname"] or not values["user"] or not values["port"]:
        return None, "effective SSH output missing hostname, user, or port"
    return values, None


def _parse_provenance(output: str) -> tuple[str, str | None, dict[str, bool]]:
    counters = {"EXACT": 0, "WILDCARD": 0, "INCLUDE": 0, "INVALID": 0}
    try:
        for line in output.splitlines():
            key, value = line.split(None, 1)
            if key in counters:
                counters[key] = int(value)
    except (ValueError, TypeError):
        return "UNKNOWN", "malformed SSH provenance output", {}
    flags = {key.lower(): bool(value) for key, value in counters.items()}
    if flags["invalid"]:
        return "UNKNOWN", "unparseable SSH config", flags
    if flags["include"]:
        return "UNKNOWN", "SSH config contains unresolved Include", flags
    if counters["EXACT"] > 1:
        return "CONFLICT", "multiple explicit Host blocks claim the alias", flags
    # Pattern blocks may contribute effective values, but they do not remove
    # ownership established by one literal Host claim.
    if counters["EXACT"] == 1:
        return "EXPLICIT", None, flags
    return "ABSENT", None, flags


def _run(
    runner: Callable[..., Any], command: list[str], *, timeout: float
) -> tuple[str | None, str | None]:
    try:
        completed = runner(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "transport timeout"
    except OSError as exc:
        return None, f"transport unavailable: {exc}"
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()
        return None, detail or f"remote command exited {completed.returncode}"
    return completed.stdout, None


def _run_local(runner, command, home):
    import os
    env = os.environ.copy()
    env["HOME"] = home
    try:
        completed = runner(command, text=True, capture_output=True, check=False,
                           timeout=8, env=env)
    except subprocess.TimeoutExpired:
        return None, "local command timeout"
    except OSError as exc:
        return None, f"local command unavailable: {exc}"
    if completed.returncode != 0:
        return None, (completed.stderr or f"local command exited {completed.returncode}").strip()
    return completed.stdout, None


def _transport_command(transport: dict[str, Any], remote_command: str) -> list[str]:
    """Build strict ordinary SSH argv for a verified bootstrap transport."""
    return [
        "ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
        "-i", transport["identity_file"],
        "-o", f"UserKnownHostsFile={transport['known_hosts_file']}",
        f"{transport['user']}@{transport['endpoint']}", remote_command,
    ]


def _inspect_local(target_identity, transport_alias, candidate_alias, runner, home):
    effective_output, reason = _run_local(runner, ["ssh", "-G", candidate_alias], home)
    if reason:
        return RemoteSSHObservation(target_identity, transport_alias, None, None,
                                    candidate_alias, "UNKNOWN", {}, "UNAVAILABLE", reason)
    effective, reason = _parse_effective(effective_output or "")
    if reason:
        return RemoteSSHObservation(target_identity, transport_alias, None, None,
                                    candidate_alias, "UNKNOWN", {}, "INVALID", reason)
    provenance_output, reason = _run_local(
        runner, ["/bin/sh", "-c", _provenance_command(candidate_alias)], home)
    if reason:
        return RemoteSSHObservation(target_identity, transport_alias, effective.get("user"),
                                    effective.get("port"), candidate_alias, "UNKNOWN",
                                    effective, "UNAVAILABLE", reason)
    provenance, reason, _ = _parse_provenance(provenance_output or "")
    status = "OK" if provenance in {"EXPLICIT", "ABSENT"} else provenance
    managed_output, managed_error = _run_local(
        runner, ["/bin/sh", "-c", _managed_provenance_command(candidate_alias)], home)
    if managed_error:
        return RemoteSSHObservation(target_identity, transport_alias, effective.get("user"),
                                    effective.get("port"), candidate_alias, provenance,
                                    effective, "UNAVAILABLE", managed_error)
    managed_provenance, managed_reason, _ = _parse_provenance(managed_output or "")
    if managed_reason and managed_provenance == "UNKNOWN":
        status = "UNKNOWN"
    return RemoteSSHObservation(target_identity, transport_alias, effective.get("user"),
                                effective.get("port"), candidate_alias, provenance,
                                effective, status, reason,
                                managed_provenance=managed_provenance,
                                managed_reason=managed_reason)


def inspect_target(
    config_path: str,
    target_identity: str,
    candidate_alias: str,
    *,
    runner: Callable[..., Any] = subprocess.run,
    transport: dict[str, Any] | None = None,
) -> RemoteSSHObservation:
    """Inspect one candidate alias using a topology-bound SSH connection."""
    if not validate_alias(candidate_alias):
        return RemoteSSHObservation(
            target_identity, None, None, None, candidate_alias, "INVALID", {},
            "INVALID", "invalid candidate alias syntax",
        )
    _, hosts = load_topology(Path(config_path))
    target = next((host for host in hosts if host.identity == target_identity), None)
    target_ssh = target.attrs.get("bindings", {}).get("ssh", {}) if target else {}
    if target is None or not target_ssh.get("aliases"):
        return RemoteSSHObservation(
            target_identity, None, None, None, candidate_alias, "UNKNOWN", {},
            "UNAVAILABLE", "target has no validated SSH binding",
        )
    if candidate_alias not in {
        alias for host in hosts
        for alias in host.attrs.get("bindings", {}).get("ssh", {}).get("aliases", [])
    }:
        return RemoteSSHObservation(
            target_identity, None, None, None, candidate_alias, "INVALID", {},
            "INVALID", "candidate alias is not present in topology bindings",
        )
    if len(target_ssh["aliases"]) != 1:
        return RemoteSSHObservation(
            target_identity, None, None, None, candidate_alias, "UNKNOWN", {},
            "UNAVAILABLE", "target requires exactly one SSH transport alias",
        )

    transport_alias = target_ssh["aliases"][0]
    if transport and transport.get("local"):
        return _inspect_local(target_identity, transport_alias, candidate_alias, runner,
                              transport.get("home", str(Path.home())))
    local = effective_config(transport_alias, runner=runner) if transport is None else {
        "status": "available", "effective": {
            "user": transport.get("user"), "port": transport.get("port", 22)
        }
    }
    if local.get("status") != "available":
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("effective", {}).get("user"),
            local.get("effective", {}).get("port"),
            candidate_alias, "UNKNOWN", {}, "UNAVAILABLE",
            "local SSH binding is unavailable",
        )
    effective_command = "/usr/bin/ssh -G " + _quote(candidate_alias)
    effective_argv = _transport_command(transport, effective_command) if transport else [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1", transport_alias, effective_command,
    ]
    effective_output, reason = _run(runner, effective_argv, timeout=8)
    if reason:
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("effective", {}).get("user"),
            local.get("effective", {}).get("port"),
            candidate_alias, "UNKNOWN", {}, "UNAVAILABLE", reason,
        )
    effective, reason = _parse_effective(effective_output or "")
    if reason:
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("effective", {}).get("user"),
            local.get("effective", {}).get("port"),
            candidate_alias, "UNKNOWN", {}, "INVALID", reason,
        )
    provenance_command = _provenance_command(candidate_alias)
    provenance_argv = _transport_command(transport, provenance_command) if transport else [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1", transport_alias, provenance_command,
    ]
    provenance_output, reason = _run(runner, provenance_argv, timeout=8)
    if reason:
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("user"), local.get("port"),
            candidate_alias, "UNKNOWN", effective or {}, "UNAVAILABLE", reason,
        )
    provenance, reason, _ = _parse_provenance(provenance_output or "")
    status = "OK" if provenance in {"EXPLICIT", "ABSENT"} else provenance
    managed_command = _managed_provenance_command(candidate_alias)
    managed_argv = _transport_command(transport, managed_command) if transport else [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1", transport_alias, managed_command,
    ]
    managed_output, managed_error = _run(runner, managed_argv, timeout=8)
    if managed_error:
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("effective", {}).get("user"),
            local.get("effective", {}).get("port"), candidate_alias, provenance,
            effective or {}, "UNAVAILABLE", managed_error,
        )
    managed_provenance, managed_parse_reason, _ = _parse_provenance(managed_output or "")
    if managed_parse_reason and managed_provenance == "UNKNOWN":
        status = "UNKNOWN"
    return RemoteSSHObservation(
        target_identity, transport_alias, local.get("effective", {}).get("user"),
        local.get("effective", {}).get("port"),
        candidate_alias, provenance, effective or {}, status, reason,
        managed_provenance=managed_provenance, managed_reason=managed_parse_reason,
    )
