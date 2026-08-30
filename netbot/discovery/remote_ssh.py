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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_alias(alias: str) -> bool:
    return isinstance(alias, str) and bool(ALIAS_RE.fullmatch(alias))


def _quote(value: str) -> str:
    return shlex.quote(value)


def _provenance_command(candidate: str) -> str:
    # This is deliberately a fixed reader: only the expected SSH config paths
    # are examined, and the candidate is data passed through awk -v.
    awk = _quote(_AWK_PROVENANCE)
    return (
        "set --; "
        "if [ -f \"$HOME/.ssh/config\" ]; then set -- \"$@\" \"$HOME/.ssh/config\"; fi; "
        "if [ -d \"$HOME/.ssh/config.d\" ]; then "
        "for file in \"$HOME/.ssh/config.d\"/*; do "
        "[ -f \"$file\" ] || continue; "
        "case \"${file##*/}\" in 50-netbot.conf*) continue;; esac; "
        "set -- \"$@\" \"$file\"; "
        "done; fi; "
        "/usr/bin/awk -v candidate=%s %s \"$@\""
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


def inspect_target(
    config_path: str,
    target_identity: str,
    candidate_alias: str,
    *,
    runner: Callable[..., Any] = subprocess.run,
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
    local = effective_config(transport_alias, runner=runner)
    if local.get("status") != "available":
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("effective", {}).get("user"),
            local.get("effective", {}).get("port"),
            candidate_alias, "UNKNOWN", {}, "UNAVAILABLE",
            "local SSH binding is unavailable",
        )
    effective_output, reason = _run(
        runner,
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1", transport_alias,
            "/usr/bin/ssh -G " + _quote(candidate_alias),
        ],
        timeout=8,
    )
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
    provenance_output, reason = _run(
        runner,
        [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1", transport_alias,
            _provenance_command(candidate_alias),
        ],
        timeout=8,
    )
    if reason:
        return RemoteSSHObservation(
            target_identity, transport_alias, local.get("user"), local.get("port"),
            candidate_alias, "UNKNOWN", effective or {}, "UNAVAILABLE", reason,
        )
    provenance, reason, _ = _parse_provenance(provenance_output or "")
    status = "OK" if provenance in {"EXPLICIT", "ABSENT"} else provenance
    return RemoteSSHObservation(
        target_identity, transport_alias, local.get("effective", {}).get("user"),
        local.get("effective", {}).get("port"),
        candidate_alias, provenance, effective or {}, status, reason,
    )
