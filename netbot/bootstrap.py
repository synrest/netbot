"""Deterministic bootstrap planning and safe command primitives."""

from __future__ import annotations

import re
import subprocess
import json
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable

from .authority import AUTHORITY_MANAGE, AUTHORITY_MAINTAIN, AUTHORITY_OBSERVE
from .tailscale_prefs import TailscalePreferenceObserver

BOOTSTRAP_STATES = (
    "discovered", "bootstrap_candidate", "bootstrap_authenticated",
    "public_key_installed", "openssh_prepared", "bootstrap_teardown_ready",
    "bootstrap_disabled", "bootstrap_teardown_blocked", "authorization_required", "openssh_verified",
    "managed",
)

BOOTSTRAP_PROVIDERS = ("infrastructure", "personal", "unknown")

BOOTSTRAP_TRANSITIONS = {
    "discovered": "bootstrap_candidate",
    "bootstrap_candidate": "bootstrap_authenticated",
    "bootstrap_authenticated": "public_key_installed",
    "public_key_installed": "openssh_prepared",
    "openssh_prepared": "bootstrap_teardown_ready",
    "bootstrap_teardown_ready": "bootstrap_disabled",
    "bootstrap_disabled": "openssh_verified",
    "openssh_verified": "managed",
}


@dataclass(frozen=True)
class Eligibility:
    state: str
    source: str
    evidence: str


def bootstrap_eligibility(node: Any, tag: str = "tag:netbot-bootstrap") -> Eligibility:
    raw = getattr(node, "raw", {}) or {}
    tags = raw.get("Tags", raw.get("tags", raw.get("AdvertisedTags")))
    if tags is None:
        return Eligibility("unknown", "Tailscale peer data", "peer tags unavailable")
    return (Eligibility("eligible", "observed Tailscale peer tag", tag)
            if tag in tags else Eligibility("ineligible", "observed Tailscale peer tags", "tag absent"))


def bootstrap_provider(node: Any, tag: str = "tag:netbot-bootstrap") -> dict[str, str]:
    """Classify a bootstrap lane only from explicit observed evidence.

    Absence of a tag is deliberately not enough to classify a peer as a
    personal candidate.  The Tailscale status payload must identify a user
    owner for that classification; otherwise the result is unknown.
    """
    raw = getattr(node, "raw", {}) or {}
    tags = raw.get("Tags", raw.get("tags", raw.get("AdvertisedTags")))
    owner = raw.get("User", raw.get("UserID", raw.get("ManagedBy")))
    if tags is not None and tag in tags:
        return {"provider": "infrastructure", "state": "candidate", "source": "observed Tailscale tag"}
    if owner and (tags is None or not tags):
        return {"provider": "personal", "state": "candidate", "source": "observed user-owned Tailscale node"}
    if tags is None:
        return {"provider": "unknown", "state": "unknown", "source": "Tailscale identity evidence unavailable"}
    return {"provider": "unknown", "state": "ineligible", "source": "no explicit bootstrap provider evidence"}


def bootstrap_authentication_outcome(returncode: int, output: str = "") -> dict[str, str]:
    """Normalize Tailscale SSH bootstrap outcomes without collapsing causes."""
    text = (output or "").lower()
    if returncode == 0:
        return {"state": "authenticated", "source": "Tailscale SSH command result"}
    if ("check" in text or "browser" in text or "reauth" in text) and ("browser" in text or "reauth" in text or "authorize" in text):
        return {"state": "check-human-authentication-required", "source": "Tailscale SSH result"}
    if "policy" in text and ("permit" in text or "denied" in text or "deny" in text):
        return {"state": "policy-denied", "source": "Tailscale SSH result"}
    if "permission denied" in text or "authentication" in text:
        return {"state": "authentication-failed", "source": "Tailscale SSH result"}
    if "could not resolve" in text or "timed out" in text or "unreachable" in text:
        return {"state": "unreachable", "source": "Tailscale SSH result"}
    return {"state": "command-failure", "source": "Tailscale SSH result"}


def adoption_decision(*, identity: str | None, identity_status: str, ordinary_openssh: dict[str, Any] | None, tailscale_ssh: dict[str, Any] | None, intended_user: str | None, host_key_state: str = "unknown") -> dict[str, Any]:
    """Choose adoption before bootstrap, using observed access evidence only."""
    if identity_status in {"ambiguous", "conflict"}:
        return {"state": "ambiguous", "reason": "topology identity evidence is ambiguous"}
    if not identity:
        return {"state": "discovered_blocked", "reason": "no durable topology binding"}
    if not intended_user:
        return {"state": "discovered_blocked", "reason": "intended Unix user unknown"}
    ordinary = ordinary_openssh or {}
    if ordinary.get("result") in {"reachable-authenticated", "authenticated"}:
        if host_key_state in {"HOST_KEY_MISMATCH", "host-key-conflict"}:
            return {"state": "ambiguous", "reason": "ordinary OpenSSH host-key conflict"}
        return {"state": "managed_existing_openssh", "authority": AUTHORITY_OBSERVE, "source": "verified ordinary OpenSSH", "bootstrap_required": False, "netbot_key_required": False}
    ts = tailscale_ssh or {}
    if ts.get("result") in {"authenticated", "reachable-authenticated"} and ts.get("eligible") is True:
        return {"state": "bootstrap_candidate", "authority": AUTHORITY_OBSERVE, "source": "eligible Tailscale SSH", "bootstrap_required": True}
    if ordinary.get("result") in {"network-reachable-authentication-failed", "host-key-verification-problem", "connection-refused", "timeout/unreachable", "name-resolution-failure"}:
        reason = f"ordinary OpenSSH: {ordinary['result']}"
    elif ordinary.get("result") in {"unknown", "unknown-error", None}:
        reason = "ordinary OpenSSH not verified"
    else:
        reason = f"ordinary OpenSSH: {ordinary.get('result')}"
    if ts.get("eligible") is True and ts.get("result") in {"policy-denied", "check_required", "unavailable", "unknown", None}:
        reason += "; eligible Tailscale SSH not authenticated"
    return {"state": "discovered_blocked", "authority": AUTHORITY_OBSERVE, "source": "access-path observations", "reason": reason, "bootstrap_required": False}


def validate_bootstrap_user(user: str | None) -> dict[str, Any]:
    if not user or not user.strip():
        return {"state": "unknown", "user": None, "reason": "explicit Unix user is required"}
    if any(ch.isspace() for ch in user) or user.startswith("-"):
        return {"state": "invalid", "user": user, "reason": "invalid Unix user value"}
    return {"state": "known", "user": user, "source": "explicit bootstrap configuration/argument"}


def bootstrap_state_for(eligibility: Eligibility, online: bool | None) -> str:
    return "bootstrap_candidate" if eligibility.state == "eligible" and online is True else "discovered"


def tailscale_ssh_command(host: str, user: str, remote_command: str) -> list[str]:
    return ["tailscale", "ssh", f"{user}@{host}", remote_command]


def managed_key_line(public_key: str, controller_id: str) -> str:
    fields = public_key.strip().split()
    if len(fields) < 2 or not fields[0].startswith(("ssh-", "ecdsa-")):
        raise ValueError("invalid public SSH key")
    return f"{fields[0]} {fields[1]} netbot:controller:{controller_id}"


def classify_managed_keys(lines: list[str], expected_line: str, controller_id: str) -> dict[str, Any]:
    marker = f"netbot:controller:{controller_id}"
    marked = [line.strip() for line in lines if marker in line]
    exact = [line for line in marked if line == expected_line]
    conflicts = [line for line in marked if line != expected_line]
    if conflicts:
        state = "conflict"
    elif len(exact) > 1:
        state = "duplicate"
    elif exact:
        state = "present"
    else:
        state = "absent"
    return {"state": state, "managed_count": len(exact), "conflict_count": len(conflicts), "marker": marker}


def managed_key_install_command() -> str:
    return r'''set -eu
umask 077
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
key=$(cat)
case "$key" in
  ssh-*\ *\ netbot:controller:*|ecdsa-*\ *\ netbot:controller:*) ;;
  *) echo invalid-managed-key >&2; exit 2 ;;
esac
marker=$(printf '%s\n' "$key" | awk '{print $3}')
if grep -Fqx "$key" "$HOME/.ssh/authorized_keys" 2>/dev/null; then result=already-present
elif grep -Fq "$marker" "$HOME/.ssh/authorized_keys" 2>/dev/null; then echo managed-key-conflict >&2; exit 3
else printf '%s\n' "$key" >> "$HOME/.ssh/authorized_keys"; result=appended; fi
chmod 600 "$HOME/.ssh/authorized_keys"
printf 'managed-key=%s\nmanaged-count=%s\n' "$result" "$(grep -Fxc "$key" "$HOME/.ssh/authorized_keys")"
'''


def openssh_precheck_command() -> str:
    return r'''set +e
SSHD=$(command -v sshd 2>/dev/null || test -x /usr/sbin/sshd && echo /usr/sbin/sshd)
test -n "$SSHD" && echo NETBOT_SSH sshd=present || echo NETBOT_SSH sshd=absent
if test -n "$SSHD"; then "$SSHD" -t >/dev/null 2>&1 && echo NETBOT_SSH config=valid || echo NETBOT_SSH config=unknown; fi
systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null
ss -ltn 2>/dev/null | grep -E ':22[[:space:]]' || true
test -d "$HOME/.ssh" && stat -c 'NETBOT_SSH ssh_dir=%a:%U:%G' "$HOME/.ssh"
test -f "$HOME/.ssh/authorized_keys" && stat -c 'NETBOT_SSH authorized=%a:%U:%G' "$HOME/.ssh/authorized_keys"
for key in /etc/ssh/ssh_host_*_key.pub; do test -r "$key" || continue; echo NETBOT_HOST_KEY_FILE="$key"; ssh-keygen -lf "$key" 2>/dev/null; awk '{print "NETBOT_HOST_KEY_MATERIAL=" $1 " " $2}' "$key"; done
'''


def parse_host_key_observation(output: str) -> list[dict[str, str]]:
    result, current = [], None
    for line in output.splitlines():
        if line.startswith("NETBOT_HOST_KEY_FILE="): current = line.split("=", 1)[1]
        match = re.match(r"\s*\d+\s+(SHA256:\S+)\s+.*\(([^)]+)\)", line)
        if match and current:
            result.append({"path": current, "fingerprint": match.group(1), "key_type": match.group(2), "source": "target sshd public key"})
            current = None
    return result


def parse_host_key_material(output: str) -> list[dict[str, str]]:
    """Extract public host-key material only; private files are never read."""
    result = []
    for line in output.splitlines():
        if not line.startswith("NETBOT_HOST_KEY_MATERIAL="):
            continue
        value = line.split("=", 1)[1].strip().split()
        if len(value) == 2 and value[0].startswith(("ssh-", "ecdsa-")):
            result.append({"key_type": value[0], "key_data": value[1], "source": "target sshd public key"})
    return result


def temporary_known_hosts_line(endpoint: str, key: dict[str, str]) -> str:
    """Create one temporary known_hosts line from an observed public key."""
    if not endpoint or not key.get("key_type") or not key.get("key_data"):
        raise ValueError("complete observed public host key required")
    if any(ch.isspace() for ch in endpoint) or any(ch.isspace() for ch in key["key_data"]):
        raise ValueError("invalid host-key material")
    return f"{endpoint} {key['key_type']} {key['key_data']}"


def verify_host_key_continuity(expected: list[dict[str, str]] | None, observed: list[dict[str, str]] | None) -> dict[str, Any]:
    if not expected or not observed:
        return {"state": "host-key-unavailable", "confidence": "none"}
    expected_fingerprints = {x.get("fingerprint") for x in expected if x.get("fingerprint")}
    observed_fingerprints = {x.get("fingerprint") for x in observed if x.get("fingerprint")}
    if not expected_fingerprints or not observed_fingerprints:
        return {"state": "host-key-unavailable", "confidence": "none"}
    if expected_fingerprints & observed_fingerprints:
        return {"state": "match", "confidence": "high"}
    return {"state": "HOST_KEY_MISMATCH", "confidence": "high"}


def teardown_capability(sudo_listing: str, command_result: int | None = None) -> dict[str, Any]:
    """Classify exact capability; a sudo listing alone is never sufficient."""
    allowed = bool(re.search(r"tailscale\s+set\s+--ssh(?:=false|\s+false)", sudo_listing))
    if command_result is None:
        state = "unknown" if allowed else "blocked"
        source = "sudo -n -l is advisory; exact execution not verified"
    else:
        state = "available" if allowed and command_result == 0 else "blocked"
        source = "exact non-mutating command-form probe"
    return {"state": state, "authority": AUTHORITY_MAINTAIN, "command": "sudo -n /usr/bin/tailscale set --ssh=false", "requires_password": state != "available", "source": source}


def observe_teardown_capability(host: str, user: str = "zero", runner: Callable = subprocess.run, timeout: int = 8) -> dict[str, Any]:
    # `--help` exercises the exact executable/subcommand/flag form without
    # changing Tailscale state.  Listing output is retained only as context.
    command = tailscale_ssh_command(host, user, "sudo -n -l /usr/bin/tailscale set --ssh=false; sudo -n /usr/bin/tailscale set --ssh=false --help")
    try: result = runner(command, text=True, capture_output=True, check=False, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"state": "observer-unavailable", "authority": AUTHORITY_MAINTAIN, "source": "Tailscale SSH sudo inspection", "detail": str(exc)}
    listing = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 and not listing:
        return {"state": "observer-unavailable", "authority": AUTHORITY_MAINTAIN, "source": "Tailscale SSH sudo inspection"}
    return teardown_capability(listing, result.returncode)


def attempt_teardown(host: str, runner: Callable = subprocess.run, timeout: int = 8,
                     *, user: str = "zero", identity_file: str | None = None,
                     host_keys: list[dict[str, str]] | None = None) -> dict[str, Any]:
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1"]
    temporary = None
    if host_keys:
        temporary = tempfile.NamedTemporaryFile("w", prefix="netbot-known-hosts-teardown-", delete=True)
        for key in host_keys:
            temporary.write(temporary_known_hosts_line(host, key) + "\n")
        temporary.flush()
        command += ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={temporary.name}"]
    if identity_file:
        command += ["-i", identity_file, "-o", "IdentitiesOnly=yes"]
    command += [f"{user}@{host}", "sudo", "-n", "/usr/bin/tailscale", "set", "--ssh=false"]
    try: result = runner(command, text=True, capture_output=True, check=False, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc: return {"state": "blocked", "reason": "observer/tool unavailable", "detail": str(exc)}
    finally:
        if temporary is not None:
            temporary.close()
    text = (result.stderr or result.stdout or "").strip()
    if result.returncode == 0: return {"state": "succeeded", "authority": AUTHORITY_MAINTAIN}
    if re.search(r"password|not permitted|permission denied", text, re.I): return {"state": "blocked", "reason": "noninteractive maintenance authorization unavailable", "detail": text}
    return {"state": "failed", "reason": "teardown command failed", "detail": text}


def attempt_tailscale_teardown(host: str, user: str = "zero", runner: Callable = subprocess.run,
                               timeout: int = 8) -> dict[str, Any]:
    """Use the active bootstrap transport for the one approved teardown."""
    command = tailscale_ssh_command(host, user, "sudo -n /usr/bin/tailscale set --ssh=false")
    try:
        result = runner(command, text=True, capture_output=True, check=False, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"state": "blocked", "reason": "observer/tool unavailable", "detail": str(exc)}
    text = (result.stderr or result.stdout or "").strip()
    if result.returncode == 0:
        return {"state": "succeeded", "success": True, "authority": AUTHORITY_MAINTAIN}
    if re.search(r"password|not permitted|permission denied", text, re.I):
        return {"state": "blocked", "reason": "noninteractive maintenance authorization unavailable", "detail": text}
    return {"state": "failed", "reason": "teardown command failed", "detail": text}


def ordinary_ssh_command(host: str, user: str, identity_file: str, known_hosts_file: str) -> list[str]:
    return ["ssh", "-i", identity_file, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts_file}", f"{user}@{host}", "true"]


def bootstrap_plan(identity: str, host: str, user: str | None, eligibility: Eligibility, teardown: dict[str, Any] | None = None, ssh_observed: bool | None = None, provider: dict[str, Any] | None = None, tailscale_ssh_enabled: bool | None = None, host_key: dict[str, Any] | None = None) -> dict[str, Any]:
    teardown = teardown or {"state": "unknown", "authority": AUTHORITY_MAINTAIN}
    provider = provider or {"provider": "infrastructure" if eligibility.state == "eligible" else "unknown", "state": "candidate" if eligibility.state == "eligible" else "unknown", "source": eligibility.source}
    user_state = validate_bootstrap_user(user)
    candidate = eligibility.state == "eligible" and user_state["state"] == "known"
    exact_teardown = teardown.get("state") == "available"
    stages = [
        {"state": "discovered", "authority": AUTHORITY_OBSERVE, "status": "ready"},
        {"state": "bootstrap_candidate", "authority": AUTHORITY_OBSERVE, "status": "ready" if candidate else "blocked", "reason": eligibility.evidence if user_state["state"] == "known" else user_state["reason"]},
        {"state": "bootstrap_authenticated", "authority": AUTHORITY_OBSERVE, "status": "future"},
        {"state": "public_key_installed", "authority": AUTHORITY_MANAGE, "status": "future"},
        {"state": "openssh_prepared", "authority": AUTHORITY_OBSERVE, "status": "future"},
        {"state": "bootstrap_teardown_ready", "authority": AUTHORITY_MAINTAIN, "status": "ready" if exact_teardown else "blocked", "reason": "exact noninteractive teardown capability required"},
        {"state": "bootstrap_disabled", "authority": AUTHORITY_MAINTAIN, "status": "future"},
        {"state": "openssh_verified", "authority": AUTHORITY_OBSERVE, "status": "ready" if ssh_observed is True else "blocked"},
        {"state": "managed", "authority": AUTHORITY_OBSERVE, "status": "future"},
    ]
    return {"identity": identity, "target": host, "user": user, "user_validation": user_state, "provider": provider, "eligibility": eligibility.__dict__, "tailscale_ssh_enabled": tailscale_ssh_enabled, "host_key": host_key or {"state": "unknown"}, "state": bootstrap_state_for(eligibility, True) if candidate else "discovered", "stages": stages, "teardown": teardown, "maintenance_authorized": exact_teardown, "action": "no mutation; plan only"}


def teardown_preconditions(plan: dict[str, Any], *, authenticated: bool, key_installed: bool, openssh_prepared: bool, host_key_captured: bool, tailscale_ssh_enabled: bool | None, capability: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "target_authenticated": authenticated,
        "explicit_user_verified": bool(plan.get("user_validation", {}).get("state") == "known"),
        "managed_key_installed": key_installed,
        "openssh_prepared": openssh_prepared,
        "host_key_captured": host_key_captured,
        "tailscale_ssh_enabled": tailscale_ssh_enabled is True,
        "exact_teardown_capability": capability.get("state") == "available",
    }
    return {"state": "ready" if all(checks.values()) else "authorization_required" if checks["exact_teardown_capability"] is False else "blocked", "checks": checks, "authority": AUTHORITY_MAINTAIN}


def classify_post_teardown(*, observed_disabled: bool | None, ordinary_ssh_verified: bool, host_key_state: str) -> dict[str, Any]:
    if observed_disabled is not True:
        return {"state": "bootstrap-disabled-unverified", "managed": False, "reason": "Tailscale SSH is not positively observed disabled"}
    if host_key_state != "match":
        return {"state": "host-key-mismatch" if host_key_state == "HOST_KEY_MISMATCH" else "host-key-unavailable", "managed": False, "reason": "host-key continuity failed"}
    if not ordinary_ssh_verified:
        return {"state": "openssh-verification-failed", "managed": False, "reason": "new ordinary OpenSSH connection was not verified"}
    return {"state": "managed", "managed": True, "reason": "Tailscale SSH disabled and new OpenSSH path verified"}


def advance_bootstrap(current: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Apply one conservative state transition from verified evidence."""
    if current not in BOOTSTRAP_STATES:
        return {"state": "invalid", "reason": "unknown bootstrap state"}
    if current in {"managed", "bootstrap_teardown_blocked", "openssh_verified"}:
        return {"state": current, "changed": False, "reason": "terminal/intermediate state requires fresh observation"}
    next_state = BOOTSTRAP_TRANSITIONS.get(current)
    if not next_state:
        return {"state": current, "changed": False, "reason": "no automatic transition"}
    required = {
        "bootstrap_candidate": "candidate",
        "bootstrap_authenticated": "authenticated",
        "public_key_installed": "key_installed",
        "openssh_prepared": "openssh_prepared",
        "bootstrap_teardown_ready": "teardown_ready",
        "bootstrap_disabled": "tailscale_ssh_disabled",
        "openssh_verified": "ordinary_ssh_verified",
        "managed": "managed",
    }.get(next_state)
    if required and evidence.get(required) is not True:
        return {"state": current, "changed": False, "reason": f"verified evidence required: {required}"}
    return {"state": next_state, "changed": True, "evidence": required}


def bootstrap_command_set(host: str, user: str, public_key: str, controller_id: str) -> dict[str, Any]:
    """Return the only remote commands used by the executor.

    The public key is supplied as stdin to the target-side script. No private
    key or password is represented here. Teardown is deliberately absent from
    the bootstrap transport command set and is separately capability-gated.
    """
    if validate_bootstrap_user(user)["state"] != "known":
        raise ValueError("explicit valid bootstrap Unix user required")
    expected = managed_key_line(public_key, controller_id)
    return {
        "bootstrap": tailscale_ssh_command(host, user, "true"),
        "install_public_key": tailscale_ssh_command(host, user, managed_key_install_command()),
        "install_stdin": expected + "\n",
        "openssh_precheck": tailscale_ssh_command(host, user, openssh_precheck_command()),
        "teardown": ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1", f"{user}@{host}", "sudo", "-n", "tailscale", "set", "--ssh=false"],
        "permanent_probe": ordinary_ssh_command(host, user, "<controller-private-key-local-only>", "<verified-known-hosts-file>"),
    }


def guarded_teardown(plan: dict[str, Any], observations: dict[str, Any], runner: Callable = subprocess.run, timeout: int = 8) -> dict[str, Any]:
    """Attempt only the authority-lowering operation after every precondition."""
    preconditions = teardown_preconditions(
        plan,
        authenticated=observations.get("authenticated") is True,
        key_installed=observations.get("key_installed") is True,
        openssh_prepared=observations.get("openssh_prepared") is True,
        host_key_captured=observations.get("host_key_captured") is True,
        tailscale_ssh_enabled=observations.get("tailscale_ssh_enabled"),
        capability=observations.get("teardown_capability", {}),
    )
    if preconditions["state"] != "ready":
        return {"state": "authorization_required" if preconditions["checks"]["exact_teardown_capability"] is False else "blocked", "preconditions": preconditions, "invoked": False}
    result = attempt_teardown(plan["target"], runner=runner, timeout=timeout)
    result["preconditions"] = preconditions
    result["invoked"] = True
    return result


def execute_bootstrap(plan: dict[str, Any], operations: dict[str, Callable[[], dict[str, Any]]]) -> dict[str, Any]:
    """Run the guarded workflow using explicit, injectable observations/actions.

    Production transports supply the operations; keeping them injected makes
    the state machine testable without a live tailnet. No operation named
    ``agent-temporary on`` is accepted or generated here.
    """
    if plan.get("state") not in {"discovered", "bootstrap_candidate", "bootstrap_teardown_blocked"}:
        return {"state": plan.get("state", "invalid"), "events": [], "reason": "not a fresh bootstrap candidate"}
    if plan.get("eligibility", {}).get("state") != "eligible":
        return {"state": "discovered", "events": [], "reason": "bootstrap eligibility is not verified"}
    if plan.get("user_validation", {}).get("state") != "known":
        return {"state": "discovered", "events": [], "reason": "explicit Unix user is not verified"}
    events: list[dict[str, Any]] = []

    def step(name: str, state: str, required: tuple[str, ...]) -> dict[str, Any] | None:
        operation = operations.get(name)
        if operation is None:
            return {"state": state, "events": events, "reason": f"operation unavailable: {name}"}
        result = operation() or {}
        if result.get("success") is not True:
            return {"state": state, "events": events, "reason": result.get("reason", f"{name} not verified"), "observation": result}
        events.append({"state": state, "observation": {k: result.get(k) for k in required if k in result}})
        return None

    for name, state, required in (
        ("authenticate", "bootstrap_authenticated", ("authenticated",)),
        ("install_key", "public_key_installed", ("key_installed",)),
        ("precheck", "openssh_prepared", ("openssh_prepared",)),
        ("capture_host_key", "bootstrap_teardown_ready", ("host_key_captured",)),
    ):
        failure = step(name, state, required)
        if failure:
            return failure

    # A live executor must prove a fresh ordinary OpenSSH connection before
    # it can consider the permanent path prepared.  Older injected tests may
    # omit this operation; production execution supplies it explicitly.
    if "ordinary_prepared" in operations:
        prepared = operations["ordinary_prepared"]() or {}
        if prepared.get("success") is not True:
            return {"state": "openssh_verification_failed", "events": events,
                    "reason": prepared.get("reason", "ordinary OpenSSH was not verified"),
                    "observation": prepared}
        events.append({"state": "openssh_prepared", "observation": prepared})

    capability = operations.get("teardown_capability")
    capability_result = capability() if capability else {"success": False, "reason": "exact teardown capability unavailable"}
    if capability_result.get("state") != "available":
        events.append({"state": "bootstrap_teardown_ready", "observation": {"state": "ready"}})
        events.append({"state": "authorization_required", "observation": capability_result})
        return {"state": "authorization_required", "events": events, "reason": "human authorization required for exact teardown operation", "teardown": capability_result}
    teardown = operations.get("teardown")
    if teardown is None:
        return {"state": "authorization_required", "events": events, "reason": "teardown operation unavailable"}
    teardown_result = teardown() or {}
    if teardown_result.get("success") is not True:
        # Disabling Tailscale SSH can close the very transport carrying the
        # command.  A nonzero transport result is therefore ambiguous until
        # target reality is re-observed; it must not be treated as success by
        # itself, but a positive ssh=false observation is sufficient proof.
        disabled_probe = operations.get("observe_disabled")
        observed = disabled_probe() if disabled_probe else {}
        if observed.get("disabled") is not True:
            return {"state": "bootstrap_teardown_blocked", "events": events,
                    "reason": teardown_result.get("reason", "teardown failed"),
                    "teardown": teardown_result, "post_teardown_observation": observed}
        teardown_result = {**teardown_result, "state": "succeeded",
                           "transport_result": teardown_result.get("state"),
                           "verified_by": "target-side ssh=false observation"}
    disabled = operations.get("observe_disabled")
    disabled_result = disabled() if disabled else {}
    if disabled_result.get("disabled") is not True:
        return {"state": "bootstrap_teardown_blocked", "events": events, "reason": "Tailscale SSH was not positively observed disabled", "teardown": teardown_result}
    events.append({"state": "bootstrap_disabled", "observation": disabled_result})
    ordinary = operations.get("ordinary_ssh")
    ordinary_result = ordinary() if ordinary else {}
    continuity = operations.get("host_key_continuity")
    continuity_result = continuity() if continuity else {"state": "host-key-unavailable"}
    final = classify_post_teardown(observed_disabled=True, ordinary_ssh_verified=ordinary_result.get("success") is True, host_key_state=continuity_result.get("state", "unknown"))
    events.append({"state": final["state"], "observation": {"ordinary_ssh": ordinary_result, "host_key": continuity_result}})
    result = {"state": final["state"], "events": events, "managed": final.get("managed", False), "ordinary_ssh": ordinary_result, "host_key": continuity_result}
    revoke = operations.get("revoke_authority")
    if final.get("managed") and revoke:
        result["authority_revocation"] = revoke() or {}
    return result


def _run(command: list[str], *, input_text: str | None = None, timeout: int = 12) -> dict[str, Any]:
    """Run one bounded external command and retain output for classification."""
    try:
        result = subprocess.run(command, input=input_text, text=True,
                                capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": 255, "stdout": "", "stderr": str(exc), "error": str(exc)}
    return {"returncode": result.returncode, "stdout": result.stdout or "", "stderr": result.stderr or ""}


def _tailscale_remote(host: str, user: str, command: str) -> dict[str, Any]:
    return _run(tailscale_ssh_command(host, user, command))


def _remote_identity(result: dict[str, Any], user: str) -> dict[str, Any]:
    output = result["stdout"]
    lines = output.splitlines()
    if result["returncode"] != 0:
        return {"success": False, "reason": "bootstrap authentication failed", "detail": (result["stderr"] or output).strip()}
    if len(lines) < 3 or lines[0].strip() != user or not lines[1].strip() or lines[2].strip() != "1000":
        return {"success": False, "reason": "bootstrap target/user identity mismatch", "detail": output.strip()}
    return {"success": True, "authenticated": True, "user": lines[0].strip(), "hostname": lines[1].strip(), "uid": lines[2].strip()}


def _tailscale_enabled(host: str, user: str) -> dict[str, Any]:
    observation = TailscalePreferenceObserver(lambda command: _tailscale_remote(host, user, command)).observe()
    return {"state": "enabled" if observation.ssh is True else "disabled" if observation.ssh is False else observation.state,
            "success": observation.ssh is True, "ssh": observation.ssh, "source": observation.source, "detail": observation.detail}


def _ordinary_run(host: str, user: str, identity_file: str, host_keys: list[dict[str, str]], remote_command: str) -> dict[str, Any]:
    if not host_keys:
        return {"success": False, "reason": "host-key-unavailable"}
    with tempfile.NamedTemporaryFile("w", prefix="netbot-known-hosts-", delete=True) as known:
        for key in host_keys:
            known.write(temporary_known_hosts_line(host, key) + "\n")
        known.flush()
        command = ["ssh", "-i", identity_file, "-o", "IdentitiesOnly=yes",
                   "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", f"UserKnownHostsFile={known.name}",
                   "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1",
                   f"{user}@{host}", remote_command]
        result = _run(command)
    return {"success": result["returncode"] == 0, "stdout": result["stdout"],
            "stderr": result["stderr"], "returncode": result["returncode"]}


def _ordinary_verify(host: str, user: str, identity_file: str, host_keys: list[dict[str, str]]) -> dict[str, Any]:
    """Verify a fresh OpenSSH connection using only temporary trusted keys."""
    if not host_keys:
        return {"success": False, "reason": "host-key-unavailable"}
    result = _ordinary_run(host, user, identity_file, host_keys, "hostname; id -un; id -u")
    if not result["success"]:
        return {"success": False, "reason": "ordinary OpenSSH authentication failed", "detail": result["stderr"].strip()}
    lines = result["stdout"].splitlines()
    if len(lines) < 3 or lines[1].strip() != user:
        return {"success": False, "reason": "ordinary OpenSSH user verification failed", "detail": result["stdout"].strip()}
    return {"success": True, "hostname": lines[0].strip(), "user": lines[1].strip(), "uid": lines[2].strip(), "host_key_state": "match"}


def _observe_ordinary_tailscale_state(host: str, user: str, identity_file: str,
                                      host_keys: list[dict[str, str]]) -> dict[str, Any]:
    """Observe target Tailscale state over the now-permanent SSH path."""
    result = _ordinary_run(host, user, identity_file, host_keys, "tailscale get --json")
    source = "target tailscale get --json"
    if result["success"]:
        try:
            value = json.loads(result["stdout"]).get("ssh")
        except (TypeError, ValueError):
            value = None
    else:
        fallback = _ordinary_run(host, user, identity_file, host_keys, "tailscale debug prefs")
        source = "target tailscale debug prefs (RunSSH)"
        try:
            value = json.loads(fallback["stdout"]).get("RunSSH") if fallback["success"] else None
        except (TypeError, ValueError):
            value = None
        if value is None:
            return {"disabled": False, "state": "unavailable", "detail": result["stderr"].strip()}
    return {"disabled": value is False, "state": "disabled" if value is False else "enabled" if value is True else "unknown", "ssh": value, "source": source}


def execute_live_bootstrap(*, host: str, user: str, public_key_path: Path,
                           ordinary_host: str | None = None,
                           controller_id: str = "arasaka",
                           resume_host_key_material: list[dict[str, str]] | None = None,
                           node_id: str | None = None) -> dict[str, Any]:
    """Execute only the MANAGE portion of bootstrap, then stop at teardown authority."""
    public_key = public_key_path.read_text().strip()
    expected_line = managed_key_line(public_key, controller_id)
    identity_file = str(Path.home() / ".ssh" / "id_ed25519_arasaka")
    ordinary_endpoint = ordinary_host or host
    auth = _remote_identity(_tailscale_remote(host, user, "whoami; hostname; id -u"), user)
    if not auth["success"] and resume_host_key_material:
        ordinary = _ordinary_verify(ordinary_endpoint, user, identity_file, resume_host_key_material)
        state = _observe_ordinary_tailscale_state(ordinary_endpoint, user, identity_file, resume_host_key_material)
        if ordinary["success"] and state.get("ssh") is False:
            cleanup = _ordinary_run(ordinary_endpoint, user, identity_file, resume_host_key_material, "sudo -n /usr/local/bin/agent-temporary off")
            status = _ordinary_run(ordinary_endpoint, user, identity_file, resume_host_key_material, "sudo agent-temporary status")
            return {"state": "managed", "managed": True, "node_id": node_id, "hostname": host,
                    "events": [{"state": "bootstrap_disabled", "observation": state},
                               {"state": "openssh_verified", "observation": ordinary}],
                    "reason": "resumed from positively observed post-teardown reality",
                    "tailscale": {"state": "disabled", "success": True, "ssh": False},
                    "ordinary_ssh": ordinary, "host_key": {"state": "match"},
                    "authority_revocation": {"command": "sudo -n /usr/local/bin/agent-temporary off",
                                              "success": cleanup["success"],
                                              "status": status["stdout"].strip(),
                                              "detail": status["stderr"].strip()}}
    if not auth["success"]:
        return {"state": "bootstrap_candidate", "reason": auth["reason"], "events": []}
    enabled = _tailscale_enabled(host, user)
    if not enabled["success"]:
        return {"state": "bootstrap_candidate", "reason": "Tailscale SSH is not positively enabled", "events": [], "tailscale": enabled}
    precheck = _tailscale_remote(host, user, openssh_precheck_command())
    precheck_output = precheck["stdout"]
    keys = parse_host_key_observation(precheck_output)
    materials = parse_host_key_material(precheck_output)
    if precheck["returncode"] != 0 or "NETBOT_SSH sshd=present" not in precheck_output or not keys or not materials:
        return {"state": "bootstrap_authenticated", "reason": "OpenSSH precheck or host-key observation failed", "events": [], "precheck": precheck_output, "host_keys": keys}
    marker = f"netbot:controller:{controller_id}"
    key_state_result = _tailscale_remote(host, user, f"awk '/{marker}$/ {{print}}' \"$HOME/.ssh/authorized_keys\" 2>/dev/null || true")
    marked_lines = [line.strip() for line in key_state_result["stdout"].splitlines() if line.strip()]
    key_state = classify_managed_keys(marked_lines, expected_line, controller_id)
    if key_state["state"] in {"conflict", "duplicate"}:
        return {"state": "bootstrap_authenticated", "reason": "controller marker conflicts or is duplicated", "events": [], "key_state": key_state}
    if key_state["state"] == "present":
        install_output = "managed-key=already-present\nmanaged-count=1\n"
    elif key_state["state"] == "absent":
        install = _run(tailscale_ssh_command(host, user, managed_key_install_command()), input_text=expected_line + "\n")
        install_output = install["stdout"] + install["stderr"]
        if install["returncode"] != 0 or "managed-count=1" not in install_output:
            return {"state": "bootstrap_authenticated", "reason": "managed public-key installation was not verified", "events": [], "install": install_output}
    else:
        return {"state": "bootstrap_authenticated", "reason": "controller marker state unavailable", "events": [], "key_state": key_state}
    ordinary = _ordinary_verify(ordinary_endpoint, user, identity_file, materials)
    # The private key is referenced locally only; it is never read or sent.
    if not ordinary["success"]:
        return {"state": "openssh_verification_failed", "reason": ordinary["reason"], "events": [], "host_keys": keys, "install": install_output}
    capability = observe_teardown_capability(host, user)
    plan = bootstrap_plan(host, host, user, Eligibility("eligible", "observed Tailscale peer tag", "tag:netbot-bootstrap"), teardown=capability, ssh_observed=True, provider={"provider": "infrastructure", "state": "candidate", "source": "observed Tailscale tag"}, tailscale_ssh_enabled=True, host_key={"state": "captured", "fingerprints": keys})
    result = execute_bootstrap(plan, {
        "authenticate": lambda: {"success": True, "authenticated": True, **auth},
        "install_key": lambda: {"success": True, "key_installed": True, "managed_count": 1},
        "precheck": lambda: {"success": True, "openssh_prepared": True},
        "capture_host_key": lambda: {"success": True, "host_key_captured": True, "host_keys": keys},
        "ordinary_prepared": lambda: ordinary,
        "teardown_capability": lambda: capability,
        "teardown": lambda: attempt_tailscale_teardown(host, user),
        "observe_disabled": lambda: _observe_ordinary_tailscale_state(
            ordinary_endpoint, user, identity_file, materials),
        "ordinary_ssh": lambda: _ordinary_verify(ordinary_endpoint, user, identity_file, materials),
        "host_key_continuity": lambda: {"state": "match"},
        "revoke_authority": lambda: _ordinary_run(ordinary_endpoint, user, identity_file, materials,
                                                    "sudo -n /usr/local/bin/agent-temporary off"),
    })
    result.update({"node_id": node_id, "hostname": host, "plan": plan, "tailscale": enabled, "host_keys": keys, "host_key_material": materials, "install": install_output, "ordinary_ssh": ordinary, "teardown_capability": capability})
    return result
