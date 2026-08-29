"""Read-only observation of the agent-temporary mechanism."""

import re
import subprocess
from typing import Callable


OBSERVER_SCRIPT = r'''
script=/usr/local/bin/agent-temporary
if [ -x "$script" ]; then
    echo NETBOT_AGENT installed=yes
    version=$($script version 2>/dev/null || true)
    case "$version" in
        agent-temporary\ *) echo NETBOT_AGENT version=${version#agent-temporary\ } ;;
        *) echo NETBOT_AGENT version=unknown ;;
    esac
else
    echo NETBOT_AGENT installed=no
    echo NETBOT_AGENT version=unknown
fi
if [ "$(uname -s 2>/dev/null)" = Linux ] && command -v systemctl >/dev/null 2>&1; then
    echo NETBOT_AGENT platform=linux-systemd
else
    echo NETBOT_AGENT platform=unsupported
fi
if [ -r "$script" ]; then
    if grep -Eiq '(^|[^[:alnum:]])(expire|expiry|timer|cron|at[[:space:]])' "$script"; then
        echo NETBOT_AGENT lifecycle_markers=yes
    else
        echo NETBOT_AGENT lifecycle_markers=no
    fi
else
    echo NETBOT_AGENT lifecycle_markers=unknown
fi
if command -v systemctl >/dev/null 2>&1 && systemctl list-timers --all 2>/dev/null | grep -Eiq 'agent-temporary|temporary-agent'; then
    echo NETBOT_AGENT timer=present
else
    echo NETBOT_AGENT timer=absent
fi
echo NETBOT_AGENT sudo_begin
sudo -n -l 2>&1
sudo_rc=$?
echo NETBOT_AGENT sudo_end
echo NETBOT_AGENT sudo_rc=$sudo_rc
echo NETBOT_AGENT status_begin
sudo -n "$script" status 2>&1
status_rc=$?
echo NETBOT_AGENT status_end
echo NETBOT_AGENT status_rc=$status_rc
'''


def _field(output: str, key: str) -> str | None:
    match = re.search(r"^NETBOT_AGENT " + re.escape(key) + r"=([^\n]+)$", output, re.MULTILINE)
    return match.group(1).strip() if match else None


def _sudo_listing(output: str) -> str:
    match = re.search(r"^NETBOT_AGENT sudo_begin\n(.*?)^NETBOT_AGENT sudo_end$", output, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def _status_listing(output: str) -> str:
    match = re.search(r"^NETBOT_AGENT status_begin\n(.*?)^NETBOT_AGENT status_end$", output, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def parse_agent_observation(output: str, returncode: int = 0, error: str | None = None) -> dict:
    """Normalize the safe probe output without retaining raw sudo output."""
    if returncode != 0 and not _field(output, "installed"):
        return {
            "status": "observer-unavailable",
            "installed": "unknown",
            "privilege_state": "unknown",
            "source": "SSH read-only agent observer",
            "confidence": "none",
            "error": error or "agent observer failed",
        }

    installed = _field(output, "installed") or "unknown"
    version = _field(output, "version")
    listing = _sudo_listing(output)
    sudo_rc = _field(output, "sudo_rc")
    # Match the effective command listing, not a file path or expected rule.
    unrestricted = bool(re.search(r"^\s*(?:\S+\s+ALL=\([^\n]*\)\s+)?\([^\n]*\)\s+NOPASSWD:\s+ALL\s*$", listing, re.MULTILINE))
    sudo_denied = bool(re.search(r"not allowed|may not run sudo|not in the sudoers", listing, re.IGNORECASE))
    sudo_password_required = bool(re.search(r"password is required|a password is required", listing, re.IGNORECASE))
    sudo_listing_available = bool(re.search(r"^User\s+\S+\s+may run the following", listing, re.MULTILINE))

    status_listing = _status_listing(output)
    if unrestricted:
        privilege_state = "privileged"
        confidence = "high"
    elif sudo_denied or (sudo_rc not in (None, "0") and not sudo_listing_available and not sudo_password_required):
        privilege_state = "unknown"
        confidence = "low"
    elif installed == "yes" and (sudo_listing_available or sudo_password_required):
        privilege_state = "installed-inactive"
        confidence = "medium"
    else:
        privilege_state = "unknown"
        confidence = "low"

    lifecycle = _field(output, "lifecycle_markers")
    timer = _field(output, "timer")
    if unrestricted and lifecycle == "no" and timer == "absent":
        expiry = "none-observed"
        reboot_persistence = "yes"
        risk = "persistent-unbounded-privilege"
    elif unrestricted:
        expiry = "unknown"
        reboot_persistence = "unknown"
        risk = "unrestricted-privilege-details-unknown"
    else:
        expiry = "unknown" if installed == "unknown" else "not-applicable"
        reboot_persistence = "unknown"
        risk = "none-observed" if privilege_state == "installed-inactive" else "unknown"

    return {
        "status": "available",
        "installed": installed,
        "version": None if version in (None, "unknown") else version,
        "platform": _field(output, "platform") or "unknown",
        "privilege_state": privilege_state,
        "user": _sudo_user(listing),
        "scope": "ALL commands as root" if unrestricted else "unknown",
        "authentication": "NOPASSWD" if unrestricted else "unknown",
        "expiry": expiry,
        "reboot_persistence": reboot_persistence,
        "risk": risk,
        "source": "effective sudo -n -l plus agent-temporary metadata",
        "confidence": confidence,
        "expires_at_epoch": _status_field(status_listing, "expires_at_epoch"),
        "remaining_seconds": _status_field(status_listing, "remaining_seconds"),
        "persist_reboot": _status_field(status_listing, "persist_reboot"),
    }


def _status_field(listing: str, key: str) -> str | None:
    match = re.search(r"^" + re.escape(key) + r"=([^\n]+)$", listing, re.MULTILINE)
    return match.group(1).strip() if match else None


def _sudo_user(listing: str) -> str | None:
    match = re.search(r"^User\s+(\S+)\s+may run the following", listing, re.MULTILINE)
    return match.group(1) if match else None


def observe_agent(host: str, runner: Callable = subprocess.run, timeout: int = 8) -> dict:
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
        "-o", "ConnectionAttempts=1", host, "sh", "-c", OBSERVER_SCRIPT,
    ]
    try:
        completed = runner(command, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return parse_agent_observation("", 1, str(exc)) | {"status": "observer-unavailable", "error": "SSH observer timed out"}
    except OSError as exc:
        return parse_agent_observation("", 1, str(exc)) | {"status": "observer-unavailable", "error": str(exc)}
    if completed.returncode != 0 and not _field(completed.stdout or "", "installed"):
        return parse_agent_observation(completed.stdout or "", completed.returncode, (completed.stderr or "").strip())
    return parse_agent_observation(completed.stdout or "", completed.returncode, (completed.stderr or "").strip() or None)
