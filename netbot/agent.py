"""Deterministic agent version comparison and update planning."""

from .authority import host_capabilities


def _version_tuple(value):
    try:
        return tuple(int(part) for part in str(value).split("."))
    except (TypeError, ValueError):
        return None


def version_state(desired_version, observation):
    if not observation or observation.get("status") == "observer-unavailable":
        return "unknown"
    if observation.get("platform") == "unsupported":
        return "unsupported"
    if observation.get("installed") != "yes":
        return "not-installed"
    observed = observation.get("version")
    if not observed or not desired_version:
        return "unknown"
    desired_key, observed_key = _version_tuple(desired_version), _version_tuple(observed)
    if not desired_key or not observed_key:
        return "unknown"
    if observed_key == desired_key:
        return "current"
    return "update-needed" if observed_key < desired_key else "newer-than-desired"


def update_plan(identity, desired_version, observation, ssh_observed=True):
    state = version_state(desired_version, observation)
    capabilities = host_capabilities(observation, ssh_observed)
    stages = [
        {"authority": "observe", "action": "verify host identity, SSH, installed version, and effective privilege", "state": "ready" if capabilities["observe"] == "available" else "blocked"},
        {"authority": "manage", "action": "stage and checksum the release artifact", "state": "ready" if capabilities["manage"] == "available" else "blocked"},
        {"authority": "maintain", "action": "install release and update systemd units", "state": "ready" if capabilities["maintain"] == "available" else "blocked", "reason": capabilities["maintain_reason"]},
        {"authority": "safety", "action": "verify installation, revoke temporary privilege, and verify permanent SSH", "state": "future"},
    ]
    return {
        "identity": identity,
        "desired_version": desired_version,
        "observed_version": (observation or {}).get("version"),
        "version_state": state,
        "privilege_state": (observation or {}).get("privilege_state", "unknown"),
        "authority": capabilities,
        "maintenance_authorized": capabilities["maintain"] == "available",
        "maintenance_reason": capabilities["maintain_reason"],
        "action": "no update needed" if state == "current" else "update requires future approved maintenance",
        "stages": stages,
        "dry_run": True,
    }
