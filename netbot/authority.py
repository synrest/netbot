"""Small, explicit authority and host-capability vocabulary."""

AUTHORITY_OBSERVE = "observe"
AUTHORITY_MANAGE = "manage"
AUTHORITY_MAINTAIN = "maintain"


def host_capabilities(agent_observation: dict | None, ssh_observed: bool | None) -> dict:
    observe = "available" if agent_observation and agent_observation.get("status") == "available" else "unavailable"
    manage = "available" if ssh_observed is True else ("blocked" if ssh_observed is False else "unknown")
    privilege = (agent_observation or {}).get("privilege_state")
    if privilege == "privileged":
        maintain, reason = "available", "effective temporary privilege observed"
    elif privilege == "installed-inactive":
        maintain, reason = "blocked", "human authorization required"
    elif privilege in ("observer-unavailable", "unknown", None):
        maintain, reason = "unknown", "privilege provider state unavailable"
    else:
        maintain, reason = "blocked", "privilege provider is not active"
    return {
        "observe": observe,
        "manage": manage,
        "maintain": maintain,
        "maintain_reason": reason,
    }


def authority_for_operation(operation: str) -> str:
    if operation in {"inspect", "probe", "discover", "agent-status"}:
        return AUTHORITY_OBSERVE
    if operation in {"stage", "generate", "ssh-apply", "bootstrap-key-install"}:
        return AUTHORITY_MANAGE
    if operation in {"bootstrap-observe", "bootstrap-precheck", "bootstrap-verify"}:
        return AUTHORITY_OBSERVE
    if operation == "bootstrap-teardown":
        return AUTHORITY_MAINTAIN
    return AUTHORITY_MAINTAIN
