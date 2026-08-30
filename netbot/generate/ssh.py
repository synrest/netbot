"""Deterministic, read-only planning for Netbot-owned SSH aliases."""
from pathlib import Path


def _bindings(host):
    return host.attrs.get("bindings", {}).get("ssh", {})


def _manual_paths(result):
    paths = {}
    for path in result.get("access_paths", []):
        if path.get("kind") == "ssh":
            paths.setdefault(path["name"], path)
    return paths


def _observed(result, identity):
    return next((r for r in result["rows"] if r.get("identity") == identity and r.get("name")), None)


def _alias_claims(result):
    claims = {}
    for host in result["desired"]:
        for alias in _bindings(host).get("aliases", []):
            claims.setdefault(alias, set()).add(host.identity)
    return claims


def _route(bindings, observed, controller_identity):
    """Return (state, route, reason) for a topology-declared route."""
    if not observed or observed.get("status") != "present" or not observed.get("name"):
        return "BLOCKED", None, "insufficient verified connection information"
    configured = {key: bindings.get(key) for key in ("hostname", "port", "controller")
                  if bindings.get(key) is not None}
    hostname = configured.get("hostname")
    controller = configured.get("controller")
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        if not controller:
            return "BLOCKED", None, "localhost route has no explicit controller identity"
        if controller != controller_identity:
            return "BLOCKED", None, "machine-local route belongs to controller " + str(controller)
        return "CANDIDATE", {"hostname": hostname, "port": configured.get("port", 22)}, \
            "verified machine-local route for current controller " + str(controller_identity)
    names = {observed.get("name"), (observed.get("dns_name") or "").rstrip(".")}
    addresses = set(observed.get("addresses", []))
    if hostname and hostname.rstrip(".") not in names and hostname not in addresses:
        return "BLOCKED", None, "configured route does not match the verified observed endpoint"
    return "CANDIDATE", {"hostname": hostname or observed["name"], "port": configured.get("port", 22)}, \
        "verified direct route is portable"


def _target_matches_observation(path, observed):
    if not observed:
        return True
    effective = path.get("effective_config", {}).get("effective", {})
    target = effective.get("hostname") or path.get("target")
    target = target.rstrip(".") if isinstance(target, str) else target
    names = {observed.get("name"), (observed.get("dns_name") or "").rstrip(".")}
    return target in names or target in set(observed.get("addresses", []))


def _manual_state(path, observed):
    config = path.get("effective_config", {})
    effective = config.get("effective", {})
    valid = config.get("status") == "available" and all(
        effective.get(k) not in (None, "", "none") for k in ("hostname", "user", "port"))
    if not valid:
        return "CONFLICT", "manual alias is not a demonstrably valid effective SSH configuration"
    if path.get("classification") == "local-forwarded-or-child":
        return "MANUAL", "manual local/forwarded route is controller-relative"
    if not _target_matches_observation(path, observed):
        return "CONFLICT", "manual alias target conflicts with the observed topology endpoint"
    return "MANUAL", "valid manual alias wins; no generated duplicate"


def plan(result):
    """Return ownership states and only renderable Netbot candidates."""
    manual = _manual_paths(result)
    claims = _alias_claims(result)
    controller_identity = result.get("controller_identity")
    items = []
    for host in sorted(result["desired"], key=lambda h: h.identity):
        bindings = _bindings(host)
        aliases = list(bindings.get("aliases", []))
        aliases = aliases or ([host.identity] if host.identity in manual else [])
        observed = _observed(result, host.identity)
        for alias in sorted(set(aliases)):
            if len(claims.get(alias, set())) > 1:
                owners = ", ".join(sorted(claims[alias]))
                items.append({"identity": host.identity, "alias": alias, "status": "TOPOLOGY CONFLICT",
                              "manual": alias in manual, "proposal": "none", "action": "none",
                              "reason": "SSH alias is claimed by multiple topology identities: " + owners})
                continue
            path = manual.get(alias)
            if path:
                status, reason = _manual_state(path, observed)
                effective = path.get("effective_config", {}).get("effective", {})
                items.append({"identity": host.identity, "alias": alias, "status": status,
                              "manual": True, "proposal": "preserve-manual", "action": "none",
                              "reason": reason, "manual_entry": {
                                  "hostname": effective.get("hostname", path.get("target")),
                                  "user": effective.get("user", path.get("user")),
                                  "port": effective.get("port", path.get("port")),
                                  "classification": path.get("classification"),
                                  "source": path.get("source")}})
                continue
            route_status, route, route_reason = _route(bindings, observed, controller_identity)
            if route_status == "CANDIDATE" and bindings.get("user"):
                items.append({"identity": host.identity, "alias": alias, "status": "CANDIDATE", "manual": False,
                              "proposal": "generate", "action": "create-preview-entry",
                              "reason": route_reason + " plus explicit topology SSH user",
                              "entry": {"alias": alias, "hostname": route["hostname"],
                                        "user": bindings["user"], "port": route["port"]}})
            else:
                items.append({"identity": host.identity, "alias": alias, "status": "BLOCKED", "manual": False,
                              "proposal": "none", "action": "none",
                              "reason": route_reason if route_status == "BLOCKED" else "explicit topology SSH user is missing"})
    return items


def _render(plan_items, installed=False):
    lines = ["# GENERATED BY NETBOT",
             "# DO NOT EDIT MANUALLY" if installed else "# PREVIEW ONLY — NOT INSTALLED",
             "# Source: repository generated/50-netbot.conf" if installed else "# This artifact contains only Netbot-owned SSH alias candidates.",
             "# Installed only by explicit netbot ssh-apply" if installed else "# Manual and conflicting aliases are never copied here.", ""]
    for item in plan_items:
        alias = item.get("alias", item["identity"])
        status = item.get("status", "INFO")
        lines.append(f"# {item['identity']} / {alias}: {status} - {item['reason']}")
        if item.get("entry"):
            e = item["entry"]
            lines += [f"Host {e['alias']}", f"    HostName {e['hostname']}",
                      f"    User {e['user']}", f"    Port {e['port']}", ""]
    lines.append("")
    return "\n".join(lines)


def render(plan_items):
    return _render(plan_items)


def render_installed(plan_items):
    return _render(plan_items, installed=True)


def write_preview(plan_items, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(plan_items))
    return path
