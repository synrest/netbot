"""Explicit, fail-closed adoption of an observed node into topology intent."""
from pathlib import Path
from typing import Any
import re

NON_CHANGES = [
    "hostname, Tailscale name, tags, enrollment, Tailscale SSH",
    "authorized_keys, sshd, Unix user, host keys, sudo, agent-temporary",
    "IP addresses and UTM configuration",
]

def adoption_plan(result: dict[str, Any], selector: str, target_identity: str) -> dict[str, Any]:
    candidates = [r for r in result.get("rows", []) if r.get("name") == selector or r.get("dns_name") == selector or selector in (r.get("addresses") or [])]
    conflicts = []
    if len(candidates) != 1:
        return {"state":"blocked", "observed_selector":selector, "target_identity":target_identity, "conflicts":["observed node is not uniquely resolved"], "action":"no mutation"}
    observed = candidates[0]; node_id = observed.get("node_id")
    if not node_id: conflicts.append("observed Tailscale node ID is unavailable")
    desired = result.get("desired", []); target = next((h for h in desired if h.identity == target_identity), None)
    if target and target.attrs.get("lifecycle") == "retired": conflicts.append("requested identity is retired")
    if target and target.attrs.get("superseded_by"): conflicts.append("requested identity is superseded")
    for host in desired:
        binding = host.attrs.get("bindings", {}).get("tailscale", {})
        bound = binding.get("node_id")
        if bound is not None and str(bound) == str(node_id) and host.identity != target_identity: conflicts.append(f"node ID is already bound to active identity {host.identity}")
        if host.identity == target_identity and bound is not None and str(bound) != str(node_id): conflicts.append(f"requested identity is bound to node ID {bound}")
    return {"state":"ready" if not conflicts else "blocked", "observed":{"hostname":observed.get("name"),"node_id":node_id,"addresses":observed.get("addresses",[]),"os":observed.get("os"),"access_state":"unverified; access lifecycle is independent","topology_state":"bound" if target and target.attrs.get("bindings",{}).get("tailscale",{}).get("node_id") else "unbound"}, "proposed":{"topology_identity":target_identity,"node_id":node_id,"desired_mutation":"create/update explicit topology.tailscale.node_id binding","create_identity":target is None}, "conflicts":conflicts,"non_changes":NON_CHANGES,"action":"write topology intent only" if not conflicts else "no mutation"}

def apply_adoption(config: Path, plan: dict[str, Any], current_result: dict[str, Any]) -> dict[str, Any]:
    if plan.get("state") != "ready": return {"state":"blocked","reason":"adoption plan is not ready"}
    current = adoption_plan(current_result, plan["observed"]["hostname"], plan["proposed"]["topology_identity"])
    if current.get("state") != "ready" or str(current["observed"].get("node_id")) != str(plan["observed"].get("node_id")):
        return {"state":"stale_plan","reason":"current observed identity or conflicts differ"}
    identity = plan["proposed"]["topology_identity"]; node_id = str(plan["observed"]["node_id"]); name = plan["observed"]["hostname"]
    text = config.read_text()
    host_match = re.search(rf"^  {re.escape(identity)}:\n", text, re.MULTILINE)
    if host_match and re.search(rf"^        node_id: [\"']?{re.escape(node_id)}[\"']?\s*$", text, re.MULTILINE):
        return {"state":"already_adopted","node_id":node_id,"topology_identity":identity}
    block = f'  {identity}:\n    class: unknown\n    bindings:\n      tailscale:\n        node_id: "{node_id}"\n        name: {name}\n'
    if host_match:
        next_host = re.search(r"^  [^ ]+:\n", text[host_match.end():], re.MULTILINE)
        end = host_match.end() + next_host.start() if next_host else len(text)
        segment = text[host_match.start():end]
        if "      tailscale:" not in segment:
            replacement = segment.rstrip() + "\n    bindings:\n      tailscale:\n        node_id: \"" + node_id + "\"\n        name: " + name + "\n"
            text = text[:host_match.start()] + replacement + text[end:]
        else:
            return {"state":"blocked","reason":"existing topology tailscale binding requires explicit conflict review"}
    else:
        text = text.rstrip() + "\n" + block
    config.write_text(text)
    return {"state":"adopted","node_id":node_id,"topology_identity":identity}
