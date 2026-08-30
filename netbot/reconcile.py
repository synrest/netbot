from datetime import datetime, timezone
import json
from pathlib import Path
from .config import load_topology
from .discovery.tailscale import discover, short_dns_name
from .discovery.ssh import inspect_ssh, public_key_inventory, classify_aliases, effective_config, probe_ssh, probe_endpoint, known_host_fingerprints
from .state import State
from .bootstrap import bootstrap_eligibility, bootstrap_provider, adoption_decision

def now(): return datetime.now(timezone.utc).isoformat()

def identity_match(desired, node):
    bindings=desired.attrs.get("bindings",{}).get("tailscale",{})
    if bindings.get("node_id") is not None and str(bindings.get("node_id")) == str(node.node_id):
        drift=bool(bindings.get("name") and bindings.get("name") != node.name)
        return "explicit", "topology.tailscale.node_id", ("hostname-drift" if drift else "mapped"), drift
    names={node.name, short_dns_name(node.dns_name)}
    if bindings.get("node_id") is not None and (bindings.get("name") in names):
        return None, "topology.tailscale.node_id conflict", "conflict", False
    if bindings.get("name") and bindings.get("name") in names:
        return "high", "topology.tailscale.name", "mapped", False
    if desired.identity in names:
        return "high", "exact observed name", "mapped", False
    return None, None, "unknown", False

def reconcile(config: Path, db_path: Path, home: Path, reason="cli", probe=False, selected_path=None, selected_identity=None, probe_user=None):
    _, desired = load_topology(config); state=State(db_path); state.save_desired(desired)
    started=now(); run=state.begin(started,reason); nodes,error=discover(); ssh,includes=inspect_ssh(home)
    observer_status = "observer-unavailable" if error else "available"
    by_name={x.identity:x for x in desired}; matched=set(); rows=[]; changes=[]; event_candidates=[]; unknown=[]; migration_candidates=[]
    for node in nodes:
        explicit=[h for h in desired if str(h.attrs.get("bindings",{}).get("tailscale",{}).get("node_id")) == str(node.node_id) and h.attrs.get("bindings",{}).get("tailscale",{}).get("node_id") is not None]
        names={node.name,short_dns_name(node.dns_name)}; named=[h for h in desired if h.identity in names or h.attrs.get("bindings",{}).get("tailscale",{}).get("name") in names]
        ambiguous=len(explicit)>1 or (not explicit and len({h.identity for h in named})>1)
        identity=None; confidence=None; mapping_source=None; mapping_status="unknown"; hostname_drift=False
        if not ambiguous and explicit:
            identity=explicit[0].identity; confidence="explicit"; mapping_source="topology.tailscale.node_id"; mapping_status="mapped"; hostname_drift=bool(explicit[0].attrs.get("bindings",{}).get("tailscale",{}).get("name") != node.name)
        elif not ambiguous and named:
            candidate=named[0]; result=identity_match(candidate,node)
            if result[2] != "conflict": identity=candidate.identity; confidence=result[0]; mapping_source=result[1]; mapping_status=result[2]; hostname_drift=result[3]
            else: mapping_source=result[1]; mapping_status="conflict"
        if identity: matched.add(identity)
        eligibility = bootstrap_eligibility(node)
        provider = bootstrap_provider(node)
        if not identity: unknown.append({"name":node.name,"dns_name":node.dns_name,"node_id":node.node_id,"addresses":node.addresses,"online":node.online,"os":node.os,"reason":"ambiguous identity" if ambiguous else mapping_status,"bootstrap_eligibility":eligibility.__dict__,"bootstrap_provider":provider})
        rows.append({"identity":identity,"mapping_confidence":confidence,"mapping_source":mapping_source,"mapping_status":"ambiguous" if ambiguous else mapping_status,"hostname_drift":hostname_drift,"node_id":node.node_id,"name":node.name,"dns_name":node.dns_name,"addresses":node.addresses,"online":node.online,"os":node.os,"last_seen":node.last_seen,"status":"present","bootstrap_eligibility":eligibility.__dict__,"bootstrap_provider":provider})
        if identity: event_candidates.append({"kind":"expected_present","identity":identity})
        if hostname_drift: changes.append({"kind":"hostname_drift","identity":identity,"observed_name":node.name})
        if identity and node.name in by_name and node.name != identity and node.name not in matched:
            candidate={"from_identity":identity,"to_identity":node.name,"node_id":node.node_id,"observed_name":node.name,"confidence":"high","evidence":["explicit durable Tailscale node ID matched source","observed Tailscale name matches unbound target identity"],"action":"human approval required"}
            migration_candidates.append(candidate); changes.append({"kind":"identity_migration_candidate",**candidate})
    if error:
        for h in desired: rows.append({"identity":h.identity,"status":"observer-unavailable"})
    else:
        for h in desired:
            if h.identity not in matched and h.attrs.get("lifecycle") == "retired":
                rows.append({"identity":h.identity,"status":"retired","superseded_by":h.attrs.get("superseded_by")})
            elif h.identity not in matched:
                candidate=next((x for x in migration_candidates if x["to_identity"]==h.identity),None)
                if candidate: rows.append({"identity":h.identity,"status":"unbound","migration_candidate":candidate})
                else: rows.append({"identity":h.identity,"status":"absent"}); changes.append({"kind":"expected_absent","identity":h.identity})
    for u in unknown: changes.append({"kind":"unknown_node","identity":None,"node":u})
    topology_alias_claims={}
    for host in desired:
        for alias_name in host.attrs.get("bindings", {}).get("ssh", {}).get("aliases", []):
            topology_alias_claims.setdefault(alias_name, set()).add(host.identity)
    for alias_name, owners in sorted(topology_alias_claims.items()):
        if len(owners) > 1:
            changes.append({"kind":"topology_ssh_alias_conflict", "identity":None,
                            "alias":alias_name, "owners":sorted(owners),
                            "reason":"SSH alias claimed by multiple topology identities"})
    current_changes=list(changes)
    events=[c for c in event_candidates + current_changes if not state.known_change(c)]
    summary={"known":len(matched),"unknown":len(unknown),"absent":len(desired)-len(matched) if not error else 0,"observer_unavailable":len(desired) if error else 0}
    summary["topology_conflicts"]=sum(1 for owners in topology_alias_claims.values() if len(owners)>1)
    aliases=classify_aliases(ssh,nodes); known_hosts=known_host_fingerprints(home)
    controller_identity=next((r.get("identity") for r, node in zip(rows, nodes)
                              if node.raw.get("_netbot_self") and r.get("identity")), None)
    access_paths=[]
    ssh_identity_by_alias={alias_name: next(iter(owners))
                          for alias_name, owners in topology_alias_claims.items()
                          if len(owners) == 1}
    node_by_identity={r.get("identity"):r for r in rows if r.get("identity") and r.get("name")}
    for alias in aliases:
        identity=ssh_identity_by_alias.get(alias["alias"]) or (alias["alias"] if alias["alias"] in by_name else None)
        path={"identity":identity,"kind":"ssh","name":alias["alias"],"endpoint":f'{alias["target"]}:{alias["port"]}',"user":alias["user"],"source":"existing-ssh-config","classification":alias["classification"],"tested":False,"result":"unknown"}
        path["effective_config"]=effective_config(alias["alias"])
        effective_host=path["effective_config"].get("effective",{}).get("hostname",alias["target"])
        host_candidates={effective_host, alias["target"], f"[{effective_host}]:{alias['port']}"}
        path["known_host_keys"]=[entry for entry in known_hosts.get("entries",[]) if entry["host"] in host_candidates]
        if probe:
            path["probe"]=probe_ssh(alias["alias"]); path["tested"]=True; path["result"]=path["probe"]["status"]
        access_paths.append(path)
    for identity,node in node_by_identity.items():
        path={"identity":identity,"kind":"tailscale","name":"tailscale","endpoint":node["name"],"user":probe_user,"source":"observed-tailscale","tested":False,"result":"unknown","node_id":node["node_id"],"tailscale_ip":node["addresses"],"eligible":next((x for x in rows if x.get("identity")==identity),{}).get("bootstrap_eligibility",{}).get("state")=="eligible"}
        if probe and selected_path == "tailscale" and identity == selected_identity:
            endpoint=next((ip for ip in node["addresses"] if "." in ip),None) or node["name"]
            path["probe_endpoint"]=endpoint
            path["probe"]=probe_endpoint(endpoint,user=probe_user); path["tested"]=True; path["result"]=path["probe"]["status"]
        access_paths.append(path)
    adoption={}
    for row in rows:
        identity=row.get("identity")
        if not identity:
            continue
        paths=[x for x in access_paths if x.get("identity")==identity]
        ordinary=next((x for x in paths if x.get("kind")=="ssh"),None)
        tailscale=next((x for x in paths if x.get("kind")=="tailscale"),None)
        desired_host=by_name.get(identity)
        user=(ordinary or {}).get("user") or (desired_host.attrs.get("bindings",{}).get("ssh",{}).get("user") if desired_host else None)
        decision=adoption_decision(identity=identity, identity_status=row.get("mapping_status","unknown"), ordinary_openssh=ordinary, tailscale_ssh=tailscale, intended_user=user, host_key_state="unknown")
        adoption[identity]=decision
        row["adoption"] = decision
    state.observations(started,rows); state.changes(run,started,events); state.access_observations(started,access_paths)
    state.finish(run,now(),error is None,summary,observer_status,error)
    last=state.latest(); state.close()
    return {"desired":desired,"nodes":nodes,"ssh":ssh,"ssh_aliases":aliases,"known_hosts":known_hosts,"access_paths":access_paths,"adoption":adoption,"includes":includes,"keys":public_key_inventory(home),"rows":rows,"unknown":unknown,"migration_candidates":migration_candidates,"changes":current_changes,"events":events,"error":error,"observer_status":observer_status,"run_id":run,"summary":summary,"last":last}

def migration_plan(result, source, target):
    candidate=next((x for x in result["migration_candidates"] if x["from_identity"]==source and x["to_identity"]==target),None)
    observed=next((x for x in result["rows"] if x.get("identity")==source and x.get("name")),None)
    source_host=next((x for x in result["desired"] if x.identity==source),None)
    target_host=next((x for x in result["desired"] if x.identity==target),None)
    alias=next((x for x in result["ssh_aliases"] if x["alias"]==source),None)
    return {"source":{"identity":source,"binding":source_host.attrs.get("bindings",{}) if source_host else None},"target":{"identity":target,"binding":target_host.attrs.get("bindings",{}) if target_host else None,"currently_unbound":target_host is not None and not target_host.attrs.get("bindings")},"observed":observed,"candidate":candidate,"proposed":{"transfer_tailscale_binding":f"{source} -> {target}","preserve_unix_ssh_user":alias.get("user") if alias else None,"future_ssh_alias":{"alias":target,"hostname":target,"user":alias.get("user") if alias else None},"old_ssh_alias":"human decision required","apply":"not implemented"}}

def generate(result, path: Path):
    path.parent.mkdir(parents=True,exist_ok=True)
    hosts=[]
    for h in result["desired"]:
        obs=next((x for x in result["rows"] if x["identity"]==h.identity),None)
        hosts.append({"identity":h.identity,"desired":h.attrs,"observed":obs,"status":obs.get("status","unknown") if obs else "unknown","ssh_aliases":[s["alias"] for s in result["ssh_aliases"] if s["alias"]==h.identity]})
    path.write_text(json.dumps({"version":1,"generated_at":now(),"observer_status":result["observer_status"],"observer_error":result["error"],"hosts":hosts,"unknown_nodes":result["unknown"],"ssh_aliases":result["ssh_aliases"],"access_paths":result["access_paths"]},indent=2,sort_keys=True)+"\n")
