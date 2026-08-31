import argparse, json, os, sys
from pathlib import Path
from .config import load_topology, load_agent_settings
from .discovery.ssh import inspect_ssh
from .reconcile import reconcile, generate, migration_plan
from .generate.ssh import plan as ssh_plan, write_preview
from .activation import build_plan, dry_run as activation_dry_run, apply as activation_apply, drift as activation_drift
from .migration import apply_migration
from .discovery.agent import observe_agent
from .agent import update_plan, version_state
from .authority import host_capabilities
from .bootstrap import bootstrap_plan, bootstrap_eligibility, bootstrap_provider, observe_teardown_capability, execute_live_bootstrap, Eligibility
from .adoption import adoption_plan, apply_adoption
from .state import State
from .reconcile import now
from .sync import run_sync
from .service import start as service_start, stop as service_stop, restart as service_restart, status as service_status
from .doctor import diagnose
from .version import __version__
from .snapshot import build_snapshot, compare_snapshot, persist_snapshot, export_snapshot, fetch_snapshot, resolve_authority
from .discovery.remote_ssh import inspect_target
from .discovery.tailscale import discover
from .target_view import build_ssh_view
from .peer_policy import expected_peers, load_peer_policy, PolicyValidationError
from .render_target import render_target
from .apply_target import build_apply_plan, apply_target

def main(argv=None):
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    p=argparse.ArgumentParser(prog="netbot"); p.add_argument("--version",action="version",version=__version__); p.add_argument("command",choices=["version","doctor","status","topology","discover","diff","reconcile","sync","inspect","access","bindings","ssh","ssh-plan","ssh-apply","ssh-status","migrate-plan","migrate","agent","bootstrap","adopt","enroll","service"]); p.add_argument("host",nargs="?"); p.add_argument("target",nargs="?"); p.add_argument("candidate",nargs="?"); p.add_argument("--as",dest="topology_identity"); p.add_argument("--path",choices=["ssh","tailscale"]); p.add_argument("--user"); p.add_argument("--reason",choices=["manual","launch","calendar","ipn","followup"],default="manual"); p.add_argument("--probe",action="store_true",help="explicitly perform harmless SSH probes"); p.add_argument("--dry-run",action="store_true",help="show changes without writing"); p.add_argument("--export",action="store_true",help="export the persisted topology snapshot"); p.add_argument("--config",type=Path,default=Path("config/topology.yaml")); p.add_argument("--db",type=Path,default=Path("state/netbot.sqlite3")); p.add_argument("--generated",type=Path,default=Path("generated/topology.json")); a=p.parse_args(argv)
    if a.command == "enroll":
        if len(raw_argv) != 1:
            p.error("usage: netbot enroll")
        print("Infrastructure / server:\n  sudo tailscale up --ssh --advertise-tags=tag:netbot-bootstrap\n\nPersonal / end-user:\n  sudo tailscale up --ssh\n\nAlready enrolled:\n  sudo tailscale set --ssh\n\nNetbot will discover the node after it joins the tailnet.")
        return
    if a.command == "version":
        if a.host or a.target:
            p.error("usage: netbot version")
        print(__version__)
        return
    if a.command == "doctor":
        if a.host or a.target:
            p.error("usage: netbot doctor")
        print(json.dumps(diagnose(), indent=2))
        return
    if a.command == "sync":
        if a.host or a.target or a.probe or a.dry_run:
            p.error("usage: netbot sync [--reason REASON]")
        print(json.dumps(run_sync(a.config, a.db, Path.home(), a.generated,
                                  reason=a.reason), indent=2))
        return
    if a.command == "ssh":
        if a.host == "inspect-target":
            if not a.target or not a.candidate:
                p.error("usage: netbot ssh inspect-target TARGET CANDIDATE")
            print(json.dumps(inspect_target(str(a.config), a.target, a.candidate).as_dict(), indent=2, sort_keys=True))
            return
        if a.host == "diff-target":
            if not a.target or a.candidate:
                p.error("usage: netbot ssh diff-target TARGET")
            nodes, error = discover()
            observed = [] if error else [{"identity": node.name, "status": "present", "name": node.name,
                                          "dns_name": node.dns_name, "addresses": node.addresses}
                                         for node in nodes]
            view = build_ssh_view(a.config, a.target, observed)
            if error:
                view = type(view)(view.target_identity, "UNAVAILABLE", view.relationships, error)
            print(json.dumps(view.as_dict(), indent=2, sort_keys=True))
            return
        if a.host == "expected-target":
            if not a.target or a.candidate:
                p.error("usage: netbot ssh expected-target TARGET")
            try:
                _, desired = load_topology(a.config)
                policy = load_peer_policy(a.config)
                result = expected_peers(a.target, desired, policy)
            except PolicyValidationError as exc:
                print(json.dumps({"source_identity": a.target, "state": "INVALID_POLICY",
                                  "reason": str(exc), "peers": [], "excluded": []}, indent=2, sort_keys=True))
                return
            payload = result.as_dict()
            if policy is None:
                payload["peer_policy"] = "NOT_DECLARED"
            else:
                payload["peer_policy"] = "DECLARED"
            print(json.dumps(payload, indent=2, sort_keys=True))
            return
        if a.host == "render-target":
            if not a.target or a.candidate:
                p.error("usage: netbot ssh render-target TARGET")
            result = render_target(a.config, a.target)
            if result.state == "RENDERABLE":
                print(result.text, end="")
            else:
                print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
            return
        if a.host == "apply-target":
            if not a.target:
                p.error("usage: netbot ssh apply-target TARGET [--dry-run]")
            plan = build_apply_plan(a.config, a.target, db_path=a.db)
            if a.dry_run:
                print(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
            else:
                print(json.dumps(apply_target(plan, a.config), indent=2, sort_keys=True))
            return
        p.error("usage: netbot ssh {inspect-target TARGET CANDIDATE|diff-target TARGET|render-target TARGET}")
        return
    if a.command == "service":
        actions = {"start": service_start, "stop": service_stop,
                   "restart": service_restart, "status": service_status}
        if a.host not in actions or a.target:
            p.error("usage: netbot service {start|stop|restart|status}")
        result = actions[a.host]()
        print(json.dumps(result, indent=2))
        if result.get("ok") is False and a.host != "status":
            raise SystemExit(1)
        return
    if a.command == "bootstrap":
        action = a.host or "status"
        if action not in {"plan", "status", "execute"}:
            p.error("usage: netbot bootstrap {plan|execute} HOST [--user USER]")
        target = a.target or ""
        result = reconcile(a.config, a.db, Path.home(), "bootstrap-plan")
        row = next((x for x in result["rows"] if x.get("identity") == target or x.get("name") == target), None)
        if row is None:
            row = next((x for x in result["unknown"] if x.get("name") == target), None)
        node = next((x for x in result["nodes"] if x.name == target), None)
        if row and "bootstrap_eligibility" in row:
            eligibility = Eligibility(**row["bootstrap_eligibility"])
        elif node:
            eligibility = bootstrap_eligibility(node)
        else:
            eligibility = Eligibility("unknown", "Tailscale peer data", "target not observed")
        user = a.user or next((h.attrs.get("bindings", {}).get("ssh", {}).get("user") for h in result["desired"] if h.identity == target), None)
        host = node.name if node else target
        provider = bootstrap_provider(node) if node else {"provider": "unknown", "state": "unknown", "source": "target not observed"}
        if action == "execute":
            public_key_path = Path.home() / ".ssh" / "id_ed25519_arasaka.pub"
            if not node or not a.user or eligibility.state != "eligible" or provider.get("provider") != "infrastructure":
                print(json.dumps({"state": "discovered_blocked", "reason": "verified infrastructure bootstrap candidate with explicit user required", "target": target, "provider": provider, "eligibility": eligibility.__dict__}, indent=2)); return
            if not public_key_path.is_file():
                print(json.dumps({"state": "discovered_blocked", "reason": "approved controller public key is unavailable", "target": target}, indent=2)); return
            ipv4 = next((ip for ip in node.addresses if "." in ip), node.name)
            prior = State(a.db)
            prior_observation = prior.latest_bootstrap_observation(target, node.node_id)
            prior.close()
            live = execute_live_bootstrap(host=node.name, ordinary_host=ipv4, user=a.user, public_key_path=public_key_path,
                                          resume_host_key_material=(prior_observation or {}).get("host_key_material"), node_id=node.node_id)
            state = State(a.db)
            state.bootstrap_observation(now(), target, live, node.node_id)
            state.bootstrap_event(now(), target, "bootstrap_candidate", {"provider": provider, "eligibility": eligibility.__dict__, "user": a.user, "hostname": node.name}, node.node_id)
            for event in live.get("events", []):
                state.bootstrap_event(now(), target, event["state"], event.get("observation", {}), node.node_id)
            state.close()
            print(json.dumps(live, indent=2)); return
        teardown = observe_teardown_capability(host, user) if node and host and user else {"state": "unknown", "authority": "maintain", "source": "not probed: target identity/user not observed"}
        plan = bootstrap_plan(target, host, user, eligibility, teardown=teardown, ssh_observed=None, provider=provider)
        state = State(a.db)
        state.bootstrap_observation(now(), target, plan)
        state.close()
        print(json.dumps(plan, indent=2)); return
    if a.command == "adopt":
        action = a.host or "plan"
        if action not in {"plan", "apply"} or not a.target or not a.topology_identity:
            p.error("usage: netbot adopt {plan|apply} OBSERVED-NODE --as TOPOLOGY-ID")
        result = reconcile(a.config, a.db, Path.home(), "adoption-plan")
        plan = adoption_plan(result, a.target, a.topology_identity)
        if action == "plan" or a.dry_run:
            print(json.dumps(plan, indent=2)); return
        current = reconcile(a.config, a.db, Path.home(), "adoption-apply-reobserve")
        applied = apply_adoption(a.config, plan, current)
        if applied.get("state") == "adopted":
            state = State(a.db); state.adoption_event(now(), a.topology_identity, plan["observed"]["node_id"], plan["observed"]["hostname"], {"source":"explicit human-authorized adoption"}); state.close()
        print(json.dumps({"plan": plan, "result": applied}, indent=2)); return
    if a.command=="agent":
        action=a.host or "status"
        _, desired=load_topology(a.config); settings=load_agent_settings(a.config)
        desired_version=settings.get("temporary_desired_version")
        if action == "status":
            identities=[a.target] if a.target else [h.identity for h in desired if h.attrs.get("bindings",{}).get("ssh",{}).get("aliases")]
            results=[]; state=State(a.db)
            for identity in identities:
                observation=observe_agent(identity)
                state.agent_observation(now(),identity,observation)
                result={"host":identity,"installed":observation.get("installed"),"version":observation.get("version"),"desired_version":desired_version,"version_state":version_state(desired_version,observation),**observation}
                result["authority"]=host_capabilities(observation,True if observation.get("status")=="available" else None)
                result["maintenance_authorized"]=result["authority"]["maintain"]=="available"
                results.append(result)
            state.close()
            print(json.dumps(results[0] if a.target else results,indent=2)); return
        if action == "update":
            if not a.target or not a.dry_run:
                p.error("usage: netbot agent update HOST --dry-run")
            observation=observe_agent(a.target)
            state=State(a.db); state.agent_observation(now(),a.target,observation); state.close()
            print(json.dumps(update_plan(a.target,desired_version,observation,ssh_observed=True if observation.get("status")=="available" else None),indent=2)); return
        p.error("usage: netbot agent status [HOST] or netbot agent update HOST --dry-run")
    if a.command=="topology":
        if a.host == "snapshot":
            if a.target:
                p.error("usage: netbot topology snapshot")
            state = State(a.db)
            if a.export:
                snapshot = export_snapshot(state)
                authority, _ = resolve_authority(a.config)
                if snapshot is None or authority is None:
                    print(json.dumps({"error": "no persisted snapshot or explicit authority available"}, sort_keys=True))
                    state.close()
                    return
                print(json.dumps({"source_authority": authority["identity"], "snapshot": snapshot}, ensure_ascii=False, sort_keys=True))
                state.close()
                return
            previous = state.latest_topology_snapshot()
            snapshot = build_snapshot(a.config)
            comparison = compare_snapshot(snapshot, previous)
            persist_snapshot(state, snapshot)
            state.close()
            print(json.dumps({"schema": snapshot["schema"], "version": snapshot["version"], "content_hash": snapshot["content_hash"],
                              "comparison": comparison, "generated_at": snapshot["generated_at"]}, indent=2))
            return
        if a.host == "fetch":
            if a.target or a.export:
                p.error("usage: netbot topology fetch")
            state = State(a.db)
            result = fetch_snapshot(a.config, state)
            state.close()
            print(json.dumps(result, indent=2, sort_keys=True))
            return
        version,hosts=load_topology(a.config); print(json.dumps({"version":version,"hosts":[{"identity":h.identity,**h.attrs} for h in hosts]},indent=2)); return
    if a.command=="bindings":
        _,hosts=load_topology(a.config); print(json.dumps([{"identity":h.identity,"binding":h.attrs.get("bindings",{}),"provenance":"explicit topology binding" if h.attrs.get("bindings") else "none"} for h in hosts],indent=2)); return
    if a.command=="migrate-plan":
        r=reconcile(a.config,a.db,Path.home(),a.command); print(json.dumps(migration_plan(r,a.host,a.target),indent=2)); return
    if a.command=="migrate":
        result=apply_migration(a.config,a.db,Path.home(),a.host,a.target); print(json.dumps({"status":result["status"],"source":result["source"],"target":result["target"],"node_id":result["node_id"],"backup":result["backup"],"ssh_activation":result["ssh_activation"],"ssh_probe":result["ssh_probe"]},indent=2)); return
    selected_path=a.path if a.path else ("ssh" if (a.probe or a.command=="access") else None)
    r=reconcile(a.config,a.db,Path.home(),a.command,probe=a.probe or a.command=="access",selected_path=selected_path,selected_identity=a.host,probe_user=a.user)
    if a.command in ("ssh-apply","ssh-status"):
        activation=build_plan(r,Path.home())
        if a.command=="ssh-status": print(json.dumps({"include_active":activation["include_present"],"installed_file":str(activation["installed"]),"drift":activation_drift(activation)},indent=2)); return
        if a.dry_run: print(json.dumps(activation_dry_run(activation),indent=2)); return
        print(json.dumps(activation_apply(activation),indent=2)); return
    if a.command=="discover": print(json.dumps({"observer_status":r["observer_status"],"observer_error":r["error"],"nodes":r["rows"],"unknown_nodes":r["unknown"],"ssh_aliases":r["ssh_aliases"]},indent=2))
    elif a.command=="diff": print(json.dumps({"observer_status":r["observer_status"],"message":"network state could not be observed" if r["error"] else None,"changes":r["changes"]},indent=2))
    elif a.command=="reconcile": generate(r,a.generated); print(f"reconciliation {r['run_id']} complete; observer={r['observer_status']} known={r['summary']['known']} unknown={r['summary']['unknown']} absent={r['summary']['absent']} unavailable={r['summary']['observer_unavailable']}")
    elif a.command=="status":
        topology=r.get("topology",{})
        print(f"NETBOT\ncontroller: {r.get('controller_identity') or os.uname().nodename}\nauthority: {topology.get('authority')}\ntopology source: {topology.get('source')}\ntopology state: {topology.get('state')}\nlocal topology hash: {topology.get('effective_hash')}\nobserver: {r['observer_status']}\nknown: {r['summary']['known']}\nunknown nodes: {r['summary']['unknown']}\nabsent: {r['summary']['absent']}\nunavailable: {r['summary']['observer_unavailable']}\nlast reconcile: {r['last']['completed_at'] if r['last'] else 'never'}")
    elif a.command=="inspect":
        h=next((x for x in r["desired"] if x.identity==a.host),None); print(json.dumps({"topology_identity":a.host,"observer_status":r["observer_status"],"topology":r.get("topology"),"desired":h.attrs if h else None,"observed":next((x for x in r["rows"] if x["identity"]==a.host),None),"ssh":[s for s in r["ssh_aliases"] if s["alias"]==a.host],"access_paths":[x for x in r["access_paths"] if x.get("identity")==a.host],"diff":[x for x in r["changes"] if x.get("identity")==a.host]},indent=2))
    elif a.command=="access":
        paths=[x for x in r["access_paths"] if a.host is None or x.get("identity")==a.host]
        print(json.dumps({"probe_requested":True,"paths":paths,"adoption":{k:v for k,v in r.get("adoption",{}).items() if a.host is None or k==a.host}},indent=2))
    elif a.command=="ssh-plan":
        items=ssh_plan(r); write_preview(items,Path("generated/50-netbot.conf")); print(json.dumps(items,indent=2)); print("preview: generated/50-netbot.conf (not installed)")

if __name__ == "__main__": main()
