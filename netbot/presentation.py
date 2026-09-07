"""Read-only operator views over existing Netbot state and result objects."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import load_topology, load_topology_authority
from .scheduler import status as scheduler_status
from .version import __version__


SCHEMA = "netbot.cli/v1"


def _connect(path: Path):
    if not path.exists():
        return None
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error:
        return None


def _one(connection, query: str, args=()):
    if connection is None:
        return None
    try:
        row = connection.execute(query, args).fetchone()
        return dict(row) if row else None
    except sqlite3.Error:
        return None


def _many(connection, query: str, args=()):
    if connection is None:
        return []
    try:
        return [dict(row) for row in connection.execute(query, args)]
    except sqlite3.Error:
        return []


def _json(value, default=None):
    try:
        return json.loads(value) if value is not None else default
    except (TypeError, json.JSONDecodeError):
        return default


def _db_data(db: Path) -> dict[str, Any]:
    connection = _connect(db)
    try:
        controller = _one(connection, "SELECT value FROM controller_identity WHERE id=1")
        discovery = _one(connection, "SELECT * FROM discovery_runs ORDER BY completed_at DESC LIMIT 1")
        reconciliation = _one(connection, "SELECT * FROM reconciliations ORDER BY id DESC LIMIT 1")
        events = _many(connection, """SELECT event_id,event_type,severity,subject_identity,summary,
            first_seen_at,last_seen_at,occurrence_count,resolved_at,stable_key
            FROM events ORDER BY (resolved_at IS NULL) DESC,
            CASE severity WHEN 'ERROR' THEN 0 WHEN 'ATTENTION' THEN 1 ELSE 2 END,
            last_seen_at DESC,event_id DESC LIMIT 10""")
        nodes = []
        relationships = []
        if discovery:
            nodes = _many(connection, "SELECT * FROM discovery_node_evidence WHERE run_id=? ORDER BY id", (discovery["run_id"],))
            relationships = _many(connection, "SELECT * FROM discovery_relationship_evidence WHERE run_id=? ORDER BY id", (discovery["run_id"],))
            for node in nodes:
                node["addresses"] = _json(node.pop("addresses_json", "[]"), [])
                node["metadata"] = _json(node.pop("metadata_json", "{}"), {})
            for relationship in relationships:
                relationship["effective"] = _json(relationship.pop("effective_json", "{}"), {})
        return {"controller_id": controller["value"] if controller else None,
                "discovery": discovery, "reconciliation": reconciliation,
                "events": events, "nodes": nodes, "relationships": relationships}
    finally:
        if connection is not None:
            connection.close()


def _envelope(command: str, data: dict[str, Any], status: str = "OK", warnings=None, errors=None):
    return {"schema": SCHEMA, "command": command, "status": status, "data": data,
            "warnings": list(warnings or []), "errors": list(errors or [])}


def _age(value: str | None) -> str:
    if not value:
        return "never"
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        seconds = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds()))
    except (TypeError, ValueError):
        return value
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _latest_provider_state(discovery):
    if not discovery:
        return "never"
    provider = discovery.get("provider_status")
    if provider == "OK":
        return "operational"
    if provider == "FAILED":
        return "failed"
    return "unavailable"


def _provider_info(discovery):
    status = _latest_provider_state(discovery)
    return {"status": status,
            "run_status": (discovery or {}).get("status"),
            "provider_status": (discovery or {}).get("provider_status"),
            "last_run": (discovery or {}).get("completed_at")}


def _active_host(host):
    attrs = host.attrs
    return attrs.get("lifecycle") != "retired" and not attrs.get("superseded_by")


def _topology_data(config: Path, db: Path):
    version, hosts = load_topology(config)
    raw = _db_data(db)
    accepted = []
    bound_ids = set()
    for host in sorted((host for host in hosts if _active_host(host)), key=lambda item: item.identity):
        attrs = dict(host.attrs)
        tailscale = attrs.get("bindings", {}).get("tailscale", {})
        if tailscale.get("node_id") is not None:
            bound_ids.add(("tailscale", str(tailscale["node_id"])))
        accepted.append({"identity": host.identity, **attrs})
    provider_info = _provider_info(raw["discovery"])
    provider_usable = provider_info["provider_status"] == "OK"
    for host in accepted:
        binding = host.get("bindings", {}).get("tailscale", {})
        match = next((node for node in raw["nodes"]
                      if node.get("provider") == "tailscale"
                      and str(node.get("provider_node_id")) == str(binding.get("node_id"))), None)
        host["state"] = ("online" if match and provider_usable and match.get("online") in (True, "True")
                          else "offline" if match and provider_usable and match.get("online") in (False, "False")
                          else "unknown")
    observed = []
    for node in raw["nodes"]:
        if node.get("evidence_key") == raw.get("controller_id") or node.get("observed_from") == raw.get("controller_id") and not node.get("provider_node_id"):
            continue
        candidates = [node]
        if node.get("provider_node_id") is None:
            candidates = node.get("metadata", {}).get("provider_peers", []) or candidates
        for candidate in candidates:
            provider = candidate.get("provider")
            node_id = candidate.get("provider_node_id")
            if not provider or node_id is None:
                continue
            if (provider, str(node_id)) in bound_ids:
                continue
            observed.append({"observation_identity": node.get("evidence_key") or f"{provider}:{node_id}",
                             "provider": provider, "provider_node_id": node_id,
                             "advertised_name": candidate.get("advertised_name"),
                             "addresses": candidate.get("addresses", []),
                             "online": candidate.get("online"),
                             "observed_from": node.get("observed_from"),
                             "observed_at": candidate.get("observed_at") or node.get("observed_at")})
    observed.sort(key=lambda item: (item.get("advertised_name") or "", item.get("observation_identity") or ""))
    attention = [event for event in raw["events"] if event.get("resolved_at") is None and event.get("severity") in {"ERROR", "ATTENTION"}]
    return {"schema": SCHEMA, "command": "topology", "version": version,
            "authority": load_topology_authority(config), "accepted": accepted,
            "observed": observed, "relationships": raw["relationships"],
            "attention": attention, "provider": provider_info}


def dashboard(config: Path, db: Path):
    version, hosts = load_topology(config)
    raw = _db_data(db)
    topology_data = _topology_data(config, db)
    accepted_nodes = topology_data["accepted"]
    unaccepted = topology_data["observed"]
    online = sum(node.get("state") == "online" for node in accepted_nodes)
    offline = sum(node.get("state") == "offline" for node in accepted_nodes)
    unknown = sum(node.get("state") == "unknown" for node in accepted_nodes)
    try:
        scheduler = scheduler_status()
    except Exception:
        scheduler = {"installed": False, "enabled": False, "configured_interval": "unavailable"}
    active_attention = sum(event.get("resolved_at") is None and event.get("severity") in {"ERROR", "ATTENTION"}
                           for event in raw["events"])
    data = {"schema": SCHEMA, "command": "dashboard", "controller": load_topology_authority(config) or raw["controller_id"],
            "controller_id": raw["controller_id"], "version": __version__,
            "topology": "OK" if accepted_nodes else "EMPTY", "nodes": len(accepted_nodes),
            "online": online, "offline": offline, "unknown": unknown, "observed": len(unaccepted),
            "attention": active_attention,
            "last_maintain": _age((raw["reconciliation"] or {}).get("completed_at")),
            "provider": _latest_provider_state(raw["discovery"]),
            "provider_detail": _provider_info(raw["discovery"]),
            "scheduler": {"installed": scheduler.get("installed", False),
                          "enabled": scheduler.get("enabled", False),
                          "interval": scheduler.get("configured_interval", "unavailable")}}
    return data


def status(config: Path, db: Path):
    data = dashboard(config, db)
    data["command"] = "status"
    data["database"] = "OK" if db.exists() else "not initialized"
    data["last_maintain"] = _age((_db_data(db)["reconciliation"] or {}).get("completed_at"))
    return _envelope("status", data, "OK")


def topology(config: Path, db: Path):
    return _topology_data(config, db)


def inspect(config: Path, db: Path, identity: str):
    data = _topology_data(config, db)
    accepted = next((item for item in data["accepted"] if item["identity"] == identity), None)
    observed = next((item for item in data["observed"] if identity in {item.get("observation_identity"), item.get("advertised_name"), *(item.get("addresses") or [])}), None)
    relationships = [item for item in data["relationships"] if item.get("source") == identity or item.get("destination") == identity or item.get("alias") == identity]
    raw = _db_data(db)
    payload = {"schema": SCHEMA, "command": "inspect", "topology_identity": identity,
               "state": "ACCEPTED" if accepted else ("OBSERVED" if observed else "UNKNOWN"),
               "topology": {"authority": data["authority"], "accepted": accepted},
               "controller_id": raw.get("controller_id"),
               "observed": observed, "relationships": relationships}
    return payload


def events(config: Path, db: Path):
    return {"schema": SCHEMA, "command": "events", "events": _db_data(db)["events"]}


def _symbol(state):
    return {"online": "●", "offline": "○", "observed": "◇", "attention": "!"}.get(state, "·")


def render_dashboard(data):
    content_width = 44
    label = f"{data.get('controller') or 'controller unavailable'} · controller"
    if len(label) > content_width:
        label = label[:content_width - 1] + "…"
    top_fill = "─ NETBOT " + "─" * (content_width + 2 - len("─ NETBOT "))
    box = ("╭" + top_fill + "╮\n"
           f"│ {label:<{content_width}} │\n"
           "╰" + "─" * (content_width + 2) + "╯\n\n")
    unknown = f"  Unknown        {data['unknown']}\n" if data.get("unknown") else ""
    return (box +
            f"  Topology       {data['topology']}\n  Nodes          {data['nodes']}\n"
            f"  Online         {data['online']}\n  Offline        {data['offline']}\n"
            f"{unknown}  Observed       {data['observed']}\n  Attention      {data['attention']}\n\n"
            f"  Last maintain  {data['last_maintain']}\n"
            f"  Scheduler      {'● every ' + str(data['scheduler']['interval']) if data['scheduler'].get('enabled') else 'not installed'}\n\n"
            "  Run `netbot topology` to explore the network.\n")


def render_status(payload):
    data = payload["data"]
    scheduler = data["scheduler"]
    sched = ("enabled · " + str(scheduler["interval"]) if scheduler.get("enabled") else
             "installed · disabled" if scheduler.get("installed") else "not installed")
    return ("NETBOT STATUS\n\n"
            f"Controller     {data.get('controller') or 'unavailable'}\nVersion        {data['version']}\n"
            f"Topology       {data['topology']}\nDatabase       {data['database']}\n"
            f"Provider       {data['provider']}\nScheduler      {sched}\n\n"
            f"Last maintain  {data['last_maintain']}\nAttention      {data['attention']}\n")


def render_topology(data):
    accepted = data["accepted"]
    authority = data.get("authority")
    lines = ["NETBOT TOPOLOGY", ""]
    if not accepted and not data["observed"]:
        lines.append("  No accepted or observed nodes.")
    else:
        peers = [host for host in accepted if host["identity"] != authority]
        if authority:
            lines += [f"{authority.upper():^60}", f"{'● controller':^60}", f"{'│':^60}"]
        for offset in range(0, len(peers), 3):
            group = peers[offset:offset + 3]
            width, gap = 16, 3
            start = max(0, (60 - (width * len(group) + gap * (len(group) - 1))) // 2)
            lines.append(" " * start + "   ".join(host["identity"].upper().center(width) for host in group))
            lines.append(" " * start + "   ".join(((_symbol(host.get("state")) + " " + host.get("state", "unknown")).center(width)) for host in group))
        if data["observed"]:
            lines += ["", "Observed"]
            for node in data["observed"]:
                name = node.get("advertised_name") or node.get("observation_identity") or "unknown"
                state = "online" if node.get("online") in (True, "True") else "offline" if node.get("online") in (False, "False") else "observed"
                lines.append(f"  ◇ {name}  {state}")
    counts = {state: sum(host.get("state") == state for host in accepted) for state in ("online", "offline", "unknown")}
    legend = "  ● online   ○ offline"
    if counts["unknown"]:
        legend += "   · unknown"
    lines += ["", legend + "   ◇ observed   ! attention", "",
              f"  {len(accepted)} known · {counts['online']} online · {counts['offline']} offline"
              + (f" · {counts['unknown']} unknown" if counts["unknown"] else "")
              + f" · {len(data['observed'])} observed · {len(data['attention'])} conflicts"]
    return "\n".join(lines) + "\n"


def render_inspect(data):
    identity = data["topology_identity"]
    observed = data.get("observed") or {}
    state = data["state"]
    online = observed.get("online") in (True, "True")
    lines = [f"{identity.upper()}                                      {'● online' if online else '○ offline' if observed else '· unknown'}", "", "Identity",
             f"  Topology       {identity}", f"  State          {state}"]
    accepted = (data.get("topology") or {}).get("accepted") or {}
    bindings = accepted.get("bindings", {})
    if bindings.get("tailscale"):
        lines.append("  Provider       Tailscale")
    if accepted.get("os_family"):
        lines.append(f"  OS             {accepted['os_family']}")
    network = []
    if observed.get("addresses"):
        network.append(f"  Address        {observed['addresses'][0]}")
    if observed.get("observed_at"):
        network.append(f"  Last observed  {_age(observed['observed_at'])}")
    if network:
        lines += ["", "Network", *network]
    access = []
    evidence = []
    for edge in data.get("relationships", []):
        source = edge.get("source")
        if source == data.get("controller_id"):
            source = (data.get("topology") or {}).get("authority") or source
        if source and source != identity:
            access.append((source, edge.get("auth_state", "UNKNOWN"), edge))
            evidence.append(edge)
    if access:
        source = access[0][0]
        lines += ["", f"Access from {source}", f"  SSH            {access[0][1]}"]
    if evidence:
        lines += ["", "Evidence", "  SSH            observed"]
    return "\n".join(lines) + "\n"


def render_events(payload):
    rows = payload["events"]
    active = [row for row in rows if row.get("resolved_at") is None and row.get("severity") in {"ERROR", "ATTENTION"}]
    recent = [row for row in rows if row not in active]
    lines = ["NETBOT EVENTS", ""]
    if not active:
        lines += ["✓ Nothing needs attention", ""]
    else:
        lines += ["ATTENTION", ""]
        for row in active:
            lines += [f"  ◇ {row.get('summary', row.get('event_type'))}  {_age(row.get('last_seen_at'))}",
                      f"    {row.get('subject_identity') or 'unspecified'}"]
            if row.get("event_type") == "NEW_TOPOLOGY_PROPOSAL":
                lines.append("    → netbot inspect " + str(row.get("subject_identity") or "<node>"))
            lines.append("")
    if recent:
        lines += ["RECENT", ""]
        for row in recent:
            symbol = "✓" if row.get("severity") == "INFO" else "○"
            lines.append(f"  {symbol} {row.get('summary', row.get('event_type'))}  {_age(row.get('last_seen_at'))}")
    return "\n".join(lines).rstrip() + "\n"


def render_accept(result):
    requested = result.get("requested_node", "node")
    outcome = result.get("result")
    if outcome in {"ACCEPTED", "WOULD_ACCEPT"}:
        identity = result.get("canonical_identity") or requested
        provider = ((result.get("proposal") or {}).get("provider_binding") or {}).get("provider")
        lines = [f"✓ {'Accepted' if outcome == 'ACCEPTED' else 'Would accept'} {identity}", "",
                 "  State       ACCEPTED"]
        if provider:
            lines.append(f"  Provider    {str(provider).title()}")
        if outcome == "ACCEPTED":
            lines += ["", "Run `netbot maintain --dry-run` to review changes."]
        return "\n".join(lines) + "\n"
    if outcome == "ALREADY_ACCEPTED":
        return f"{requested} is already represented in accepted topology.\n"
    reason = result.get("reason") or "the current observation cannot be accepted"
    return f"Cannot accept {requested}.\n\n{reason}.\nRun `netbot events` to review current attention.\n"


def render_reject(result):
    requested = result.get("requested_node", "node")
    if result.get("result") == "REJECTED":
        return (f"✓ Rejected {requested}\n\n"
                "  Evidence retained\n  Topology unchanged\n\n"
                "Netbot will surface materially different identity evidence.\n")
    if result.get("result") == "ALREADY_REJECTED":
        return f"{requested} was already rejected for the current evidence.\n"
    if result.get("result") == "ALREADY_ACCEPTED":
        return f"Cannot reject {requested}.\n\nThe identity is already accepted in topology.\n"
    reason = result.get("reason") or "the current observation cannot be rejected"
    return f"Cannot reject {requested}.\n\n{reason}.\nRun `netbot events` to review current attention.\n"


def render_maintain(result, verbose=False, config=None, db=None):
    if verbose:
        return json.dumps(result, indent=2, sort_keys=True) + "\n"
    dry = result.get("dry_run")
    summary = result.get("summary", {})
    discovery = result.get("discovery", {})
    proposals = result.get("proposals", {})
    reconciliation = result.get("reconciliation", {})
    status = result.get("status", "UNKNOWN")
    lines = ["NETBOT · DRY RUN" if dry else "NETBOT MAINTENANCE", "",
             f"Discovering network       {'✓' if discovery.get('status') in {'OK', 'PARTIAL'} else '!'}",
             f"Checking topology         {'✓' if proposals is not None else '!'}",
             f"Reconciling SSH           {'✓' if reconciliation.get('status') in {'OK', 'PARTIAL'} else '!'}", ""]
    counts = _topology_data(config, db) if config and db and Path(config).exists() else None
    count_text = None
    if counts:
        active = counts["accepted"]
        provider_unavailable = counts.get("provider", {}).get("provider_status") not in (None, "OK")
        count_text = (f"{len(active)} known · provider state unavailable" if provider_unavailable else
                      f"{len(active)} known · {sum(h.get('state') == 'online' for h in active)} online · {len(counts['observed'])} observed")
    if dry:
        lines += [f"{'✓' if status in {'OK', 'PARTIAL'} else '!'} Topology {'consistent' if status in {'OK', 'PARTIAL'} else status.lower()}",
                  f"  {count_text}" if count_text else "  Network counts unavailable",
                  f"  {summary.get('proposal_count', 0)} proposals · {proposals.get('counts', {}).get('CONFLICT', 0)} conflicts",
                  "  No changes would be made."]
    else:
        changed = summary.get("reconcile_changed", 0)
        lines += [f"{'✓' if status in {'OK', 'PARTIAL'} else '!'} Network {'consistent' if status in {'OK', 'PARTIAL'} else status.lower()}",
                  f"  {summary.get('reconcile_unchanged', 0) + changed} targets · {changed} changes"]
    if result.get("proposals", {}).get("total"):
        lines.append(f"  {result['proposals']['total']} proposals pending")
    return "\n".join(lines) + "\n"


def render_doctor(payload):
    labels = {"python": "Python", "tailscale": "Tailscale", "ssh": "SSH",
              "launchctl": "launchctl", "tailscale-version": "Tailscale version",
              "tailscale-status": "Tailscale status", "topology": "Topology",
              "state": "State", "runtime": "Runtime", "logs": "Logs",
              "supervisor": "Supervisor", "watcher-service": "Watcher service"}
    lines = ["NETBOT DOCTOR", ""]
    for check in payload.get("checks", []):
        symbol = "✓" if check.get("status") == "OK" else "!" if check.get("status") == "ERROR" else "○"
        name = check.get("name", "")
        lines.append(f"{labels.get(name.lower(), name):18} {symbol} {check.get('detail', '')}")
    errors = sum(check.get("status") == "ERROR" for check in payload.get("checks", []))
    lines += ["", "No blocking problems found." if not errors else f"{errors} blocking problem(s) found."]
    return "\n".join(lines) + "\n"
