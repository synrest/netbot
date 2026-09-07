import json, sqlite3, uuid
from pathlib import Path

SCHEMA = """CREATE TABLE IF NOT EXISTS hosts(identity TEXT PRIMARY KEY, desired_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, discovered_at TEXT NOT NULL, identity TEXT, node_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reconciliations(id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT, success INTEGER, reason TEXT, summary_json TEXT);
CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY, reconciliation_id INTEGER, created_at TEXT NOT NULL, kind TEXT NOT NULL, identity TEXT, details_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bootstrap_observations(id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, identity TEXT, node_id TEXT, observation_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bootstrap_events(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, identity TEXT, node_id TEXT, state TEXT NOT NULL, details_json TEXT NOT NULL);"""

class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True); self.db = sqlite3.connect(path); self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        for column, definition in (("observer_status", "TEXT"), ("observer_error", "TEXT")):
            try: self.db.execute(f"ALTER TABLE reconciliations ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError: pass
        # Bootstrap tables were introduced lazily in older releases.  Keep
        # old rows readable while giving positively observed Tailscale nodes
        # a durable, nullable node-ID association.
        for table in ("bootstrap_observations", "bootstrap_events"):
            try:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN node_id TEXT")
            except sqlite3.OperationalError:
                pass
        self.db.commit()
    def save_desired(self, hosts):
        self.db.execute("DELETE FROM hosts")
        self.db.executemany("INSERT OR REPLACE INTO hosts VALUES (?,?)", [(h.identity, json.dumps(h.attrs, sort_keys=True)) for h in hosts]); self.db.commit()
    def save_topology_snapshot(self, snapshot):
        self.db.execute("CREATE TABLE IF NOT EXISTS topology_snapshots(id INTEGER PRIMARY KEY CHECK(id=1), content_hash TEXT NOT NULL, snapshot_json TEXT NOT NULL, generated_at TEXT NOT NULL)")
        payload = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.db.execute("BEGIN")
        try:
            self.db.execute("INSERT INTO topology_snapshots(id,content_hash,snapshot_json,generated_at) VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET content_hash=excluded.content_hash,snapshot_json=excluded.snapshot_json,generated_at=excluded.generated_at", (snapshot["content_hash"], payload, snapshot["generated_at"]))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return snapshot
    def latest_topology_snapshot(self):
        try:
            row = self.db.execute("SELECT snapshot_json FROM topology_snapshots WHERE id=1").fetchone()
        except sqlite3.OperationalError:
            return None
        return json.loads(row[0]) if row else None
    def save_accepted_topology_snapshot(self, snapshot, source_identity, transport, accepted_at=None):
        from datetime import datetime, timezone
        accepted_at = accepted_at or datetime.now(timezone.utc).isoformat()
        self.db.execute("CREATE TABLE IF NOT EXISTS accepted_topology_snapshots(id INTEGER PRIMARY KEY CHECK(id=1), source_identity TEXT NOT NULL, content_hash TEXT NOT NULL, transport TEXT NOT NULL, accepted_at TEXT NOT NULL, snapshot_json TEXT NOT NULL)")
        payload = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.db.execute("BEGIN")
        try:
            self.db.execute("INSERT INTO accepted_topology_snapshots(id,source_identity,content_hash,transport,accepted_at,snapshot_json) VALUES (1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET source_identity=excluded.source_identity,content_hash=excluded.content_hash,transport=excluded.transport,accepted_at=excluded.accepted_at,snapshot_json=excluded.snapshot_json", (source_identity, snapshot["content_hash"], transport, accepted_at, payload))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
    def latest_accepted_topology_snapshot(self):
        try:
            row = self.db.execute("SELECT source_identity,content_hash,transport,accepted_at,snapshot_json FROM accepted_topology_snapshots WHERE id=1").fetchone()
        except sqlite3.OperationalError:
            return None
        if not row:
            return None
        try:
            snapshot = json.loads(row[4])
        except (TypeError, json.JSONDecodeError) as exc:
            return {"source_identity": row[0], "content_hash": row[1], "transport": row[2],
                    "accepted_at": row[3], "snapshot": None, "invalid": True,
                    "reason": "accepted snapshot JSON is invalid: " + str(exc)}
        return {"source_identity": row[0], "content_hash": row[1], "transport": row[2], "accepted_at": row[3], "snapshot": snapshot}
    def save_topology_fetch_status(self, result, checked_at=None):
        from datetime import datetime, timezone
        checked_at = checked_at or datetime.now(timezone.utc).isoformat()
        self.db.execute("CREATE TABLE IF NOT EXISTS topology_fetch_status(id INTEGER PRIMARY KEY CHECK(id=1), checked_at TEXT NOT NULL, result TEXT NOT NULL, authority TEXT, reason TEXT, remote_hash TEXT)")
        self.db.execute("INSERT INTO topology_fetch_status(id,checked_at,result,authority,reason,remote_hash) VALUES (1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET checked_at=excluded.checked_at,result=excluded.result,authority=excluded.authority,reason=excluded.reason,remote_hash=excluded.remote_hash", (checked_at, result.get("result", "UNKNOWN"), result.get("authority"), result.get("reason"), result.get("remote_hash")))
        self.db.commit()
    def latest_topology_fetch_status(self):
        try:
            row = self.db.execute("SELECT checked_at,result,authority,reason,remote_hash FROM topology_fetch_status WHERE id=1").fetchone()
        except sqlite3.OperationalError:
            return None
        return {"checked_at": row[0], "result": row[1], "authority": row[2], "reason": row[3], "remote_hash": row[4]} if row else None
    def begin(self, started, reason):
        cur=self.db.execute("INSERT INTO reconciliations(started_at,reason) VALUES (?,?)",(started,reason)); self.db.commit(); return cur.lastrowid
    def finish(self, run_id, completed, success, summary, observer_status, observer_error):
        self.db.execute("UPDATE reconciliations SET completed_at=?,success=?,summary_json=?,observer_status=?,observer_error=? WHERE id=?",(completed,int(success),json.dumps(summary,sort_keys=True),observer_status,observer_error,run_id)); self.db.commit()
    def observations(self, discovered, rows):
        self.db.executemany("INSERT INTO observations(discovered_at,identity,node_json) VALUES (?,?,?)",[(discovered,r.get("identity"),json.dumps(r,sort_keys=True)) for r in rows]); self.db.commit()
    def changes(self, run_id, created, changes):
        self.db.executemany("INSERT INTO changes(reconciliation_id,created_at,kind,identity,details_json) VALUES (?,?,?,?,?)",[(run_id,created,c["kind"],c.get("identity"),json.dumps(c,sort_keys=True)) for c in changes]); self.db.commit()
    def known_change(self, change):
        detail=json.dumps(change,sort_keys=True)
        return self.db.execute("SELECT 1 FROM changes WHERE kind=? AND identity IS ? AND details_json=? LIMIT 1",(change["kind"],change.get("identity"),detail)).fetchone() is not None
    def access_observations(self, observed_at, paths):
        self.db.execute("CREATE TABLE IF NOT EXISTS access_observations(id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, identity TEXT, path_json TEXT NOT NULL)")
        for path in paths:
            detail=json.dumps(path,sort_keys=True); identity=path.get("identity")
            previous=self.db.execute("SELECT 1 FROM access_observations WHERE identity IS ? AND path_json=? LIMIT 1",(identity,detail)).fetchone()
            if previous is None: self.db.execute("INSERT INTO access_observations(observed_at,identity,path_json) VALUES (?,?,?)",(observed_at,identity,detail))
        self.db.commit()
    def migration(self, created_at, source, target, node_id, reason):
        self.db.execute("CREATE TABLE IF NOT EXISTS migrations(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, from_identity TEXT NOT NULL, to_identity TEXT NOT NULL, node_id TEXT NOT NULL, reason TEXT NOT NULL)")
        self.db.execute("INSERT INTO migrations(created_at,from_identity,to_identity,node_id,reason) VALUES (?,?,?,?,?)",(created_at,source,target,str(node_id),reason)); self.db.commit()
    def agent_observation(self, observed_at, identity, observation):
        self.db.execute("CREATE TABLE IF NOT EXISTS agent_observations(id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, identity TEXT, observation_json TEXT NOT NULL)")
        detail=json.dumps(observation, sort_keys=True)
        previous=self.db.execute("SELECT 1 FROM agent_observations WHERE identity IS ? AND observation_json=? LIMIT 1",(identity,detail)).fetchone()
        if previous is None:
            self.db.execute("INSERT INTO agent_observations(observed_at,identity,observation_json) VALUES (?,?,?)",(observed_at,identity,detail)); self.db.commit()
    def bootstrap_observation(self, observed_at, identity, observation, node_id=None):
        self.db.execute("CREATE TABLE IF NOT EXISTS bootstrap_observations(id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, identity TEXT, node_id TEXT, observation_json TEXT NOT NULL)")
        try: self.db.execute("ALTER TABLE bootstrap_observations ADD COLUMN node_id TEXT")
        except sqlite3.OperationalError: pass
        detail=json.dumps(observation, sort_keys=True)
        previous=self.db.execute("SELECT 1 FROM bootstrap_observations WHERE identity IS ? AND node_id IS ? AND observation_json=? LIMIT 1",(identity,str(node_id) if node_id is not None else None,detail)).fetchone()
        if previous is None:
            self.db.execute("INSERT INTO bootstrap_observations(observed_at,identity,node_id,observation_json) VALUES (?,?,?,?)",(observed_at,identity,str(node_id) if node_id is not None else None,detail)); self.db.commit()
    def bootstrap_event(self, created_at, identity, state, details=None, node_id=None):
        self.db.execute("CREATE TABLE IF NOT EXISTS bootstrap_events(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, identity TEXT, node_id TEXT, state TEXT NOT NULL, details_json TEXT NOT NULL)")
        try: self.db.execute("ALTER TABLE bootstrap_events ADD COLUMN node_id TEXT")
        except sqlite3.OperationalError: pass
        details_json=json.dumps(details or {}, sort_keys=True)
        previous=self.db.execute("SELECT 1 FROM bootstrap_events WHERE identity IS ? AND node_id IS ? AND state=? AND details_json=? LIMIT 1",(identity,str(node_id) if node_id is not None else None,state,details_json)).fetchone()
        if previous is None:
            self.db.execute("INSERT INTO bootstrap_events(created_at,identity,node_id,state,details_json) VALUES (?,?,?,?,?)",(created_at,identity,str(node_id) if node_id is not None else None,state,details_json)); self.db.commit()
    def latest_bootstrap_observation(self, identity, node_id=None):
        try:
            if node_id is None:
                row = self.db.execute("SELECT observation_json FROM bootstrap_observations WHERE identity IS ? AND observation_json LIKE '%host_key_material%' ORDER BY id DESC LIMIT 1", (identity,)).fetchone()
            else:
                row = self.db.execute("SELECT observation_json FROM bootstrap_observations WHERE identity IS ? AND node_id IS ? AND observation_json LIKE '%host_key_material%' ORDER BY id DESC LIMIT 1", (identity, str(node_id))).fetchone()
        except sqlite3.OperationalError:
            return None
        return json.loads(row[0]) if row else None
    def controller_identity(self, create=True):
        if create:
            self.db.execute("CREATE TABLE IF NOT EXISTS controller_identity(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)")
        else:
            try:
                row = self.db.execute("SELECT value FROM controller_identity WHERE id=1").fetchone()
            except sqlite3.OperationalError:
                return None
            return row[0] if row else None
        row = self.db.execute("SELECT value FROM controller_identity WHERE id=1").fetchone()
        if row:
            return row[0]
        if not create:
            return None
        value = uuid.uuid4().hex
        self.db.execute("INSERT INTO controller_identity(id,value) VALUES (1,?)", (value,)); self.db.commit()
        return value
    def managed_ssh_ownership(self, target_identity):
        try:
            row = self.db.execute("SELECT target_identity,controller_id,managed_path,target_node_id,content_hash,updated_at FROM managed_ssh_ownership WHERE target_identity=?", (target_identity,)).fetchone()
        except sqlite3.OperationalError:
            return None
        return dict(row) if row else None
    def save_managed_ssh_ownership(self, target_identity, controller_id, managed_path, target_node_id, content_hash, updated_at):
        self.db.execute("CREATE TABLE IF NOT EXISTS managed_ssh_ownership(target_identity TEXT PRIMARY KEY, controller_id TEXT NOT NULL, managed_path TEXT NOT NULL, target_node_id TEXT, content_hash TEXT NOT NULL, updated_at TEXT NOT NULL)")
        self.db.execute("INSERT INTO managed_ssh_ownership(target_identity,controller_id,managed_path,target_node_id,content_hash,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(target_identity) DO UPDATE SET controller_id=excluded.controller_id,managed_path=excluded.managed_path,target_node_id=excluded.target_node_id,content_hash=excluded.content_hash,updated_at=excluded.updated_at", (target_identity,controller_id,managed_path,target_node_id,content_hash,updated_at)); self.db.commit()
    def remove_managed_ssh_ownership(self, target_identity):
        try:
            self.db.execute("DELETE FROM managed_ssh_ownership WHERE target_identity=?", (target_identity,)); self.db.commit()
        except sqlite3.OperationalError:
            pass
    def adoption_event(self, created_at, topology_identity, node_id, observed_name, details=None):
        self.db.execute("CREATE TABLE IF NOT EXISTS adoption_events(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, topology_identity TEXT NOT NULL, node_id TEXT NOT NULL, observed_name TEXT, details_json TEXT NOT NULL)")
        payload = dict(details or {}); payload["observed_name"] = observed_name
        self.db.execute("INSERT INTO adoption_events(created_at,topology_identity,node_id,observed_name,details_json) VALUES (?,?,?,?,?)", (created_at, topology_identity, str(node_id), observed_name, json.dumps(payload, sort_keys=True)))
        self.db.commit()
    def close(self):
        self.db.close()

    def record_discovery_cycle(self, run_id, controller_id, started_at, completed_at,
                               status, provider_status, crawl_status, truncation_reason,
                               graph, provider_peers):
        """Atomically persist one discovery cycle and its evidence graph."""
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS discovery_runs(
          run_id TEXT PRIMARY KEY, controller_id TEXT NOT NULL, started_at TEXT NOT NULL,
          completed_at TEXT NOT NULL, status TEXT NOT NULL, provider_status TEXT NOT NULL,
          crawl_status TEXT NOT NULL, truncation_reason TEXT, summary_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS discovery_node_evidence(
          id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, evidence_key TEXT NOT NULL,
          observed_from TEXT NOT NULL, provider TEXT, provider_node_id TEXT,
          advertised_name TEXT, addresses_json TEXT NOT NULL, online TEXT,
          metadata_json TEXT NOT NULL, observed_at TEXT, topology_identity TEXT,
          UNIQUE(run_id, evidence_key, observed_from));
        CREATE TABLE IF NOT EXISTS discovery_relationship_evidence(
          id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, source TEXT NOT NULL,
          destination TEXT NOT NULL, alias TEXT NOT NULL, effective_json TEXT NOT NULL,
          auth_state TEXT NOT NULL, provenance TEXT NOT NULL, observed_from TEXT NOT NULL,
          evidence TEXT, observed_at TEXT NOT NULL,
          UNIQUE(run_id, source, destination, alias, observed_from, effective_json, auth_state));
        """)
        import json
        self.db.execute("BEGIN")
        try:
            summary = {"nodes": len(graph.get("nodes", [])),
                       "relationships": len(graph.get("relationships", [])),
                       "sources": len(graph.get("sources", []))}
            self.db.execute("INSERT INTO discovery_runs(run_id,controller_id,started_at,completed_at,status,provider_status,crawl_status,truncation_reason,summary_json) VALUES (?,?,?,?,?,?,?,?,?)",
                            (run_id, controller_id, started_at, completed_at, status, provider_status,
                             crawl_status, truncation_reason, json.dumps(summary, sort_keys=True)))
            for node in graph.get("nodes", []):
                key = node["observation_identity"]
                self.db.execute("INSERT OR IGNORE INTO discovery_node_evidence(run_id,evidence_key,observed_from,provider,provider_node_id,advertised_name,addresses_json,online,metadata_json,observed_at,topology_identity) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                (run_id, key, node.get("observed_from", controller_id), None, None,
                                 None, "[]", None, json.dumps({"aliases": node.get("aliases", []),
                                 "provider_peers": node.get("provider_peers", [])}, sort_keys=True),
                                 node.get("observed_at"), None))
            for peer in provider_peers:
                key = f"{peer.get('provider')}:{peer.get('provider_node_id')}" if peer.get("provider_node_id") else f"{run_id}:peer:{peer.get('advertised_name')}"
                self.db.execute("INSERT OR IGNORE INTO discovery_node_evidence(run_id,evidence_key,observed_from,provider,provider_node_id,advertised_name,addresses_json,online,metadata_json,observed_at,topology_identity) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                (run_id, key, controller_id, peer.get("provider"), peer.get("provider_node_id"),
                                 peer.get("advertised_name"), json.dumps(peer.get("addresses", [])),
                                 None if peer.get("online") is None else str(bool(peer.get("online"))),
                                 json.dumps(peer.get("metadata", {}), sort_keys=True), peer.get("observed_at"), None))
            for relationship in graph.get("relationships", []):
                self.db.execute("INSERT OR IGNORE INTO discovery_relationship_evidence(run_id,source,destination,alias,effective_json,auth_state,provenance,observed_from,evidence,observed_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                (run_id, relationship["source"], relationship["destination"], relationship["alias"],
                                 json.dumps(relationship.get("effective", {}), sort_keys=True), relationship["auth_state"],
                                 relationship["provenance"], relationship["observed_from"], relationship.get("evidence"),
                                 completed_at))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def latest_discovery_run(self):
        try:
            row = self.db.execute("SELECT * FROM discovery_runs ORDER BY completed_at DESC LIMIT 1").fetchone()
        except sqlite3.OperationalError:
            return None
        return dict(row) if row else None

    def discovery_history(self):
        try:
            return [dict(row) for row in self.db.execute(
                "SELECT * FROM discovery_runs ORDER BY completed_at ASC")]
        except sqlite3.OperationalError:
            return []

    def discovery_graph(self, run_id=None):
        import json
        try:
            if run_id is None:
                row = self.db.execute("SELECT run_id FROM discovery_runs ORDER BY completed_at DESC LIMIT 1").fetchone()
                run_id = row[0] if row else None
            if run_id is None:
                return {"run_id": None, "nodes": [], "relationships": []}
            nodes = [dict(row) for row in self.db.execute("SELECT * FROM discovery_node_evidence WHERE run_id=? ORDER BY id", (run_id,))]
            relationships = [dict(row) for row in self.db.execute("SELECT * FROM discovery_relationship_evidence WHERE run_id=? ORDER BY id", (run_id,))]
            for row in nodes:
                row["addresses"] = json.loads(row.pop("addresses_json"))
                row["metadata"] = json.loads(row.pop("metadata_json"))
            for row in relationships:
                row["effective"] = json.loads(row.pop("effective_json"))
            return {"run_id": run_id, "nodes": nodes, "relationships": relationships}
        except sqlite3.OperationalError:
            return {"run_id": None, "nodes": [], "relationships": []}

    def discovery_evidence(self):
        """Return all retained discovery evidence without collapsing history."""
        import json
        try:
            nodes = [dict(row) for row in self.db.execute("SELECT * FROM discovery_node_evidence ORDER BY id")]
            relationships = [dict(row) for row in self.db.execute("SELECT * FROM discovery_relationship_evidence ORDER BY id")]
            for row in nodes:
                row["addresses"] = json.loads(row.pop("addresses_json"))
                row["metadata"] = json.loads(row.pop("metadata_json"))
            for row in relationships:
                row["effective"] = json.loads(row.pop("effective_json"))
            return {"nodes": nodes, "relationships": relationships}
        except sqlite3.OperationalError:
            return {"nodes": [], "relationships": []}
    def record_discovery_acceptance(self, record):
        self.db.execute("""CREATE TABLE IF NOT EXISTS discovery_acceptances(
          acceptance_id INTEGER PRIMARY KEY, proposal_id TEXT NOT NULL, proposal_type TEXT NOT NULL,
          timestamp TEXT NOT NULL, controller_id TEXT NOT NULL, topology_hash_before TEXT NOT NULL,
          topology_hash_after TEXT NOT NULL, result TEXT NOT NULL, discovery_run_id TEXT)""")
        try:
            self.db.execute("ALTER TABLE discovery_acceptances ADD COLUMN discovery_run_id TEXT")
        except sqlite3.OperationalError:
            pass
        from datetime import datetime, timezone
        self.db.execute("INSERT INTO discovery_acceptances(proposal_id,proposal_type,timestamp,controller_id,topology_hash_before,topology_hash_after,result,discovery_run_id) VALUES (?,?,?,?,?,?,?,?)",
                        (record["proposal_id"], record["proposal_type"], datetime.now(timezone.utc).isoformat(),
                         record["controller_id"], record["topology_hash_before"], record["topology_hash_after"],
                         record["result"], record.get("discovery_run_id")))
        self.db.commit()
    def discovery_acceptance(self, proposal_id):
        try:
            row = self.db.execute("SELECT * FROM discovery_acceptances WHERE proposal_id=? ORDER BY acceptance_id DESC LIMIT 1", (proposal_id,)).fetchone()
        except sqlite3.OperationalError:
            return None
        return dict(row) if row else None

    def topology_decisions(self, decision_type=None):
        try:
            query = "SELECT * FROM topology_decisions"
            args = ()
            if decision_type:
                query += " WHERE decision_type=?"
                args = (decision_type,)
            query += " ORDER BY decision_id"
            return [dict(row) for row in self.db.execute(query, args)]
        except sqlite3.OperationalError:
            return []

    def record_topology_decision(self, record):
        self.db.execute("""CREATE TABLE IF NOT EXISTS topology_decisions(
          decision_id INTEGER PRIMARY KEY, decision_type TEXT NOT NULL,
          evidence_fingerprint TEXT NOT NULL, fingerprint_version TEXT NOT NULL,
          proposal_type TEXT NOT NULL, proposal_id TEXT NOT NULL,
          subject_reference TEXT NOT NULL, decided_at TEXT NOT NULL, reason TEXT,
          UNIQUE(decision_type, evidence_fingerprint))""")
        from datetime import datetime, timezone
        decided_at = record.get("decided_at") or datetime.now(timezone.utc).isoformat()
        cur = self.db.execute("""INSERT OR IGNORE INTO topology_decisions(
          decision_type,evidence_fingerprint,fingerprint_version,proposal_type,
          proposal_id,subject_reference,decided_at,reason)
          VALUES (?,?,?,?,?,?,?,?)""", (record["decision_type"],
          record["evidence_fingerprint"], record["fingerprint_version"],
          record["proposal_type"], record["proposal_id"],
          record["subject_reference"], decided_at, record.get("reason")))
        if cur.rowcount and record.get("proposal_id"):
            self.resolve_event("proposal:" + record["proposal_id"])
        self.db.commit()
        row = self.db.execute("""SELECT * FROM topology_decisions
          WHERE decision_type=? AND evidence_fingerprint=?""",
          (record["decision_type"], record["evidence_fingerprint"])).fetchone()
        return dict(row) if row else None

    def record_merge_pending(self, record):
        self.db.execute("""CREATE TABLE IF NOT EXISTS topology_merges(
          merge_id TEXT PRIMARY KEY, source TEXT NOT NULL, survivor TEXT NOT NULL,
          decided_at TEXT NOT NULL, before_hash TEXT NOT NULL, after_hash TEXT NOT NULL,
          evidence_json TEXT NOT NULL, state TEXT NOT NULL, actual_after_hash TEXT)""")
        from datetime import datetime, timezone
        self.db.execute("""INSERT OR IGNORE INTO topology_merges(
          merge_id,source,survivor,decided_at,before_hash,after_hash,evidence_json,state)
          VALUES (?,?,?,?,?,?,?,?)""", (record["merge_id"], record["source"], record["survivor"],
          record.get("decided_at") or datetime.now(timezone.utc).isoformat(), record["before_hash"],
          record["after_hash"], record["evidence_json"], "PENDING"))
        self.db.commit()

    def merge_operation(self, merge_id):
        try:
            row = self.db.execute("SELECT * FROM topology_merges WHERE merge_id=?", (merge_id,)).fetchone()
        except sqlite3.OperationalError:
            return None
        return dict(row) if row else None

    def pending_merge(self, source, survivor):
        try:
            row = self.db.execute("""SELECT * FROM topology_merges WHERE source=? AND survivor=?
              AND state='PENDING' ORDER BY decided_at DESC LIMIT 1""", (source, survivor)).fetchone()
        except sqlite3.OperationalError:
            return None
        return dict(row) if row else None

    def update_merge(self, merge_id, state, actual_after_hash):
        self.db.execute("UPDATE topology_merges SET state=?,actual_after_hash=? WHERE merge_id=?",
                        (state, actual_after_hash, merge_id))
        self.db.commit()

    def record_event(self, event_type, severity, subject_identity, stable_key,
                     summary, details=None, occurred_at=None, *, condition=False):
        """Record one meaningful transition, coalescing an active condition."""
        from datetime import datetime, timezone
        occurred_at = occurred_at or datetime.now(timezone.utc).isoformat()
        self.db.execute("""CREATE TABLE IF NOT EXISTS events(
          event_id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, severity TEXT NOT NULL,
          subject_identity TEXT, stable_key TEXT NOT NULL, first_seen_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL, occurrence_count INTEGER NOT NULL DEFAULT 1,
          summary TEXT NOT NULL, details_json TEXT NOT NULL, resolved_at TEXT)""")
        row = self.db.execute("SELECT * FROM events WHERE stable_key=? AND resolved_at IS NULL ORDER BY event_id DESC LIMIT 1", (stable_key,)).fetchone()
        payload = json.dumps(details or {}, sort_keys=True)
        if row:
            self.db.execute("UPDATE events SET last_seen_at=?,occurrence_count=occurrence_count+1,details_json=? WHERE event_id=?", (occurred_at, payload, row["event_id"]))
            return {"event_id": row["event_id"], "created": False}
        cur = self.db.execute("INSERT INTO events(event_type,severity,subject_identity,stable_key,first_seen_at,last_seen_at,summary,details_json) VALUES (?,?,?,?,?,?,?,?)", (event_type, severity, subject_identity, stable_key, occurred_at, occurred_at, summary, payload))
        return {"event_id": cur.lastrowid, "created": True}

    def resolve_event(self, stable_key, resolved_at=None):
        from datetime import datetime, timezone
        resolved_at = resolved_at or datetime.now(timezone.utc).isoformat()
        try:
            row = self.db.execute("SELECT * FROM events WHERE stable_key=? AND resolved_at IS NULL ORDER BY event_id DESC LIMIT 1", (stable_key,)).fetchone()
        except sqlite3.OperationalError:
            return None
        if row:
            self.db.execute("UPDATE events SET resolved_at=? WHERE event_id=?", (resolved_at, row["event_id"]))
        return dict(row) if row else None

    def event_occurrence(self, stable_key):
        try:
            row = self.db.execute("SELECT occurrence_count FROM events WHERE stable_key=? ORDER BY event_id DESC LIMIT 1", (stable_key,)).fetchone()
        except sqlite3.OperationalError:
            return 0
        return int(row[0]) if row else 0

    def events(self, limit=10):
        try:
            rows = self.db.execute("""SELECT event_id,event_type,severity,subject_identity,summary,
              first_seen_at,last_seen_at,occurrence_count,resolved_at,stable_key
              FROM events ORDER BY (resolved_at IS NULL) DESC,
              CASE severity WHEN 'ERROR' THEN 0 WHEN 'ATTENTION' THEN 1 ELSE 2 END,
              last_seen_at DESC,event_id DESC LIMIT ?""", (min(max(int(limit), 0), 10),)).fetchall()
        except sqlite3.OperationalError:
            return []
        return [dict(row) for row in rows]

    def commit_events(self):
        self.db.commit()
    def latest(self):
        row=self.db.execute("SELECT * FROM reconciliations ORDER BY id DESC LIMIT 1").fetchone(); return dict(row) if row else None
