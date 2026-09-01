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
    def latest(self):
        row=self.db.execute("SELECT * FROM reconciliations ORDER BY id DESC LIMIT 1").fetchone(); return dict(row) if row else None
