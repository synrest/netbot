import json, sqlite3
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
    def close(self):
        self.db.close()
    def latest(self):
        row=self.db.execute("SELECT * FROM reconciliations ORDER BY id DESC LIMIT 1").fetchone(); return dict(row) if row else None
