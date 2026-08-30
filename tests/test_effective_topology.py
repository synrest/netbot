import json
import tempfile
import unittest
from pathlib import Path

from netbot.discovery.tailscale import normalize_status
from netbot.reconcile import reconcile
from netbot.snapshot import (build_snapshot, effective_topology, fetch_snapshot,
                             validate_snapshot)
from netbot.state import State


class Completed:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class EffectiveTopologyTests(unittest.TestCase):
    CONFIG = """version: 1
authority: arasaka
hosts:
  arasaka:
    class: core
    bindings:
      ssh:
        aliases: [arasaka]
        user: zero
  kiroshi:
    class: core
  orion:
    class: satellite
"""

    def config(self, root, text=None):
        path = root / "topology.yaml"
        path.write_text(text or self.CONFIG)
        return path

    def test_authority_uses_local_topology(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            selected = effective_topology(config, state, "arasaka")
            self.assertEqual(selected["source"], "local-authority")
            self.assertEqual([host.identity for host in selected["desired"]], ["arasaka", "kiroshi", "orion"])
            state.close()

    def test_non_authority_without_accepted_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            selected = effective_topology(config, state, "kiroshi")
            self.assertEqual(selected["state"], "NO_AUTHORITATIVE_TOPOLOGY")
            self.assertEqual(selected["desired"], [])
            state.close()

    def test_non_authority_uses_accepted_snapshot_not_local_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            accepted = build_snapshot(config, generated_at="authority")
            state.save_accepted_topology_snapshot(accepted, "arasaka", "ssh", accepted_at="accepted")
            config.write_text(self.CONFIG.replace("class: satellite", "class: core").replace("  orion:\n", "  remote-only:\n"))
            selected = effective_topology(config, state, "kiroshi")
            self.assertEqual(selected["source"], "accepted-authority")
            self.assertEqual(selected["effective_hash"], accepted["content_hash"])
            self.assertIn("orion", [host.identity for host in selected["desired"]])
            self.assertNotIn("remote-only", [host.identity for host in selected["desired"]])
            state.close()

    def test_corrupt_accepted_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            corrupt = build_snapshot(config, generated_at="bad")
            corrupt["content_hash"] = "0" * 64
            state.save_accepted_topology_snapshot(corrupt, "arasaka", "ssh", accepted_at="accepted")
            selected = effective_topology(config, state, "kiroshi")
            self.assertEqual(selected["state"], "NO_AUTHORITATIVE_TOPOLOGY")
            self.assertIn("content hash mismatch", selected["reason"])
            state.close()

    def test_malformed_persisted_peer_snapshot_fails_closed_without_exception(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            state.db.execute("CREATE TABLE accepted_topology_snapshots (id INTEGER PRIMARY KEY CHECK(id=1), source_identity TEXT NOT NULL, content_hash TEXT NOT NULL, transport TEXT NOT NULL, accepted_at TEXT NOT NULL, snapshot_json TEXT NOT NULL)")
            state.db.execute("INSERT INTO accepted_topology_snapshots VALUES (1, 'arasaka', 'bad', 'ssh', 'accepted', '{not-json')")
            state.db.commit()
            selected = effective_topology(config, state, "kiroshi")
            self.assertEqual(selected["state"], "NO_AUTHORITATIVE_TOPOLOGY")
            self.assertIn("JSON is invalid", selected["reason"])
            state.close()

    def test_fetch_acceptance_becomes_effective_and_same_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            envelope = {"source_authority": "arasaka", "snapshot": build_snapshot(config, generated_at="authority")}
            runner = lambda *args, **kwargs: Completed(json.dumps(envelope))
            self.assertEqual(fetch_snapshot(config, state, runner)["result"], "ACCEPTED")
            selected = effective_topology(config, state, "kiroshi")
            self.assertEqual(selected["effective_hash"], envelope["snapshot"]["content_hash"])
            self.assertEqual(fetch_snapshot(config, state, runner)["result"], "SAME")
            self.assertEqual(state.latest_accepted_topology_snapshot()["snapshot"], envelope["snapshot"])
            state.close()

    def test_fetch_failure_keeps_prior_accepted_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            accepted = build_snapshot(config, generated_at="authority")
            state.save_accepted_topology_snapshot(accepted, "arasaka", "ssh", accepted_at="accepted")
            result = fetch_snapshot(config, state, lambda *args, **kwargs: Completed(returncode=255, stderr="offline"))
            self.assertEqual(result["result"], "UNAVAILABLE")
            selected = effective_topology(config, state, "kiroshi")
            self.assertEqual(selected["effective_hash"], accepted["content_hash"])
            self.assertEqual(selected["fetch_state"]["result"], "UNAVAILABLE")
            state.close()

    def test_default_reconcile_uses_local_topology_independent_of_peer_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            accepted = build_snapshot(config, generated_at="authority")
            state.save_accepted_topology_snapshot(accepted, "arasaka", "ssh", accepted_at="accepted")
            config.write_text(config.read_text().replace("class: satellite", "class: core"))
            state.close()
            import netbot.reconcile as reconcile_module
            old = reconcile_module.discover
            reconcile_module.discover = lambda: (normalize_status({"Self": {"ID": "k", "HostName": "kiroshi", "Online": True}}), None)
            try:
                home = root / "home"; (home / ".ssh").mkdir(parents=True); (home / ".ssh" / "config").write_text("")
                result = reconcile(config, root / "state.sqlite3", home)
                self.assertEqual(result["topology"]["source"], "local-controller")
                self.assertEqual([host.identity for host in result["desired"]], ["arasaka", "kiroshi", "orion"])
                self.assertNotEqual(result["topology"]["effective_hash"], accepted["content_hash"])
            finally:
                reconcile_module.discover = old

    def test_default_reconcile_ignores_corrupt_peer_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.config(root); state = State(root / "state.sqlite3")
            state.db.execute("CREATE TABLE accepted_topology_snapshots (id INTEGER PRIMARY KEY CHECK(id=1), source_identity TEXT NOT NULL, content_hash TEXT NOT NULL, transport TEXT NOT NULL, accepted_at TEXT NOT NULL, snapshot_json TEXT NOT NULL)")
            state.db.execute("INSERT INTO accepted_topology_snapshots VALUES (1, 'arasaka', 'bad', 'ssh', 'accepted', '{not-json')")
            state.db.commit(); state.close()
            import netbot.reconcile as reconcile_module
            old = reconcile_module.discover
            reconcile_module.discover = lambda: (normalize_status({"Self": {"ID": "a", "HostName": "arasaka", "Online": True}}), None)
            try:
                home = root / "home"; (home / ".ssh").mkdir(parents=True); (home / ".ssh" / "config").write_text("")
                result = reconcile(config, root / "state.sqlite3", home)
                self.assertEqual(result["topology"]["source"], "local-controller")
                self.assertEqual(len(result["desired"]), 3)
            finally:
                reconcile_module.discover = old

    def test_snapshot_validation_requires_expected_authority(self):
        with tempfile.TemporaryDirectory() as d:
            config = self.config(Path(d)); snapshot = build_snapshot(config, generated_at="fixed")
            self.assertEqual(validate_snapshot(snapshot, "arasaka"), (True, None))
            self.assertEqual(validate_snapshot(snapshot, "kiroshi")[0], False)
