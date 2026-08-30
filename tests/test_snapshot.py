import json
import tempfile
import unittest
from pathlib import Path

from netbot.snapshot import build_snapshot, canonical_json, compare_snapshot, persist_snapshot
from netbot.state import State


class SnapshotTests(unittest.TestCase):
    def write_topology(self, root, text):
        path = root / "topology.yaml"
        path.write_text(text)
        return path

    def test_identical_topology_has_identical_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            a = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n")
            first = build_snapshot(a, generated_at="2026-01-01T00:00:00+00:00")
            second = build_snapshot(a, generated_at="2026-01-02T00:00:00+00:00")
            self.assertEqual(first["content_hash"], second["content_hash"])
            self.assertEqual(compare_snapshot(first, None), "NO_PREVIOUS_SNAPSHOT")
            self.assertEqual(compare_snapshot(first, second), "SAME")

    def test_yaml_key_order_does_not_change_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            first = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n    kind: physical\n    bindings:\n      ssh:\n        aliases: [orion]\n        user: zero\n")
            one = build_snapshot(first, generated_at="one")
            second = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    kind: physical\n    bindings:\n      ssh:\n        user: zero\n        aliases: [orion]\n    class: satellite\n")
            two = build_snapshot(second, generated_at="two")
            self.assertEqual(one["content_hash"], two["content_hash"])

    def test_meaningful_topology_change_is_changed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n")
            first = build_snapshot(path, generated_at="one")
            path.write_text("version: 1\nhosts:\n  orion:\n    class: core\n")
            second = build_snapshot(path, generated_at="two")
            self.assertEqual(compare_snapshot(second, first), "CHANGED")

    def test_serialization_is_deterministic_and_metadata_is_not_hashed(self):
        payload = {"hosts": [{"identity": "orion", "class": "satellite"}], "version": 1}
        self.assertEqual(canonical_json(payload), canonical_json({"version": 1, "hosts": payload["hosts"]}))
        with tempfile.TemporaryDirectory() as d:
            path = self.write_topology(Path(d), "version: 1\nhosts:\n  orion:\n    class: satellite\n")
            first = build_snapshot(path, generated_at="one")
            second = build_snapshot(path, generated_at="two")
            self.assertNotEqual(first["generated_at"], second["generated_at"])
            self.assertEqual(first["content_hash"], second["content_hash"])

    def test_snapshot_persists_and_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n")
            snapshot = build_snapshot(path, generated_at="fixed")
            state = State(root / "state.sqlite3")
            persist_snapshot(state, snapshot)
            self.assertEqual(state.latest_topology_snapshot(), snapshot)
            state.close()
            reopened = State(root / "state.sqlite3")
            self.assertEqual(reopened.latest_topology_snapshot(), snapshot)
            reopened.close()

    def test_failed_snapshot_write_preserves_prior_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n")
            state = State(root / "state.sqlite3")
            prior = build_snapshot(path, generated_at="prior")
            persist_snapshot(state, prior)
            with self.assertRaises(KeyError):
                persist_snapshot(state, {"generated_at": "broken"})
            self.assertEqual(state.latest_topology_snapshot(), prior)
            state.close()

    def test_route_metadata_is_preserved_but_runtime_and_auth_are_not(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.write_topology(Path(d), """version: 1
hosts:
  mikoshi:
    class: core
    parent: arasaka
    bindings:
      ssh:
        aliases: [mikoshi]
        user: zero
        hostname: 127.0.0.1
        port: 2222
        controller: arasaka
      tailscale:
        node_id: "123"
        name: mikoshi
""")
            snapshot = build_snapshot(path, generated_at="fixed")
            encoded = json.dumps(snapshot, sort_keys=True)
            self.assertEqual(snapshot["topology"]["hosts"][0]["bindings"]["ssh"]["controller"], "arasaka")
            self.assertNotIn("Host mikoshi", encoded)
            for secret in ("private_key", "public_key", "authorized_keys", "known_hosts", "sudo", "token", "credential"):
                self.assertNotIn(secret, encoded)

    def test_cli_snapshot_reports_previous_comparison(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from netbot.cli import main
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = self.write_topology(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n")
            output = StringIO()
            with redirect_stdout(output):
                main(["topology", "snapshot", "--config", str(config), "--db", str(root / "state.sqlite3")])
            first = json.loads(output.getvalue())
            output = StringIO()
            with redirect_stdout(output):
                main(["topology", "snapshot", "--config", str(config), "--db", str(root / "state.sqlite3")])
            second = json.loads(output.getvalue())
            self.assertEqual(first["comparison"], "NO_PREVIOUS_SNAPSHOT")
            self.assertEqual(second["comparison"], "SAME")
            self.assertEqual(first["content_hash"], second["content_hash"])
