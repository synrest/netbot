import json
import tempfile
import unittest
from pathlib import Path

from netbot.snapshot import (build_snapshot, export_snapshot, fetch_snapshot,
                             resolve_authority, snapshot_ssh_command)
from netbot.state import State


class Completed:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class SnapshotExchangeTests(unittest.TestCase):
    def setup_files(self, root, body=None):
        config = root / "topology.yaml"
        config.write_text(body or """version: 1
authority: arasaka
hosts:
  arasaka:
    class: core
    bindings:
      ssh:
        aliases: [arasaka-admin]
        user: zero
  orion:
    class: satellite
""")
        return config

    def envelope(self, config, generated_at="fixed"):
        return {"source_authority": "arasaka", "snapshot": build_snapshot(config, generated_at=generated_at)}

    def test_authority_is_explicit_and_transport_uses_exact_binding(self):
        with tempfile.TemporaryDirectory() as d:
            config = self.setup_files(Path(d))
            authority, reason = resolve_authority(config)
            self.assertIsNone(reason)
            self.assertEqual(authority, {"identity": "arasaka", "alias": "arasaka-admin", "user": "zero"})
            self.assertEqual(snapshot_ssh_command(authority), ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "zero@arasaka-admin", "netbot topology snapshot --export"])

    def test_non_authority_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root); state = State(root / "state.sqlite3")
            envelope = self.envelope(config); envelope["source_authority"] = "orion"
            result = fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(envelope)))
            self.assertEqual(result["result"], "REJECTED")
            self.assertIsNone(state.latest_accepted_topology_snapshot())
            state.close()

    def test_success_same_and_different_hash_acceptance(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root); state = State(root / "state.sqlite3")
            current = [self.envelope(config, "first")]
            result = fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(current[0])))
            self.assertEqual(result["result"], "ACCEPTED")
            first_hash = result["accepted_hash"]
            result = fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(current[0])))
            self.assertEqual(result["result"], "SAME")
            config.write_text(config.read_text().replace("class: satellite", "class: core"))
            changed = self.envelope(config, "earlier-source-time")
            result = fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(changed)))
            self.assertEqual(result["result"], "ACCEPTED")
            self.assertNotEqual(first_hash, result["accepted_hash"])
            self.assertEqual(state.latest_accepted_topology_snapshot()["snapshot"]["generated_at"], "earlier-source-time")
            state.close()

    def test_malformed_unsupported_hash_and_authority_snapshots_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root); state = State(root / "state.sqlite3")
            valid = self.envelope(config)
            self.assertEqual(fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(valid)))["result"], "ACCEPTED")
            cases = ["not-json"]
            unsupported = json.loads(json.dumps(valid)); unsupported["snapshot"]["schema"] = 99; cases.append(json.dumps(unsupported))
            mismatch = json.loads(json.dumps(valid)); mismatch["snapshot"]["content_hash"] = "0" * 64; cases.append(json.dumps(mismatch))
            wrong = json.loads(json.dumps(valid)); wrong["snapshot"]["topology"]["authority"] = "orion"; cases.append(json.dumps(wrong))
            for payload in cases:
                result = fetch_snapshot(config, state, lambda *args, payload=payload, **kwargs: Completed(payload))
                self.assertEqual(result["result"], "REJECTED")
            self.assertEqual(state.latest_accepted_topology_snapshot()["snapshot"]["content_hash"], valid["snapshot"]["content_hash"])
            state.close()

    def test_failed_transport_preserves_previous_snapshot_and_does_not_use_agent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root); state = State(root / "state.sqlite3")
            valid = self.envelope(config); fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(valid)))
            before = state.latest_accepted_topology_snapshot()
            calls = []
            def runner(command, **kwargs):
                calls.append(command)
                return Completed(returncode=255, stderr="connection refused")
            result = fetch_snapshot(config, state, runner)
            self.assertEqual(result["result"], "UNAVAILABLE")
            self.assertEqual(before, state.latest_accepted_topology_snapshot())
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][-1], "netbot topology snapshot --export")
            self.assertNotIn("agent-temporary", " ".join(calls[0]))
            state.close()

    def test_failed_persistence_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root); state = State(root / "state.sqlite3")
            valid = self.envelope(config); fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(valid)))
            before = state.latest_accepted_topology_snapshot()
            original = state.save_accepted_topology_snapshot
            state.save_accepted_topology_snapshot = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("disk full"))
            changed = json.loads(json.dumps(valid)); changed["snapshot"]["topology"]["hosts"][1]["class"] = "core"
            changed["snapshot"]["content_hash"] = __import__("hashlib").sha256(
                __import__("netbot.snapshot", fromlist=["canonical_json"]).canonical_json(changed["snapshot"]["topology"]).encode()).hexdigest()
            result = fetch_snapshot(config, state, lambda *args, **kwargs: Completed(json.dumps(changed)))
            self.assertEqual(result["result"], "REJECTED")
            self.assertEqual(before, state.latest_accepted_topology_snapshot())
            state.save_accepted_topology_snapshot = original
            state.close()

    def test_export_is_read_only_and_contains_snapshot_fields(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root); state = State(root / "state.sqlite3")
            snapshot = build_snapshot(config, generated_at="fixed")
            state.save_topology_snapshot(snapshot)
            exported = export_snapshot(state)
            self.assertEqual(set(exported), {"schema", "version", "content_hash", "topology", "generated_at"})
            self.assertEqual(exported, snapshot)
            self.assertFalse((root / "topology.yaml").stat().st_size == 0)
            state.close()

    def test_missing_authority_is_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); config = self.setup_files(root, "version: 1\nhosts:\n  orion:\n    class: satellite\n"); state = State(root / "state.sqlite3")
            result = fetch_snapshot(config, state, lambda *args, **kwargs: self.fail("transport must not run"))
            self.assertEqual(result["result"], "UNAVAILABLE")
            state.close()
