import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from netbot.cli import main
from netbot.merge import merge_topology, plan_merge, _mutated_text
from netbot.discovery.proposals import _accepted
from netbot.state import State


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.config = self.root / "topology.yaml"
        self.config.write_text("""version: 1
authority: controller
hosts:
  controller:
    class: core
  alpha:
    class: server
    kind: physical
    bindings:
      tailscale:
        node_id: same-node
        name: alpha
      ssh:
        aliases:
          - alpha
        user: zero
  beta:
    class: server
    kind: physical
    bindings:
      tailscale:
        node_id: same-node
        name: beta
      ssh:
        aliases:
          - beta
        user: zero
""")
        self.db = self.root / "state.sqlite3"

    def test_same_provider_merge_changes_only_source_lifecycle(self):
        before = self.config.read_text()
        plan = plan_merge(self.config, self.db, "alpha", "beta")
        self.assertEqual(plan["result"], "SAFE")
        result = merge_topology(self.config, self.db, "alpha", "beta")
        self.assertEqual(result["result"], "MERGED")
        self.assertTrue(result["topology_changed"])
        after = self.config.read_text()
        self.assertIn("lifecycle: retired", after)
        self.assertIn("superseded_by: beta", after)
        self.assertIn("node_id: same-node", after)
        self.assertIn("alpha", after)
        self.assertIn("beta", after)
        self.assertEqual(after.replace("    lifecycle: retired\n", "").replace("    superseded_by: beta\n", ""), before)

    def test_dry_run_is_read_only_and_json_contract_is_complete(self):
        State(self.db).close()
        before_config, before_db = self.config.read_bytes(), self.db.read_bytes()
        result = merge_topology(self.config, self.db, "alpha", "beta", dry_run=True)
        self.assertEqual(result["result"], "SAFE")
        self.assertFalse(result["topology_changed"])
        self.assertFalse(result["reconciliation_performed"])
        self.assertEqual(self.config.read_bytes(), before_config)
        self.assertEqual(self.db.read_bytes(), before_db)
        output = StringIO()
        with redirect_stdout(output):
            main(["merge", "alpha", "--into", "beta", "--dry-run", "--json",
                  "--config", str(self.config), "--db", str(self.db)])
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["command"], "merge")
        self.assertEqual(payload["source"], "alpha")
        self.assertEqual(payload["survivor"], "beta")
        self.assertIn("evidence", payload)
        self.assertIn("lifecycle", payload)

    def test_journal_survives_restart_and_source_stays_durable(self):
        result = merge_topology(self.config, self.db, "alpha", "beta")
        self.assertEqual(result["operation_state"], "COMMITTED")
        state = State(self.db)
        operation = state.merge_operation(result["merge_id"])
        self.assertEqual(operation["state"], "COMMITTED")
        _, hosts = __import__("netbot.config", fromlist=["load_topology"]).load_topology(self.config)
        source = next(host for host in hosts if host.identity == "alpha")
        survivor = next(host for host in hosts if host.identity == "beta")
        self.assertEqual(source.attrs["superseded_by"], "beta")
        self.assertEqual(source.attrs["bindings"]["tailscale"]["node_id"], "same-node")
        self.assertEqual(survivor.attrs["bindings"]["tailscale"]["node_id"], "same-node")
        state.close()

    def test_repeated_merge_and_alternate_survivor(self):
        self.assertEqual(merge_topology(self.config, self.db, "alpha", "beta")["result"], "MERGED")
        self.assertEqual(merge_topology(self.config, self.db, "alpha", "beta")["result"], "ALREADY_MERGED")
        blocked = plan_merge(self.config, self.db, "alpha", "controller")
        self.assertEqual(blocked["result"], "BLOCKED")

    def test_provider_conflicts_and_missing_evidence_block(self):
        self.config.write_text(self.config.read_text().replace("node_id: same-node\n        name: alpha", "node_id: alpha-node\n        name: alpha"))
        result = plan_merge(self.config, self.db, "alpha", "beta")
        self.assertIn("conflicting provider node IDs", result["conflicts"])
        self.config.write_text(self.config.read_text().replace("        node_id: alpha-node\n        name: alpha\n", "        name: alpha\n"))
        result = plan_merge(self.config, self.db, "alpha", "beta")
        self.assertIn("insufficient provider identity evidence", result["conflicts"])

    def test_missing_self_and_controller_refusals(self):
        self.assertEqual(plan_merge(self.config, self.db, "missing", "beta")["result"], "BLOCKED")
        self.assertEqual(plan_merge(self.config, self.db, "alpha", "missing")["result"], "BLOCKED")
        self.assertEqual(plan_merge(self.config, self.db, "alpha", "alpha")["result"], "BLOCKED")
        self.assertEqual(plan_merge(self.config, self.db, "controller", "beta")["result"], "BLOCKED")
        self.assertEqual(plan_merge(self.config, self.db, "alpha", "controller")["result"], "BLOCKED")

    def test_parent_child_and_alias_conflicts_block(self):
        self.config.write_text(self.config.read_text().replace("  beta:\n", "  child:\n    parent: alpha\n    class: server\n    bindings:\n      tailscale:\n        node_id: child\n        name: child\n  beta:\n"))
        self.assertEqual(plan_merge(self.config, self.db, "alpha", "beta")["result"], "BLOCKED")
        self.config.write_text(self.config.read_text().replace("- beta", "- alpha"))
        self.assertTrue(plan_merge(self.config, self.db, "alpha", "beta")["conflicts"])

    def test_lifecycle_chain_and_survivor_parent_block(self):
        text = self.config.read_text().replace("  beta:\n", "  old:\n    lifecycle: retired\n    superseded_by: gamma\n    bindings:\n      tailscale:\n        node_id: old\n  gamma:\n    class: server\n    bindings:\n      tailscale:\n        node_id: same-node\n  beta:\n")
        self.config.write_text(text)
        self.assertEqual(plan_merge(self.config, self.db, "old", "beta")["result"], "BLOCKED")
        self.config.write_text(self.config.read_text().replace("  beta:\n", "  beta:\n    parent: controller\n"))
        self.assertEqual(plan_merge(self.config, self.db, "alpha", "beta")["result"], "BLOCKED")

    def test_stale_hash_and_prewrite_failure_leave_topology_unchanged(self):
        before = self.config.read_bytes()
        def stale_write(*args):
            self.config.write_text("changed externally\n")
            raise ValueError("topology changed during merge")
        with patch("netbot.merge._atomic_merge_replace", side_effect=stale_write):
            result = merge_topology(self.config, self.db, "alpha", "beta")
        self.assertEqual(result["result"], "TOPOLOGY_WRITE_FAILED")
        self.assertNotEqual(self.config.read_bytes(), before)

    def test_pending_operation_is_finalized_after_topology_was_written(self):
        after = _mutated_text(self.config.read_bytes(), "alpha", "beta")
        before_hash = hashlib.sha256(self.config.read_bytes()).hexdigest()
        after_hash = hashlib.sha256(after).hexdigest()
        self.config.write_bytes(after)
        state = State(self.db)
        state.record_merge_pending({"merge_id": "pending-merge", "source": "alpha", "survivor": "beta",
                                    "before_hash": before_hash, "after_hash": after_hash,
                                    "evidence_json": "{}"})
        state.close()
        result = merge_topology(self.config, self.db, "alpha", "beta")
        self.assertEqual(result["result"], "ALREADY_MERGED")
        self.assertEqual(result["recovery"], "PENDING_FINALIZED")
        state = State(self.db)
        self.assertEqual(state.merge_operation("pending-merge")["state"], "COMMITTED")
        state.close()

    def test_pending_before_hash_is_reused_after_restart(self):
        before = self.config.read_bytes()
        after = _mutated_text(before, "alpha", "beta")
        before_hash = hashlib.sha256(before).hexdigest()
        merge_id = hashlib.sha256(f"merge-v1:alpha:beta:{before_hash}".encode()).hexdigest()[:20]
        state = State(self.db)
        state.record_merge_pending({"merge_id": merge_id, "source": "alpha", "survivor": "beta",
                                    "before_hash": before_hash,
                                    "after_hash": hashlib.sha256(after).hexdigest(),
                                    "evidence_json": "{}"})
        state.close()
        result = merge_topology(self.config, self.db, "alpha", "beta")
        self.assertEqual(result["result"], "MERGED")
        state = State(self.db)
        rows = state.db.execute("SELECT COUNT(*) FROM topology_merges").fetchone()[0]
        self.assertEqual(rows, 1)
        self.assertEqual(state.merge_operation(merge_id)["state"], "COMMITTED")
        state.close()

    def test_pending_unexpected_hash_refuses_without_replacement(self):
        before = self.config.read_bytes()
        after = _mutated_text(before, "alpha", "beta")
        state = State(self.db)
        state.record_merge_pending({"merge_id": "unexpected-merge", "source": "alpha", "survivor": "beta",
                                    "before_hash": hashlib.sha256(before).hexdigest(),
                                    "after_hash": hashlib.sha256(after).hexdigest(),
                                    "evidence_json": "{}"})
        state.close()
        self.config.write_bytes(before + b"\n# unrelated change\n")
        current = self.config.read_bytes()
        result = merge_topology(self.config, self.db, "alpha", "beta")
        self.assertEqual(result["result"], "RECOVERY_REQUIRED")
        self.assertEqual(self.config.read_bytes(), current)
        state = State(self.db)
        self.assertEqual(state.merge_operation("unexpected-merge")["state"], "PENDING")
        state.close()

    def test_retired_identity_is_not_an_active_provider_claim(self):
        from types import SimpleNamespace
        retired = SimpleNamespace(identity="old", attrs={
            "lifecycle": "retired", "superseded_by": "beta",
            "bindings": {"tailscale": {"node_id": "same-node"}},
        })
        active = SimpleNamespace(identity="beta", attrs={
            "bindings": {"tailscale": {"node_id": "same-node"}},
        })
        by_provider, by_identity = _accepted([retired, active])
        self.assertEqual(by_provider[("tailscale", "same-node")], ["beta"])
        self.assertNotIn("old", by_identity)


if __name__ == "__main__":
    unittest.main()
