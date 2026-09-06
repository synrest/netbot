import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from netbot.controller_reconcile import reconcile_controller, reconcile_exit_code
from netbot.cli import main
from netbot.models import TailscaleNode


TOPOLOGY = """version: 1
authority: arasaka
peer_policy:
  default: topology
hosts:
  arasaka:
    bindings:
      ssh:
        aliases: [arasaka]
        user: zero
  kiroshi:
    bindings:
      ssh:
        aliases: [kiroshi]
        user: rafael
"""


class ControllerReconcileTests(unittest.TestCase):
    def fixture(self):
        root = Path(tempfile.mkdtemp())
        config = root / "config" / "topology.yaml"
        config.parent.mkdir()
        config.write_text(TOPOLOGY)
        return config, root / "state" / "netbot.sqlite3"

    def plan(self, identity, state="READY", action="NO_CHANGE"):
        return SimpleNamespace(target_identity=identity, state=state, action=action,
                               as_dict=lambda: {"target_identity": identity, "state": state, "action": action})

    def test_targeted_local_no_change_is_ok(self):
        config, db = self.fixture()
        with patch("netbot.controller_reconcile.discover", return_value=([], "offline")), \
             patch("netbot.controller_reconcile.build_apply_plan", return_value=self.plan("arasaka")):
            result = reconcile_controller(config, db, target="arasaka", dry_run=True)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["summary"]["unchanged"], 1)

    def test_unavailable_target_is_partial_and_other_target_continues(self):
        config, db = self.fixture()
        plans = [self.plan("arasaka"), self.plan("kiroshi", "TARGET_UNAVAILABLE", "BLOCKED")]
        with patch("netbot.controller_reconcile.discover", return_value=([], "offline")), \
             patch("netbot.controller_reconcile.build_apply_plan", side_effect=plans):
            result = reconcile_controller(config, db, dry_run=True)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["summary"]["unchanged"], 1)
        self.assertEqual(result["summary"]["unavailable"], 1)

    def test_live_change_uses_existing_apply_path(self):
        config, db = self.fixture()
        plan = self.plan("arasaka", "READY", "REPLACE")
        with patch("netbot.controller_reconcile.discover", return_value=([], "offline")), \
             patch("netbot.controller_reconcile.build_apply_plan", return_value=plan), \
             patch("netbot.controller_reconcile.apply_target", return_value={"result": "WRITE_VERIFIED"}) as apply:
            result = reconcile_controller(config, db, target="arasaka")
        apply.assert_called_once_with(plan, config)
        self.assertEqual(result["summary"]["changed"], 1)

    def test_dry_run_never_calls_apply(self):
        config, db = self.fixture()
        plan = self.plan("arasaka", "READY", "CREATE")
        with patch("netbot.controller_reconcile.discover", return_value=([], "offline")), \
             patch("netbot.controller_reconcile.build_apply_plan", return_value=plan), \
             patch("netbot.controller_reconcile.apply_target") as apply:
            reconcile_controller(config, db, target="arasaka", dry_run=True)
        apply.assert_not_called()

    def offline_fixture(self):
        root = Path(tempfile.mkdtemp())
        config = root / "config" / "topology.yaml"
        config.parent.mkdir()
        config.write_text("""version: 1
authority: arasaka
peer_policy:
  default: topology
hosts:
  arasaka:
    bindings:
      ssh:
        aliases: [arasaka]
        user: zero
      tailscale:
        node_id: arasaka-id
  offline:
    bindings:
      ssh:
        aliases: [offline]
        user: zero
      tailscale:
        node_id: offline-id
  offline-two:
    bindings:
      ssh:
        aliases: [offline-two]
        user: zero
      tailscale:
        node_id: offline-two-id
  unknown:
    bindings:
      ssh:
        aliases: [unknown]
        user: zero
      tailscale:
        node_id: unknown-id
""")
        return config, root / "state" / "netbot.sqlite3"

    def test_known_offline_target_skips_remote_planning(self):
        config, db = self.offline_fixture()
        nodes = [TailscaleNode("offline-id", "offline", None, [], False, "linux", None),
                 TailscaleNode("offline-two-id", "offline-two", None, [], False, "linux", None)]
        with patch("netbot.controller_reconcile.discover", return_value=(nodes, None)), \
             patch("netbot.controller_reconcile.build_apply_plan", return_value=self.plan("arasaka")) as build:
            result = reconcile_controller(config, db, dry_run=True)
        self.assertEqual([call.args[1] for call in build.call_args_list], ["arasaka", "unknown"])
        offline = next(item for item in result["targets"] if item["target_identity"] == "offline")
        self.assertEqual(offline["result"], "TARGET_UNAVAILABLE")
        offline_two = next(item for item in result["targets"] if item["target_identity"] == "offline-two")
        self.assertEqual(offline_two["result"], "TARGET_UNAVAILABLE")
        self.assertEqual(result["summary"]["unavailable"], 2)

    def test_unknown_availability_keeps_existing_safe_path(self):
        config, db = self.offline_fixture()
        with patch("netbot.controller_reconcile.discover", return_value=([], "status unavailable")), \
             patch("netbot.controller_reconcile.build_apply_plan", side_effect=lambda c, identity, db_path: self.plan(identity)) as build:
            reconcile_controller(config, db, dry_run=True)
        self.assertEqual(build.call_count, 4)

    def test_keyboard_interrupt_stops_controller(self):
        config, db = self.fixture()
        with patch("netbot.controller_reconcile.discover", return_value=([], "offline")), \
             patch("netbot.controller_reconcile.build_apply_plan", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                reconcile_controller(config, db, dry_run=True)

    def test_exit_code_contract(self):
        self.assertEqual(reconcile_exit_code({"status": "OK"}), 0)
        self.assertEqual(reconcile_exit_code({"status": "PARTIAL"}), 10)
        self.assertEqual(reconcile_exit_code({"status": "BLOCKED"}), 20)
        self.assertEqual(reconcile_exit_code({"status": "FAILED"}), 30)
        self.assertEqual(reconcile_exit_code({"status": "unexpected"}), 30)

    def test_cli_emits_json_for_nonzero_controller_status(self):
        payload = {"controller_id": "c", "dry_run": True, "status": "PARTIAL",
                   "targets": [], "summary": {}}
        output = StringIO()
        with patch("netbot.cli.reconcile_controller", return_value=payload), redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                main(["reconcile", "--dry-run"])
        self.assertEqual(raised.exception.code, 10)
        self.assertIn('"status": "PARTIAL"', output.getvalue())

    def test_controller_exception_is_not_reclassified(self):
        with patch("netbot.cli.reconcile_controller", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                main(["reconcile", "--dry-run"])


if __name__ == "__main__":
    unittest.main()
