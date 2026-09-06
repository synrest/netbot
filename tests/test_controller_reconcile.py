import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from netbot.controller_reconcile import reconcile_controller


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
        with patch("netbot.controller_reconcile.build_apply_plan", return_value=self.plan("arasaka")):
            result = reconcile_controller(config, db, target="arasaka", dry_run=True)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["summary"]["unchanged"], 1)

    def test_unavailable_target_is_partial_and_other_target_continues(self):
        config, db = self.fixture()
        plans = [self.plan("arasaka"), self.plan("kiroshi", "TARGET_UNAVAILABLE", "BLOCKED")]
        with patch("netbot.controller_reconcile.build_apply_plan", side_effect=plans):
            result = reconcile_controller(config, db, dry_run=True)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["summary"]["unchanged"], 1)
        self.assertEqual(result["summary"]["unavailable"], 1)

    def test_live_change_uses_existing_apply_path(self):
        config, db = self.fixture()
        plan = self.plan("arasaka", "READY", "REPLACE")
        with patch("netbot.controller_reconcile.build_apply_plan", return_value=plan), \
             patch("netbot.controller_reconcile.apply_target", return_value={"result": "WRITE_VERIFIED"}) as apply:
            result = reconcile_controller(config, db, target="arasaka")
        apply.assert_called_once_with(plan, config)
        self.assertEqual(result["summary"]["changed"], 1)

    def test_dry_run_never_calls_apply(self):
        config, db = self.fixture()
        plan = self.plan("arasaka", "READY", "CREATE")
        with patch("netbot.controller_reconcile.build_apply_plan", return_value=plan), \
             patch("netbot.controller_reconcile.apply_target") as apply:
            reconcile_controller(config, db, target="arasaka", dry_run=True)
        apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
