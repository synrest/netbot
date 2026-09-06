import fcntl
import tempfile
import unittest
from pathlib import Path

from netbot.maintenance import run_maintenance
from netbot.state import State


class MaintenanceTests(unittest.TestCase):
    def fixture(self):
        root = Path(tempfile.mkdtemp())
        config = root / "topology.yaml"
        config.write_text("version: 1\nhosts:\n  arasaka:\n    class: core\n")
        return root, config, root / "state.sqlite3"

    def cycle(self, status="OK"):
        return {"cycle_id": "run-1", "controller_id": "controller", "status": status,
                "dry_run": False, "crawl": {"run_id": None, "nodes": [], "relationships": []}}

    def reconcile(self, status="OK"):
        return {"status": status, "summary": {"changed": 0, "unchanged": 1,
                "unavailable": 0, "blocked": 0, "failed": 0}}

    def test_success_no_change_aggregates_ok(self):
        root, config, db = self.fixture()
        result = run_maintenance(config, db, runtime=root / "run",
                                 cycle_runner=lambda *a, **k: self.cycle(),
                                 reconcile_runner=lambda *a, **k: self.reconcile())
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["summary"]["reconcile_unchanged"], 1)
        self.assertFalse(result["proposal_acceptance_performed"])

    def test_partial_discovery_still_reconciles(self):
        root, config, db = self.fixture(); called = []
        result = run_maintenance(config, db, runtime=root / "run",
                                 cycle_runner=lambda *a, **k: self.cycle("PARTIAL"),
                                 reconcile_runner=lambda *a, **k: (called.append(True) or self.reconcile()))
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(called, [True])

    def test_pending_proposal_is_informational(self):
        root, config, db = self.fixture()
        # The orchestration never calls acceptance; proposal collection is independent.
        result = run_maintenance(config, db, runtime=root / "run",
                                 cycle_runner=lambda *a, **k: self.cycle(),
                                 reconcile_runner=lambda *a, **k: self.reconcile())
        self.assertEqual(result["status"], "OK")
        self.assertFalse(result["topology_changed"])
        self.assertEqual(config.read_text(), "version: 1\nhosts:\n  arasaka:\n    class: core\n")

    def test_dry_run_does_not_persist_discovery_history(self):
        root, config, db = self.fixture()
        result = run_maintenance(config, db, dry_run=True, runtime=root / "run",
                                 cycle_runner=lambda *a, **k: self.cycle(),
                                 reconcile_runner=lambda *a, **k: self.reconcile())
        self.assertEqual(result["status"], "OK")
        state = State(db); self.assertIsNone(state.latest_discovery_run()); state.close()

    def test_concurrent_maintenance_is_blocked(self):
        root, config, db = self.fixture(); runtime = root / "run"; runtime.mkdir()
        with (runtime / "maintenance.lock").open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = run_maintenance(config, db, runtime=runtime)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["reason"], "maintenance run already active")


if __name__ == "__main__":
    unittest.main()
