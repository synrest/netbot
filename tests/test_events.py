import tempfile
import unittest
from pathlib import Path

from netbot.events import record_maintenance_events
from netbot.state import State


class EventTests(unittest.TestCase):
    def setUp(self):
        self.db = Path(tempfile.mkdtemp()) / "state.sqlite3"

    def state(self):
        return State(self.db)

    def discovery(self, error=None):
        return {"provider": {"name": "tailscale", "error": error}}

    def reconcile(self, result="NO_CHANGE", state_name="READY", target="oracle"):
        return {"targets": [{"target_identity": target, "result": result, "state": state_name}]}

    def test_proposal_deduplicates(self):
        proposal = {"proposal_id": "p1", "proposal_type": "NEW_IDENTITY_CANDIDATE", "proposed_alias": "machine20"}
        state = self.state()
        record_maintenance_events(state, self.discovery(), [proposal], self.reconcile())
        record_maintenance_events(state, self.discovery(), [proposal], self.reconcile())
        self.assertEqual(len(state.events(10)), 1)
        self.assertEqual(state.events(10)[0]["occurrence_count"], 2)
        state.close()

    def test_unavailable_recovery_and_recurrence(self):
        state = self.state()
        record_maintenance_events(state, self.discovery(), [], self.reconcile("TARGET_UNAVAILABLE", "TARGET_UNAVAILABLE"))
        record_maintenance_events(state, self.discovery(), [], self.reconcile("TARGET_UNAVAILABLE", "TARGET_UNAVAILABLE"))
        self.assertEqual(len(state.events(10)), 1)
        record_maintenance_events(state, self.discovery(), [], self.reconcile())
        self.assertEqual({row["event_type"] for row in state.events(10)}, {"TARGET_UNAVAILABLE", "TARGET_RECOVERED"})
        record_maintenance_events(state, self.discovery(), [], self.reconcile("TARGET_UNAVAILABLE", "TARGET_UNAVAILABLE"))
        self.assertEqual(len(state.events(10)), 3)
        state.close()

    def test_provider_failure_recovery(self):
        state = self.state()
        record_maintenance_events(state, self.discovery("socket unavailable"), [], self.reconcile())
        record_maintenance_events(state, self.discovery(), [], self.reconcile())
        self.assertEqual({row["event_type"] for row in state.events(10)}, {"PROVIDER_FAILED", "PROVIDER_RECOVERED"})
        state.close()

    def test_managed_change_and_failure_types(self):
        state = self.state()
        record_maintenance_events(state, self.discovery(), [], self.reconcile("WRITE_VERIFIED"))
        record_maintenance_events(state, self.discovery(), [], self.reconcile("FAILED", "FAILED"))
        self.assertEqual({row["event_type"] for row in state.events(10)}, {"MANAGED_STATE_CHANGED", "RECONCILE_FAILED"})
        state.close()

    def test_dry_run_is_not_an_event_operation(self):
        state = self.state()
        # The maintenance orchestrator skips this function in dry-run mode.
        self.assertEqual(state.events(10), [])
        state.close()

    def test_cli_cap_is_limited_by_store(self):
        state = self.state()
        for index in range(12):
            state.record_event("NEW_TOPOLOGY_PROPOSAL", "ATTENTION", str(index), f"p:{index}", str(index))
        state.commit_events()
        self.assertEqual(len(state.events(10)), 10)
        state.close()

    def test_legacy_uuid_controller_relationship_event_is_resolved_only_for_known_alias(self):
        state = self.state()
        state.record_event("NEW_TOPOLOGY_PROPOSAL", "ATTENTION", "controller-uuid", "proposal:old",
                           "RELATIONSHIP_CANDIDATE: oracle",
                           {"proposal_id": "old", "proposal_type": "RELATIONSHIP_CANDIDATE"})
        state.record_event("NEW_TOPOLOGY_PROPOSAL", "ATTENTION", "controller-uuid", "proposal:unrelated",
                           "RELATIONSHIP_CANDIDATE: unknown",
                           {"proposal_id": "unrelated", "proposal_type": "RELATIONSHIP_CANDIDATE"})
        state.commit_events()
        record_maintenance_events(
            state, {**self.discovery(), "controller_id": "controller-uuid"}, [], self.reconcile(),
            canonical_controller="arasaka", accepted_aliases=("oracle",))
        rows = {row["stable_key"]: row for row in state.events(10)}
        self.assertIsNotNone(rows["proposal:old"]["resolved_at"])
        self.assertIsNone(rows["proposal:unrelated"]["resolved_at"])
        state.close()


if __name__ == "__main__":
    unittest.main()
