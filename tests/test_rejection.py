import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from netbot.discovery.acceptance import reject_node
from netbot.discovery.proposals import filter_actionable_proposals, generate_proposals, rejection_fingerprint
from netbot.state import State
from netbot.cli import main


class RejectionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.config = self.root / "topology.yaml"
        self.config.write_text("version: 1\nauthority: arasaka\nhosts:\n  arasaka:\n    class: core\n")
        self.db = self.root / "state.sqlite3"

    def add_peer(self, node_id="abc", address="100.64.0.1", name="trauma", run_id="run-1", observed_at="t1"):
        state = State(self.db)
        state.record_discovery_cycle(run_id, "controller", observed_at, observed_at,
            "OK", "OK", "COMPLETE", None, {"nodes": [], "relationships": [], "sources": []},
            [{"provider": "tailscale", "provider_node_id": node_id, "advertised_name": name,
              "addresses": [address], "online": True, "metadata": {}, "observed_at": observed_at}])
        state.close()

    def current_proposal(self):
        state = State(self.db)
        proposal = generate_proposals([], state.discovery_graph(), state.discovery_evidence())[0]
        state.close()
        return proposal

    def test_rejects_candidate_and_retains_evidence(self):
        self.add_peer()
        proposal = self.current_proposal()
        result = reject_node(self.config, self.db, "trauma")
        self.assertEqual(result["result"], "REJECTED")
        self.assertFalse(result["topology_changed"])
        self.assertFalse(result["reconciliation_performed"])
        state = State(self.db)
        self.assertEqual(len(state.discovery_evidence()["nodes"]), 1)
        self.assertEqual(len(state.topology_decisions("REJECT")), 1)
        state.close()
        self.assertEqual(proposal["proposal_type"], "NEW_IDENTITY_CANDIDATE")

    def test_same_provider_identity_stays_suppressed_across_ip_name_and_run_changes(self):
        self.add_peer(address="100.64.0.1", name="trauma", run_id="run-1")
        self.assertEqual(reject_node(self.config, self.db, "trauma")["result"], "REJECTED")
        self.add_peer(address="100.64.0.99", name="trauma-renamed", run_id="run-2", observed_at="t2")
        state = State(self.db)
        proposals = generate_proposals([], state.discovery_graph(), state.discovery_evidence())
        self.assertEqual(filter_actionable_proposals(proposals, state.topology_decisions("REJECT")), [])
        state.close()

    def test_new_provider_identity_reopens(self):
        self.add_peer(node_id="abc")
        self.assertEqual(reject_node(self.config, self.db, "trauma")["result"], "REJECTED")
        self.add_peer(node_id="def", run_id="run-2", observed_at="t2")
        self.assertEqual(reject_node(self.config, self.db, "trauma")["result"], "REJECTED")

    def test_corresponding_host_key_is_not_part_of_provider_fingerprint(self):
        proposal = {"proposal_type": "NEW_IDENTITY_CANDIDATE",
                    "provider_binding": {"provider": "tailscale", "provider_node_id": "abc"}}
        first = rejection_fingerprint(proposal)
        proposal["supporting_evidence"] = ("same host_key_fingerprint XYZ",)
        self.assertEqual(first, rejection_fingerprint(proposal))

    def test_rejection_resolves_matching_proposal_event(self):
        self.add_peer()
        proposal = self.current_proposal()
        state = State(self.db)
        state.record_event("NEW_TOPOLOGY_PROPOSAL", "ATTENTION", "trauma",
                           "proposal:" + proposal["proposal_id"], "new trauma")
        state.commit_events(); state.close()
        reject_node(self.config, self.db, "trauma")
        state = State(self.db)
        self.assertIsNotNone(state.events(10)[0]["resolved_at"])
        decision = state.topology_decisions("REJECT")[0]
        event = state.events(10)[0]
        self.assertEqual(event["stable_key"], "proposal:" + decision["proposal_id"])
        self.assertIsNotNone(event["resolved_at"])
        state.close()

    def test_interrupted_resolution_rolls_back_decision_and_event_update(self):
        self.add_peer()
        proposal = self.current_proposal()
        state = State(self.db)
        state.record_event("NEW_TOPOLOGY_PROPOSAL", "ATTENTION", "trauma",
                           "proposal:" + proposal["proposal_id"], "new trauma")
        state.commit_events()
        fingerprint = rejection_fingerprint(proposal)
        with patch.object(state, "resolve_event", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                state.record_topology_decision({
                    "decision_type": "REJECT", "evidence_fingerprint": fingerprint["fingerprint"],
                    "fingerprint_version": fingerprint["version"], "proposal_type": proposal["proposal_type"],
                    "proposal_id": proposal["proposal_id"], "subject_reference": "trauma"})
        state.close()
        recovered = State(self.db)
        self.assertEqual(recovered.topology_decisions("REJECT"), [])
        self.assertIsNone(recovered.events(10)[0]["resolved_at"])
        recovered.close()

    def test_rejection_is_idempotent(self):
        self.add_peer()
        self.assertEqual(reject_node(self.config, self.db, "trauma")["result"], "REJECTED")
        self.assertEqual(reject_node(self.config, self.db, "trauma")["result"], "ALREADY_REJECTED")
        state = State(self.db)
        self.assertEqual(len(state.topology_decisions("REJECT")), 1)
        state.close()

    def test_ambiguous_reference_refuses_without_mutation(self):
        proposals = [{"proposal_type": "NEW_IDENTITY_CANDIDATE", "proposal_id": "a",
                      "proposed_alias": "trauma", "target_entity": "a",
                      "provider_binding": {"provider": "tailscale", "provider_node_id": "a"}},
                     {"proposal_type": "NEW_IDENTITY_CANDIDATE", "proposal_id": "b",
                      "proposed_alias": "trauma", "target_entity": "b",
                      "provider_binding": {"provider": "tailscale", "provider_node_id": "b"}}]
        before = self.config.read_bytes()
        with patch("netbot.discovery.acceptance.generate_proposals", return_value=proposals):
            result = reject_node(self.config, self.db, "trauma")
        self.assertEqual(result["result"], "AMBIGUOUS")
        self.assertEqual(self.config.read_bytes(), before)

    def test_cli_human_hides_internal_rejection_metadata_and_json_exposes_it(self):
        self.add_peer()
        output = StringIO()
        with redirect_stdout(output):
            main(["reject", "trauma", "--config", str(self.config), "--db", str(self.db)])
        human = output.getvalue()
        self.assertIn("Rejected trauma", human)
        self.assertNotIn("reject-v1", human)
        self.assertNotIn("proposal_id", human)

        self.add_peer(node_id="def", name="second", run_id="run-2", observed_at="t2")
        output = StringIO()
        with redirect_stdout(output):
            main(["reject", "second", "--json", "--config", str(self.config), "--db", str(self.db)])
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["command"], "reject")
        self.assertEqual(payload["result"], "REJECTED")
        self.assertIn("resolved_proposal_id", payload)
        self.assertIn("rejection_fingerprint", payload)


if __name__ == "__main__":
    unittest.main()
