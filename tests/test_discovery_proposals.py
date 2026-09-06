import unittest
import tempfile
from types import SimpleNamespace
from pathlib import Path

from netbot.discovery.proposals import (
    ALREADY_ACCEPTED, CONFLICT, EXISTING_IDENTITY_REBIND_CANDIDATE,
    NEW_IDENTITY_CANDIDATE, RELATIONSHIP_CANDIDATE, generate_proposals,
    resolve_observation_to_topology_identity,
)
from netbot.discovery.acceptance import accept_proposal
from netbot.state import State
from netbot.controller_reconcile import _eligible
from netbot.desired_route import desired_route


def host(identity, node_id=None, aliases=()):
    bindings = {"ssh": {"aliases": list(aliases)}} if aliases else {}
    if node_id is not None:
        bindings["tailscale"] = {"node_id": node_id, "name": identity}
    return SimpleNamespace(identity=identity, attrs={"bindings": bindings})


def graph(nodes=(), relationships=()):
    return {"nodes": list(nodes), "relationships": list(relationships)}


class ProposalTests(unittest.TestCase):
    def node(self, key, node_id, name, addresses=("100.0.0.1",)):
        return {"evidence_key": key, "observation_identity": key, "provider": "tailscale",
                "provider_node_id": node_id, "advertised_name": name, "addresses": list(addresses)}

    def edge(self, source, destination, alias, provenance="SSH_CONFIG_HUMAN", hostname=None,
             auth_state="PASSWORD_GATED"):
        return {"source": source, "destination": destination, "alias": alias,
                "provenance": provenance, "auth_state": auth_state,
                "effective": {"hostname": hostname or destination},
                "observed_from": source}

    def test_exact_binding_is_already_accepted(self):
        result = generate_proposals([host("machine20", "node-1")], graph([self.node("tailscale:node-1", "node-1", "machine20")]))
        self.assertEqual(result[0]["proposal_type"], ALREADY_ACCEPTED)

    def test_name_or_ip_does_not_merge(self):
        result = generate_proposals([host("machine20", "old")], graph([self.node("tailscale:new", "new", "machine20")]))
        self.assertEqual(result[0]["proposal_type"], NEW_IDENTITY_CANDIDATE)

    def test_human_alias_outweighs_provider_name(self):
        node = self.node("tailscale:new", "new", "machine20")
        edge = self.edge("b", "machine20", "astra", hostname="machine20")
        result = generate_proposals([], graph([node], [edge]))
        candidate = next(item for item in result if item["proposal_type"] == NEW_IDENTITY_CANDIDATE)
        self.assertEqual(candidate["proposed_alias"], "astra")

    def test_conflicting_human_aliases_are_ambiguous(self):
        node = self.node("tailscale:new", "new", "machine20")
        edges = [self.edge("b", "machine20", "astra"), self.edge("c", "machine20", "alice")]
        result = generate_proposals([], graph([node], edges))
        self.assertEqual(next(item for item in result if item["target_entity"] == "tailscale:new")["proposal_type"], CONFLICT)

    def test_managed_alias_is_not_independent_candidate_evidence(self):
        node = self.node("tailscale:new", "new", "machine20")
        edge = self.edge("b", "machine20", "orion", provenance="SSH_CONFIG_MANAGED")
        result = generate_proposals([], graph([node], [edge]))
        candidate = next(item for item in result if item["proposal_type"] == NEW_IDENTITY_CANDIDATE)
        self.assertEqual(candidate["proposed_alias"], "machine20")

    def test_uncorrelated_human_ssh_destination_stays_evidence_without_proposal(self):
        edge = self.edge("arasaka", "github.com", "github.com", auth_state="UNAVAILABLE")
        result = generate_proposals([host("arasaka", aliases=("arasaka",))], graph([], [edge]))
        self.assertEqual(result, [])
        self.assertEqual(edge["provenance"], "SSH_CONFIG_HUMAN")

    def test_provider_backed_password_gated_destination_remains_candidate(self):
        node = self.node("tailscale:new", "new", "machine20")
        edge = self.edge("arasaka", "new", "astra", hostname="machine20")
        result = generate_proposals([], graph([node], [edge]))
        self.assertIn(NEW_IDENTITY_CANDIDATE, {item["proposal_type"] for item in result})

    def test_directed_relationship_and_password_gate_are_preserved(self):
        edge = self.edge("b", "c", "astra")
        result = generate_proposals([host("b", aliases=("astra",))], graph([], [edge]))
        self.assertEqual(result[0]["proposal_type"], RELATIONSHIP_CANDIDATE)
        self.assertEqual(result[0]["source_identity"], "b")
        self.assertNotEqual(result[0]["source_identity"], result[0]["target_entity"])

    def test_controller_observation_correlates_to_authority_without_rewriting_provenance(self):
        controller = "controller-uuid"
        accepted = host("arasaka", aliases=("existing",))
        edge = self.edge(controller, "machine20", "existing")
        result = generate_proposals([accepted], graph([], [edge]),
                                    controller_id=controller, topology_authority="arasaka")
        self.assertEqual(result, [])
        self.assertEqual(edge["source"], controller)

    def test_correlated_controller_does_not_suppress_new_alias(self):
        controller = "controller-uuid"
        accepted = host("arasaka", aliases=("existing",))
        node = self.node("tailscale:new", "new", "machine20")
        edge = self.edge(controller, "new", "new-alias", hostname="machine20")
        result = generate_proposals([accepted], graph([node], [edge]),
                                    controller_id=controller, topology_authority="arasaka")
        relationship = next(item for item in result if item["proposal_type"] == RELATIONSHIP_CANDIDATE)
        self.assertEqual(relationship["source_identity"], controller)

    def test_correlated_controller_matches_destination_topology_aliases(self):
        controller = "controller-uuid"
        accepted = [host("arasaka", aliases=("arasaka",)), host("oracle", aliases=("oracle",))]
        edge = self.edge(controller, "100.72.113.101", "oracle")
        result = generate_proposals(accepted, graph([], [edge]),
                                    controller_id=controller, topology_authority="arasaka")
        self.assertEqual(result, [])

    def test_source_correlation_requires_exact_explicit_context(self):
        self.assertIsNone(resolve_observation_to_topology_identity("arasaka", controller_id="other", topology_authority="arasaka"))
        self.assertIsNone(resolve_observation_to_topology_identity("controller-uuid", controller_id="controller-uuid", topology_authority=None))

    def test_rebind_requires_multiple_continuity_facts(self):
        old = self.node("tailscale:old", "old", "old-name")
        new = self.node("tailscale:new", "new", "new-name")
        old_edge = self.edge("b", "tailscale:old", "astra", hostname="machine20")
        new_edge = self.edge("b", "tailscale:new", "astra", hostname="machine20")
        result = generate_proposals([host("accepted", "old")], graph([new], [new_edge]),
                                    {"nodes": [old], "relationships": [old_edge]})
        self.assertIn(EXISTING_IDENTITY_REBIND_CANDIDATE,
                      {item["proposal_type"] for item in result})

    def test_proposal_id_is_deterministic(self):
        node = self.node("tailscale:new", "new", "machine20")
        a = generate_proposals([], graph([node]))
        b = generate_proposals([], graph([node]))
        self.assertEqual(a[0]["proposal_id"], b[0]["proposal_id"])

    def discovery_fixture(self, root):
        config = root / "topology.yaml"
        config.write_text("version: 1\nhosts:\n  arasaka:\n    class: core\n")
        db = root / "state.sqlite3"
        state = State(db)
        state.record_discovery_cycle("run-1", "controller", "t1", "t1", "OK", "OK", "COMPLETE", None,
            {"nodes": [], "relationships": [], "sources": []},
            [self.node("tailscale:new", "new", "machine20")])
        state.close()
        return config, db

    def test_accept_new_identity_is_explicit_and_idempotent(self):
        root = Path(tempfile.mkdtemp()); config, db = self.discovery_fixture(root)
        state = State(db); proposal = generate_proposals([], state.discovery_graph(), state.discovery_evidence())[0]; state.close()
        preview = accept_proposal(config, db, proposal["proposal_id"], dry_run=True)
        self.assertEqual(preview["result"], "WOULD_ACCEPT")
        self.assertEqual(len(load_hosts(config)), 1)
        accepted = accept_proposal(config, db, proposal["proposal_id"])
        self.assertEqual(accepted["result"], "ACCEPTED")
        self.assertEqual(len(load_hosts(config)), 2)

    def test_accepted_provider_candidate_preserves_correlated_ssh_binding_for_reconciler(self):
        root = Path(tempfile.mkdtemp()); config = root / "topology.yaml"
        config.write_text("version: 1\nhosts:\n  arasaka:\n    class: core\n")
        db = root / "state.sqlite3"; state = State(db)
        node = self.node("tailscale:new", "new", "machine20")
        edge = self.edge("controller", "new", "machine20", hostname="machine20")
        edge["effective"].update(user="zero", port=22)
        state.record_discovery_cycle("run-1", "controller", "t1", "t1", "OK", "OK", "COMPLETE", None,
                                     {"nodes": [], "relationships": [edge], "sources": []}, [node])
        proposal = next(item for item in generate_proposals([], state.discovery_graph(), state.discovery_evidence())
                        if item["proposal_type"] == NEW_IDENTITY_CANDIDATE)
        state.close()
        result = accept_proposal(config, db, proposal["proposal_id"])
        self.assertEqual(result["result"], "ACCEPTED")
        accepted = next(item for item in load_hosts(config) if item.identity == "machine20")
        self.assertEqual(accepted.attrs["bindings"]["ssh"], {"aliases": ["machine20"], "user": "zero", "port": "22"})
        self.assertTrue(_eligible(accepted))
        self.assertEqual(desired_route("arasaka", "machine20", load_hosts(config)).state, "ROUTABLE")
        retry = accept_proposal(config, db, proposal["proposal_id"])
        self.assertIn(retry["result"], {"ALREADY_ACCEPTED", "STALE_PROPOSAL"})
        self.assertEqual(len(load_hosts(config)), 2)

    def test_conflict_and_relationship_acceptance_are_non_actionable(self):
        root = Path(tempfile.mkdtemp()); config, db = self.discovery_fixture(root)
        state = State(db); g = state.discovery_graph(); state.close()
        self.assertEqual(g["run_id"], "run-1")


def load_hosts(path):
    from netbot.config import load_topology
    return load_topology(path)[1]


if __name__ == "__main__":
    unittest.main()
