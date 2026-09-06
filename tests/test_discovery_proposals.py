import unittest
from types import SimpleNamespace

from netbot.discovery.proposals import (
    ALREADY_ACCEPTED, CONFLICT, EXISTING_IDENTITY_REBIND_CANDIDATE,
    NEW_IDENTITY_CANDIDATE, RELATIONSHIP_CANDIDATE, generate_proposals,
)


def host(identity, node_id=None, aliases=()):
    bindings = {"ssh": {"aliases": list(aliases)}} if aliases else {}
    if node_id is not None:
        bindings["tailscale"] = {"node_id": node_id, "name": identity}
    return SimpleNamespace(identity=identity, attrs={"bindings": bindings})


def graph(nodes=(), relationships=()):
    return {"nodes": list(nodes), "relationships": list(relationships)}


class ProposalTests(unittest.TestCase):
    def node(self, key, node_id, name, addresses=("100.0.0.1",)):
        return {"evidence_key": key, "provider": "tailscale", "provider_node_id": node_id,
                "advertised_name": name, "addresses": list(addresses)}

    def edge(self, source, destination, alias, provenance="SSH_CONFIG_HUMAN", hostname=None,
             auth_state="PASSWORD_GATED"):
        return {"source": source, "destination": destination, "alias": alias,
                "provenance": provenance, "auth_state": auth_state,
                "effective": {"hostname": hostname or destination}}

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

    def test_directed_relationship_and_password_gate_are_preserved(self):
        edge = self.edge("b", "c", "astra")
        result = generate_proposals([], graph([], [edge]))
        self.assertEqual(result[0]["proposal_type"], RELATIONSHIP_CANDIDATE)
        self.assertEqual(result[0]["source_identity"], "b")
        self.assertNotEqual(result[0]["source_identity"], result[0]["target_entity"])

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


if __name__ == "__main__":
    unittest.main()
