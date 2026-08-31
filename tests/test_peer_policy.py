import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from netbot.cli import main
from netbot.models import DesiredHost
from netbot.peer_policy import PeerOverride, PeerPolicy, PolicyValidationError, expected_peers, load_peer_policy


def host(identity, cls, *, bound=True, ssh=True, **attrs):
    values = {"class": cls, **attrs}
    bindings = {}
    if bound:
        bindings["tailscale"] = {"node_id": identity + "-id"}
    if ssh:
        bindings["ssh"] = {"aliases": [identity]}
    if bindings:
        values["bindings"] = bindings
    return DesiredHost(identity, values)


class PeerPolicyTests(unittest.TestCase):
    def test_policy_absent_is_fail_closed(self):
        result = expected_peers("a", [host("a", "core"), host("b", "core")], None)
        self.assertEqual(result.state, "POLICY_ABSENT")
        self.assertEqual(result.peers, ())

    def test_default_topology_selects_all_eligible_destinations(self):
        result = expected_peers("a", [host("a", "core"), host("b", "core"), host("c", "unknown"),
                                      host("d", "core", ssh=False), host("retired", "core", lifecycle="retired"),
                                      host("unbound", "core", bound=False)], PeerPolicy(default="topology"))
        self.assertEqual([p.destination_identity for p in result.peers], ["b", "c"])
        self.assertTrue(all(p.reason == "TOPOLOGY_DEFAULT" for p in result.peers))

    def test_self_offline_and_unobserved_states(self):
        policy = PeerPolicy(default="topology")
        desired = [host("a", "core"), host("b", "core")]
        online = expected_peers("a", desired, policy, observed=[{"identity": "b", "online": True}])
        offline = expected_peers("a", desired, policy, observed=[{"identity": "b", "online": False}])
        absent = expected_peers("a", desired, policy, observed=[])
        self.assertEqual(online.peers, offline.peers)
        self.assertEqual(offline.peers, absent.peers)
        self.assertNotIn("a", [p.destination_identity for p in online.peers])

    def test_explicit_class_filter_is_a_refinement(self):
        policy = PeerPolicy(default="topology", classes={"core": ("core",)})
        result = expected_peers("a", [host("a", "core"), host("b", "core"), host("c", "satellite")], policy)
        self.assertEqual([p.destination_identity for p in result.peers], ["b"])
        self.assertEqual(result.peers[0].reason, "TOPOLOGY_DEFAULT")

    def test_explicit_include_and_exclude(self):
        policy = PeerPolicy(default="topology", classes={"core": ("core",)},
                           overrides={"a": PeerOverride(include=("sat",), exclude=("b",))})
        result = expected_peers("a", [host("a", "core"), host("b", "core"), host("sat", "satellite")], policy)
        self.assertEqual([(p.destination_identity, p.reason) for p in result.peers], [("sat", "EXPLICIT_INCLUDE")])
        self.assertEqual(result.excluded[0].reason, "EXPLICIT_EXCLUDE")

    def test_exclude_wins_and_invalid_include_cannot_resurrect(self):
        policy = PeerPolicy(default="topology", overrides={"a": PeerOverride(
            include=("retired", "gone", "alias-b", "superseded"), exclude=("b",))})
        desired = [host("a", "core"), host("b", "core"), host("retired", "core", lifecycle="retired"),
                   host("superseded", "core", superseded_by="new"), host("b-real", "core")]
        result = expected_peers("a", desired, policy)
        self.assertNotIn("b", [p.destination_identity for p in result.peers])
        self.assertNotIn("retired", [p.destination_identity for p in result.peers])
        self.assertNotIn("superseded", [p.destination_identity for p in result.peers])
        self.assertNotIn("alias-b", [p.destination_identity for p in result.peers])

    def test_source_states_are_fail_closed(self):
        policy = PeerPolicy(default="topology")
        cases = [("missing", "SOURCE_UNKNOWN", []),
                 ("retired", "SOURCE_RETIRED", [host("retired", "core", lifecycle="retired")]),
                 ("superseded", "SOURCE_SUPERSEDED", [host("superseded", "core", superseded_by="new")]),
                 ("unbound", "SOURCE_UNBOUND", [host("unbound", "core", bound=False)])]
        for source, state, desired in cases:
            self.assertEqual(expected_peers(source, desired, policy).state, state)

    def test_unknown_class_and_bootstrap_tags_have_no_magic(self):
        policy = PeerPolicy(default="topology")
        desired = [host("a", "unknown"), host("b", "core")]
        tagged = expected_peers("a", desired, policy, observed=[{"identity": "b", "tags": ["tag:netbot-bootstrap"]}])
        untagged = expected_peers("a", desired, policy, observed=[{"identity": "b", "tags": []}])
        self.assertEqual(tagged.peers, untagged.peers)
        self.assertEqual([p.destination_identity for p in tagged.peers], ["b"])

    def test_aliases_do_not_substitute_for_identity(self):
        result = expected_peers("a", [host("a", "core"), host("b", "core")],
                                PeerPolicy(default="topology", overrides={"a": PeerOverride(include=("alias-b",))}))
        self.assertNotIn("alias-b", [p.destination_identity for p in result.peers])

    def test_malformed_or_unsupported_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "topology.yaml"
            path.write_text("version: 1\npeer_policy:\n  default: mesh\n")
            with self.assertRaises(PolicyValidationError):
                load_peer_policy(path)
            path.write_text("version: 1\npeer_policy:\n  classes:\n    core:\n      sees:\n        - core\n")
            with self.assertRaises(PolicyValidationError):
                load_peer_policy(path)

    def test_cli_absent_policy_and_unbound_source(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "topology.yaml"
            path.write_text("version: 1\nhosts:\n  a:\n    class: core\n")
            output = StringIO()
            with redirect_stdout(output):
                main(["ssh", "expected-target", "a", "--config", str(path)])
            self.assertIn('"state": "POLICY_ABSENT"', output.getvalue())
            path.write_text("version: 1\npeer_policy:\n  default: topology\nhosts:\n  a:\n    class: core\n")
            output = StringIO()
            with redirect_stdout(output):
                main(["ssh", "expected-target", "a", "--config", str(path)])
            self.assertIn('"state": "SOURCE_UNBOUND"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
