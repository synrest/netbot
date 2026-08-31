import tempfile
import unittest
from pathlib import Path

from netbot.cli import main
from netbot.config import load_topology
from netbot.models import DesiredHost
from netbot.peer_policy import (
    PeerOverride, PeerPolicy, PolicyValidationError, expected_peers, load_peer_policy,
)


def host(identity, cls, *, bound=True, **attrs):
    values = {"class": cls, **attrs}
    if bound:
        values["bindings"] = {"tailscale": {"node_id": identity + "-id"}}
    return DesiredHost(identity, values)


class PeerPolicyTests(unittest.TestCase):
    def test_policy_absent_is_fail_closed(self):
        result = expected_peers("a", [host("a", "core"), host("b", "core")], None)
        self.assertEqual(result.state, "POLICY_ABSENT")
        self.assertEqual(result.peers, ())

    def test_class_policy_excludes_self_and_filters_classes(self):
        policy = PeerPolicy(classes={"core": ("core",)})
        result = expected_peers("a", [host("a", "core"), host("b", "core"), host("c", "satellite")], policy)
        self.assertEqual([p.destination_identity for p in result.peers], ["b"])

    def test_multiple_classes_and_explicit_include(self):
        policy = PeerPolicy(classes={"core": ("core", "satellite")}, overrides={"a": PeerOverride(include=("d",))})
        result = expected_peers("a", [host("a", "core"), host("b", "satellite"), host("d", "unknown")], policy)
        self.assertEqual([(p.destination_identity, p.reason) for p in result.peers],
                         [("b", "CLASS_POLICY"), ("d", "EXPLICIT_INCLUDE")])

    def test_exclude_wins_over_include_and_class(self):
        policy = PeerPolicy(classes={"core": ("core",)}, overrides={"a": PeerOverride(include=("b",), exclude=("b",))})
        result = expected_peers("a", [host("a", "core"), host("b", "core")], policy)
        self.assertEqual(result.peers, ())
        self.assertEqual(result.excluded[0].reason, "EXPLICIT_EXCLUDE")

    def test_retired_superseded_and_unbound_are_excluded(self):
        policy = PeerPolicy(classes={"core": ("core",)}, overrides={"a": PeerOverride(include=("unbound",))})
        desired = [host("a", "core"), host("retired", "core", lifecycle="retired"),
                   host("superseded", "core", superseded_by="new"), host("unbound", "core", bound=False)]
        result = expected_peers("a", desired, policy)
        self.assertEqual(result.peers, ())
        self.assertEqual(result.excluded[0].reason, "UNBOUND/INELIGIBLE")

    def test_unknown_class_tags_observation_and_online_state_have_no_magic(self):
        policy = PeerPolicy(classes={"core": ("core",)})
        desired = [host("a", "mystery"), host("b", "satellite")]
        one = expected_peers("a", desired, policy, observed=[{"identity": "b", "online": True, "tags": ["tag:netbot-bootstrap"]}])
        two = expected_peers("a", desired, policy, observed=[{"identity": "b", "online": False, "tags": []}])
        self.assertEqual(one.peers, two.peers)
        self.assertEqual(one.peers, ())

    def test_unknown_source_and_aliases_do_not_substitute_for_identity(self):
        policy = PeerPolicy(classes={"core": ("core",)})
        result = expected_peers("alias-a", [host("a", "core"), host("b", "core")], policy)
        self.assertEqual(result.state, "UNKNOWN_SOURCE")

    def test_policy_parser_and_malformed_policy(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "topology.yaml"
            path.write_text("""version: 1
peer_policy:
  classes:
    core:
      sees:
        - core
  overrides:
    a:
      include:
        - b
      exclude:
        - c
hosts:
  a:
    class: core
""")
            policy = load_peer_policy(path)
            self.assertEqual(policy.classes["core"], ("core",))
            self.assertEqual(policy.overrides["a"].include, ("b",))
            path.write_text("version: 1\npeer_policy:\n  bad:\n    value: x\n")
            with self.assertRaises(PolicyValidationError):
                load_peer_policy(path)

    def test_cli_absent_policy_is_explicit_and_does_not_probe(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "topology.yaml"
            path.write_text("version: 1\nhosts:\n  a:\n    class: core\n")
            from io import StringIO
            from contextlib import redirect_stdout
            output = StringIO()
            with redirect_stdout(output):
                main(["ssh", "expected-target", "a", "--config", str(path)])
            self.assertIn('"peer_policy": "NOT_DECLARED"', output.getvalue())
            self.assertIn('"state": "POLICY_ABSENT"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
