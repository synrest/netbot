import unittest

from netbot.desired_route import desired_route
from netbot.models import DesiredHost


def host(identity, *, name=None, node_id=None, ssh=None, **attrs):
    bindings = {}
    if name is not None or node_id is not None:
        bindings["tailscale"] = {key: value for key, value in
                                  (("name", name), ("node_id", node_id)) if value is not None}
    if ssh is not None:
        bindings["ssh"] = ssh
    return DesiredHost(identity, {**attrs, "bindings": bindings})


class DesiredRouteTests(unittest.TestCase):
    def test_desired_tailscale_name_is_portable_and_alias_is_distinct(self):
        result = desired_route("source", "oracle", [
            host("source", name="source"),
            host("oracle", name="oracle.tail", node_id="oracle-id", ssh={"aliases": ["oracle"]}),
        ])
        self.assertEqual((result.state, result.kind, result.hostname, result.port),
                         ("ROUTABLE", "TAILSCALE_NAME", "oracle.tail", 22))
        self.assertNotEqual(result.hostname, "oracle")

    def test_route_does_not_depend_on_observation_or_tags(self):
        result = desired_route("source", "offline", [
            host("source", name="source"),
            host("offline", name="offline.tail", node_id="offline-id",
                 ssh={"aliases": ["offline"]}),
        ])
        self.assertEqual(result.state, "ROUTABLE")

    def test_explicit_override_and_port_win(self):
        result = desired_route("arasaka", "mikoshi", [
            host("arasaka", name="arasaka"),
            host("mikoshi", name="mikoshi.tail", node_id="mikoshi-id",
                 ssh={"aliases": ["mikoshi"], "hostname": "mikoshi.internal", "port": 2200,
                      "controller": "arasaka"}),
        ])
        self.assertEqual((result.kind, result.hostname, result.port),
                         ("EXPLICIT_OVERRIDE", "mikoshi.internal", 2200))

    def test_loopback_override_is_source_scoped(self):
        desired = [
            host("arasaka", name="arasaka"),
            host("kiroshi", name="kiroshi"),
            host("mikoshi", name="mikoshi.tail", node_id="mikoshi-id",
                 ssh={"aliases": ["mikoshi"], "hostname": "127.0.0.1", "port": 2222,
                      "controller": "arasaka"}),
        ]
        self.assertEqual(desired_route("arasaka", "mikoshi", desired).state, "ROUTABLE")
        other = desired_route("kiroshi", "mikoshi", desired)
        self.assertEqual(other.state, "NO_PORTABLE_ROUTE")
        self.assertNotEqual(other.hostname, "127.0.0.1")

    def test_missing_binding_and_unknown_destination_are_explicit(self):
        desired = [host("source", name="source"), host("unbound", ssh={"aliases": ["unbound"]})]
        self.assertEqual(desired_route("source", "missing", desired).state, "DESTINATION_UNKNOWN")
        self.assertEqual(desired_route("source", "unbound", desired).state, "DESTINATION_UNBOUND")

    def test_missing_name_has_no_portable_route(self):
        result = desired_route("source", "node", [
            host("source", name="source"),
            host("node", node_id="node-id", ssh={"aliases": ["node"]}),
        ])
        self.assertEqual(result.state, "NO_PORTABLE_ROUTE")

    def test_retired_destination_is_not_route_intent(self):
        result = desired_route("source", "old", [
            host("source", name="source"),
            host("old", name="old", node_id="old-id", lifecycle="retired"),
        ])
        self.assertEqual(result.state, "DESTINATION_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
