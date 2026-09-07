import json
import subprocess
import unittest
from unittest.mock import patch

from netbot.discovery.tailscale import TAILSCALED_SOCKET, discover, resolve_executable


class TailscaleDiscoveryTests(unittest.TestCase):
    def test_discover_uses_explicit_tailscaled_socket(self):
        payload = {"Self": {"ID": "arasaka", "HostName": "arasaka", "Online": True}}
        completed = subprocess.CompletedProcess(
            ["tailscale", f"--socket={TAILSCALED_SOCKET}", "status", "--json"],
            0, json.dumps(payload), "",
        )
        with patch("netbot.discovery.tailscale.resolve_executable", return_value="/usr/local/bin/tailscale"), \
             patch("netbot.discovery.tailscale.subprocess.run", return_value=completed) as run:
            nodes, error = discover()
        self.assertIsNone(error)
        self.assertEqual(nodes[0].name, "arasaka")
        self.assertEqual(run.call_args.args[0], [
            "/usr/local/bin/tailscale", f"--socket={TAILSCALED_SOCKET}", "status", "--json",
        ])

    def test_resolves_normal_path(self):
        with patch("netbot.discovery.tailscale.shutil.which", return_value="/custom/bin/tailscale"):
            with patch("netbot.discovery.tailscale.Path.is_file", return_value=True), \
                 patch("netbot.discovery.tailscale.os.access", return_value=True):
                self.assertEqual(resolve_executable(platform_name="darwin"), "/custom/bin/tailscale")

    def test_resolves_macos_well_known_candidates_when_path_is_constrained(self):
        with patch("netbot.discovery.tailscale.shutil.which", return_value=None), \
             patch("netbot.discovery.tailscale.Path.is_file", side_effect=[True]), \
             patch("netbot.discovery.tailscale.os.access", return_value=True):
            self.assertEqual(resolve_executable(platform_name="darwin"), "/usr/local/bin/tailscale")

    def test_resolves_homebrew_macos_candidate(self):
        with patch("netbot.discovery.tailscale.shutil.which", return_value=None), \
             patch("netbot.discovery.tailscale.Path.is_file", side_effect=[False, True]), \
             patch("netbot.discovery.tailscale.os.access", return_value=True):
            self.assertEqual(resolve_executable(platform_name="darwin"), "/opt/homebrew/bin/tailscale")

    def test_resolves_linux_candidates(self):
        with patch("netbot.discovery.tailscale.shutil.which", return_value=None), \
             patch("netbot.discovery.tailscale.Path.is_file", side_effect=[True]), \
             patch("netbot.discovery.tailscale.os.access", return_value=True):
            self.assertEqual(resolve_executable(platform_name="linux"), "/usr/bin/tailscale")

    def test_missing_executable_is_provider_failure(self):
        with patch("netbot.discovery.tailscale.resolve_executable", return_value=None), \
             patch("netbot.discovery.tailscale.subprocess.run") as run:
            nodes, error = discover()
        self.assertEqual(nodes, [])
        self.assertEqual(error, "tailscale executable not found")
        run.assert_not_called()

    def test_online_values_remain_boolean_values(self):
        payload = {"Peer": {"a": {"NodeID": "a", "HostName": "online", "Online": True},
                             "b": {"NodeID": "b", "HostName": "offline", "Online": False}}}
        nodes = {node.node_id: node for node in __import__("netbot.discovery.tailscale", fromlist=["normalize_status"]).normalize_status(payload)}
        self.assertIs(nodes["a"].online, True)
        self.assertIs(nodes["b"].online, False)


if __name__ == "__main__":
    unittest.main()
