import json
import subprocess
import unittest
from unittest.mock import patch

from netbot.discovery.tailscale import TAILSCALED_SOCKET, discover


class TailscaleDiscoveryTests(unittest.TestCase):
    def test_discover_uses_explicit_tailscaled_socket(self):
        payload = {"Self": {"ID": "arasaka", "HostName": "arasaka", "Online": True}}
        completed = subprocess.CompletedProcess(
            ["tailscale", f"--socket={TAILSCALED_SOCKET}", "status", "--json"],
            0, json.dumps(payload), "",
        )
        with patch("netbot.discovery.tailscale.subprocess.run", return_value=completed) as run:
            nodes, error = discover()
        self.assertIsNone(error)
        self.assertEqual(nodes[0].name, "arasaka")
        self.assertEqual(run.call_args.args[0], [
            "tailscale", f"--socket={TAILSCALED_SOCKET}", "status", "--json",
        ])


if __name__ == "__main__":
    unittest.main()
