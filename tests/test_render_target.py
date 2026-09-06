import tempfile
import unittest
from pathlib import Path

from netbot.render_target import render_target, RenderInput, render_inputs


TOPOLOGY = """version: 1
peer_policy:
  default: topology
hosts:
  arasaka:
    bindings:
      tailscale:
        node_id: arasaka-id
        name: arasaka
      ssh:
        aliases: [arasaka]
        user: zero
  kiroshi:
    bindings:
      tailscale:
        node_id: kiroshi-id
        name: kiroshi
      ssh:
        aliases: [kiroshi]
        user: rafael
  mikoshi:
    bindings:
      tailscale:
        node_id: mikoshi-id
        name: mikoshi
      ssh:
        aliases: [mikoshi]
        user: zero
  oracle:
    class: unknown
    bindings:
      tailscale:
        node_id: oracle-id
        name: oracle
      ssh:
        aliases: [oracle]
        user: rafael
  orion:
    bindings:
      tailscale:
        node_id: orion-id
        name: orion
      ssh:
        aliases: [orion]
        user: lourdes
  lourdes:
    lifecycle: retired
    superseded_by: orion
    bindings:
      tailscale:
        node_id: lourdes-id
        name: lourdes
      ssh:
        aliases: [lourdes]
  orthanc-postgres:
    parent: arasaka
    bindings:
      tailscale:
        node_id: orthanc-id
"""


class RenderTargetTests(unittest.TestCase):
    def write(self, text=TOPOLOGY):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "topology.yaml"
        path.write_text(text)
        return directory, path

    def test_exact_deterministic_preview_excludes_self_and_history(self):
        directory, path = self.write()
        self.addCleanup(directory.cleanup)
        result = render_target(path, "mikoshi")
        expected = (
            "Host arasaka\n    HostName arasaka\n    User zero\n    Port 22\n"
            "Host kiroshi\n    HostName kiroshi\n    User rafael\n    Port 22\n"
            "Host oracle\n    HostName oracle\n    User rafael\n    Port 22\n"
            "Host orion\n    HostName orion\n    User lourdes\n    Port 22\n"
        )
        self.assertEqual(result.state, "RENDERABLE")
        self.assertEqual(result.text, expected)
        self.assertEqual(result.text.count("Host mikoshi\n"), 0)
        self.assertNotIn("127.0.0.1", result.text)
        self.assertNotIn("ProxyJump", result.text)
        self.assertNotIn("IdentityFile", result.text)
        self.assertTrue(result.text.endswith("\n"))
        self.assertEqual(result.text, render_target(path, "mikoshi").text)

    def test_offline_runtime_does_not_affect_preview(self):
        directory, path = self.write()
        self.addCleanup(directory.cleanup)
        result = render_target(path, "kiroshi")
        self.assertEqual(result.state, "RENDERABLE")
        self.assertEqual(len(result.inputs), 4)

    def test_explicit_identity_file_is_rendered(self):
        item = RenderInput("orion", "orion", "orion", "lourdes", 22,
                           "RENDERABLE", "explicit", "~/.ssh/id_ed25519_arasaka")
        self.assertEqual(render_inputs((item,)),
                         "Host orion\n    HostName orion\n    User lourdes\n    Port 22\n"
                         "    IdentityFile ~/.ssh/id_ed25519_arasaka\n")

    def test_missing_user_is_structured_and_no_partial_claim(self):
        directory, path = self.write(TOPOLOGY.replace("        user: rafael\n", "", 1))
        self.addCleanup(directory.cleanup)
        result = render_target(path, "mikoshi")
        self.assertEqual(result.state, "INCOMPLETE")
        self.assertTrue(any(item.state == "SSH_USER_MISSING" for item in result.inputs))
        self.assertEqual(result.text, "")

    def test_loopback_override_is_not_rendered_for_other_source(self):
        text = TOPOLOGY.replace(
            "        user: zero\n  oracle:",
            "        user: zero\n        hostname: 127.0.0.1\n        port: 2222\n        controller: arasaka\n  oracle:",
            1,
        )
        directory, path = self.write(text)
        self.addCleanup(directory.cleanup)
        result = render_target(path, "mikoshi")
        self.assertEqual(result.state, "RENDERABLE")
        self.assertNotIn("127.0.0.1", result.text)

    def test_policy_and_source_failures_propagate(self):
        directory, path = self.write(TOPOLOGY.replace("peer_policy:\n  default: topology\n", ""))
        self.addCleanup(directory.cleanup)
        self.assertEqual(render_target(path, "mikoshi").state, "POLICY_ABSENT")

        invalid = self.write(TOPOLOGY.replace("default: topology", "default: mesh"))
        self.addCleanup(invalid[0].cleanup)
        self.assertEqual(render_target(invalid[1], "mikoshi").state, "INVALID_POLICY")

        unbound = self.write(TOPOLOGY + "  unbound:\n    bindings:\n      ssh:\n        aliases: [unbound]\n")
        self.addCleanup(unbound[0].cleanup)
        self.assertEqual(render_target(unbound[1], "unbound").state, "SOURCE_UNBOUND")


if __name__ == "__main__":
    unittest.main()
