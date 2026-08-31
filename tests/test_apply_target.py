import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netbot.apply_target import (READ_COMMAND, REMOVE_COMMAND, WRITE_COMMAND,
                                 apply_target, build_apply_plan)
from netbot.target_view import SSHRelationship, SSHView


TOPOLOGY = """version: 1
authority: arasaka
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
"""


def view(state="MISSING", provenance="ABSENT"):
    return SSHView("kiroshi", "OK", [SSHRelationship(
        "arasaka", "arasaka", state, provenance, {},
    )])


class RemoteFiles:
    def __init__(self, current=None):
        self.current = current
        self.calls = []
        self.writes = 0

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        remote = command[-1]
        if remote == READ_COMMAND:
            if self.current is None:
                return subprocess.CompletedProcess(command, 3, "", "")
            return subprocess.CompletedProcess(command, 0, self.current, "")
        if remote == REMOVE_COMMAND:
            self.current = None
            self.writes += 1
            return subprocess.CompletedProcess(command, 0, "", "")
        if remote == WRITE_COMMAND:
            self.current = kwargs.get("input")
            self.writes += 1
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected remote command: {remote}")


class ApplyTargetTests(unittest.TestCase):
    def config(self, root):
        path = root / "topology.yaml"
        path.write_text(TOPOLOGY)
        return path

    def test_dry_run_create_is_read_only_and_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual(plan.action, "CREATE")
            self.assertIn("Host arasaka\n    HostName arasaka\n    User zero\n    Port 22\n", plan.desired_content)
            self.assertEqual(remote.writes, 0)
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                again = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual(plan.desired_content, again.desired_content)

    def test_verified_bootstrap_transport_bridges_missing_alias(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            transport = {
                "endpoint": "netbot-test", "user": "zero", "port": 22,
                "identity_file": "/tmp/controller-key",
                "known_hosts_file": "/tmp/verified-host-keys",
                "host_keys": [{"key_type": "ssh-ed25519", "key_data": "AAAA"}],
                "source": "verified-bootstrap-ordinary-ssh",
            }
            with patch("netbot.apply_target._bootstrap_transport", return_value=transport), \
                 patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual(plan.action, "CREATE")
            self.assertEqual(plan.transport_spec, transport)
            self.assertNotIn("transport_spec", plan.as_dict())
            self.assertTrue(all(
                "-i" in command and "IdentitiesOnly=yes" in command and
                "StrictHostKeyChecking=yes" in command
                for command, _ in remote.calls
            ))

    def test_apply_verifies_bytes_and_post_view(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
                result = apply_target(plan, path, runner=remote)
            self.assertEqual(result["result"], "WRITE_VERIFIED")
            self.assertEqual(result["view_verification"], "VIEW_VERIFIED")
            self.assertEqual(remote.writes, 1)
            self.assertEqual(remote.current, plan.desired_content)

    def test_idempotent_second_plan_has_no_write(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                first = build_apply_plan(path, "kiroshi", runner=remote)
                apply_target(first, path, runner=remote)
                second = build_apply_plan(path, "kiroshi", runner=remote)
                result = apply_target(second, path, runner=remote)
            self.assertEqual(second.action, "NO_CHANGE")
            self.assertEqual(result["result"], "NO_CHANGE")
            self.assertEqual(remote.writes, 1)

    def test_manual_alias_is_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            with patch("netbot.apply_target.build_ssh_view", return_value=view("VALID_MANUAL", "EXPLICIT")):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual(plan.action, "NO_CHANGE")
            self.assertEqual(plan.managed_peers, ())
            self.assertEqual(plan.human_peers, ("arasaka",))
            self.assertEqual(remote.writes, 0)

    def test_conflict_unknown_and_unavailable_block_without_write(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d))
            for state, provenance in (("CONFLICT", "EXPLICIT"), ("UNKNOWN", "UNKNOWN"), ("UNAVAILABLE", "UNKNOWN")):
                remote = RemoteFiles("existing")
                with patch("netbot.apply_target.build_ssh_view", return_value=view(state, provenance)):
                    plan = build_apply_plan(path, "kiroshi", runner=remote)
                self.assertEqual(plan.action, "BLOCKED")
                self.assertEqual(remote.writes, 0)
                self.assertEqual(remote.current, "existing")

    def test_replace_and_remove_only_managed_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles("old")
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                replace = build_apply_plan(path, "kiroshi", runner=remote)
                self.assertEqual(replace.action, "REPLACE")
                apply_target(replace, path, runner=remote)
                with patch("netbot.apply_target.build_ssh_view", return_value=view("VALID_MANUAL", "EXPLICIT")):
                    remove = build_apply_plan(path, "kiroshi", runner=remote)
                    result = apply_target(remove, path, runner=remote)
            self.assertEqual(remove.action, "REMOVE")
            self.assertEqual(result["result"], "WRITE_VERIFIED")
            self.assertIsNone(remote.current)
            self.assertEqual(remote.writes, 2)
            for command, kwargs in remote.calls:
                if command[-1] == WRITE_COMMAND:
                    self.assertNotIn("Host arasaka", command[-1])
                    self.assertTrue(kwargs.get("input"))

    def test_write_failure_preserves_existing_content(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles("old")
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            original = remote.current
            def fail_write(command, **kwargs):
                if command[-1] == WRITE_COMMAND:
                    return subprocess.CompletedProcess(command, 1, "", "write failed")
                return remote(command, **kwargs)
            result = apply_target(plan, path, runner=fail_write)
            self.assertEqual(result["result"], "WRITE_FAILED")
            self.assertEqual(remote.current, original)

    def test_post_write_unavailable_is_distinguished(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            unavailable = SSHView("kiroshi", "UNAVAILABLE", [], "view unavailable")
            with patch("netbot.apply_target.build_ssh_view", side_effect=[view(), unavailable]):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
                result = apply_target(plan, path, runner=remote)
            self.assertEqual(result["result"], "WRITE_VERIFIED")
            self.assertEqual(result["view_verification"], "VIEW_UNAVAILABLE")

    def test_local_target_and_transport_read_failure_block(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d))
            self.assertEqual(build_apply_plan(path, "arasaka").state, "LOCAL_TARGET_NOT_IMPLEMENTED")
            remote = RemoteFiles()
            remote.__call__ = lambda *args, **kwargs: None
            with patch("netbot.apply_target.build_ssh_view", return_value=view()), \
                 patch("netbot.apply_target._read_managed", return_value=("REMOTE_READ_ERROR", None, "read failed")):
                plan = build_apply_plan(path, "kiroshi", runner=RemoteFiles())
            self.assertEqual(plan.state, "REMOTE_READ_ERROR")
            self.assertEqual(plan.action, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
