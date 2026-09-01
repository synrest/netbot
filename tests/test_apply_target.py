import subprocess
import tempfile
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

from netbot.apply_target import (READ_COMMAND, REMOVE_COMMAND, WRITE_COMMAND,
                                 CONTROLLER_MARKER, MANAGED_MARKER, apply_target, build_apply_plan)
from netbot.state import State
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
        path = root / "config" / "topology.yaml"
        path.parent.mkdir()
        path.write_text(TOPOLOGY)
        return path

    def owned_current(self, path, body="old\n"):
        state = State(path.parent.parent / "state" / "netbot.sqlite3")
        controller = state.controller_identity()
        current = f"{MANAGED_MARKER}\n{CONTROLLER_MARKER}{controller}\n{body}"
        state.save_managed_ssh_ownership("kiroshi", controller, "~/.ssh/config.d/50-netbot.conf",
                                         "kiroshi-id", hashlib.sha256(current.encode()).hexdigest(), "now")
        state.close()
        return current

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

    def test_apply_plan_delegates_manual_proof_to_shared_view(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            with patch("netbot.apply_target.build_ssh_view", return_value=view("VALID_MANUAL", "EXPLICIT")) as build_view:
                build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual(build_view.call_args.args, (path, "kiroshi"))

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
            with patch("netbot.apply_target.resolve_observation_transport", return_value=transport), \
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
            self.assertIn(MANAGED_MARKER, remote.current)
            self.assertNotIn(CONTROLLER_MARKER + "unprovisioned", remote.current)

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
            path = self.config(Path(d)); remote = RemoteFiles(self.owned_current(path))
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
            path = self.config(Path(d)); remote = RemoteFiles(self.owned_current(path))
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

    def test_unmarked_existing_file_blocks_replace_and_remove(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles("legacy\n")
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual((plan.state, plan.action), ("UNMARKED_EXISTING", "BLOCKED"))

    def test_create_adds_marker_and_persists_ownership(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
                self.assertIn(MANAGED_MARKER, plan.desired_content)
                result = apply_target(plan, path, runner=remote)
            self.assertEqual(result["result"], "WRITE_VERIFIED")
            state = State(path.parent.parent / "state" / "netbot.sqlite3")
            record = state.managed_ssh_ownership("kiroshi")
            self.assertIsNotNone(record)
            self.assertEqual(record["content_hash"], hashlib.sha256(remote.current.encode()).hexdigest())
            state.close()

    def test_owned_drift_blocks_replace(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles(self.owned_current(path) + "# external drift\n")
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual((plan.state, plan.action), ("DRIFTED", "BLOCKED"))

    def test_marked_file_without_local_record_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles(
                f"{MANAGED_MARKER}\n{CONTROLLER_MARKER}other-controller\nold\n")
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual((plan.state, plan.action), ("UNCLAIMED_MARKED", "BLOCKED"))

    def test_foreign_controller_marker_blocks_when_controller_is_known(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); state = State(path.parent.parent / "state" / "netbot.sqlite3")
            state.controller_identity(); state.close()
            remote = RemoteFiles(f"{MANAGED_MARKER}\n{CONTROLLER_MARKER}other-controller\nold\n")
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
            self.assertEqual((plan.state, plan.action), ("FOREIGN_CONTROLLER", "BLOCKED"))

    def test_owned_file_can_be_removed_and_record_is_retired(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles(self.owned_current(path))
            with patch("netbot.apply_target.build_ssh_view", return_value=view("VALID_MANUAL", "EXPLICIT")):
                plan = build_apply_plan(path, "kiroshi", runner=remote)
                result = apply_target(plan, path, runner=remote)
            self.assertEqual((plan.action, result["result"]), ("REMOVE", "WRITE_VERIFIED"))
            state = State(path.parent.parent / "state" / "netbot.sqlite3")
            self.assertIsNone(state.managed_ssh_ownership("kiroshi")); state.close()

    def test_path_safety_failure_blocks_without_write(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d)); remote = RemoteFiles()
            def unsafe(command, **kwargs):
                if command[-1] == READ_COMMAND:
                    return subprocess.CompletedProcess(command, 44, "", "unsafe managed path")
                return remote(command, **kwargs)
            with patch("netbot.apply_target.build_ssh_view", return_value=view()):
                plan = build_apply_plan(path, "kiroshi", runner=unsafe)
            self.assertEqual(plan.action, "BLOCKED")
            self.assertEqual(plan.state, "REMOTE_READ_ERROR")

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
