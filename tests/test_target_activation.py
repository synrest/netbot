import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netbot.target_activation import (CREATE_COMMAND, INCLUDE, TargetActivationPlan,
                                      build_activation_plan, activate_target)


SPEC = {
    "endpoint": "netbot-test", "user": "zero", "port": 22,
    "identity_file": "/tmp/controller-key", "known_hosts_file": "/tmp/hosts",
    "host_keys": [{"key_type": "ssh-ed25519", "key_data": "AAAA"}],
    "source": "verified-bootstrap-ordinary-ssh",
}


class ActivationRunner:
    def __init__(self, output):
        self.output = output
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, self.output, "")


class TargetActivationTests(unittest.TestCase):
    def test_live_activation_uses_planned_normal_alias_without_bootstrap(self):
        original = "Host *\n    User rafael\n"
        expected = INCLUDE + "\n" + original
        plan = TargetActivationPlan("kiroshi", "READY", "INSERT_INCLUDE",
                                    desired_content=expected,
                                    transport_alias="kiroshi",
                                    transport_source="normal-alias")
        runner = ActivationRunner(expected)
        result = activate_target(plan, Path("topology.yaml"), runner=runner)
        self.assertEqual(result["result"], "WRITE_VERIFIED")
        self.assertGreaterEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[0][0][0:2], ["ssh", "-o"])
        self.assertIn("kiroshi", runner.calls[0][0])
        self.assertNotIn("-i", runner.calls[0][0])

    def test_absent_config_plans_create_substrate(self):
        output = "NETBOT_CONFIG_ABSENT\nNETBOT_CONFIG_D_ABSENT\n"
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=ActivationRunner(output))
        self.assertEqual(plan.state, "CONFIG_ABSENT")
        self.assertEqual(plan.action, "CREATE_SUBSTRATE")
        self.assertEqual(plan.desired_content, INCLUDE + "\n")

    def test_existing_correct_include_is_no_change(self):
        output = "NETBOT_CONFIG_PRESENT\nInclude ~/.ssh/config.d/*\nNETBOT_CONFIG_D_PRESENT\n50-netbot.conf\n"
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=ActivationRunner(output))
        self.assertEqual((plan.state, plan.action), ("ACTIVE", "NO_CHANGE"))

    def test_existing_config_without_include_blocks(self):
        output = "NETBOT_CONFIG_PRESENT\nHost human\n    User zero\nNETBOT_CONFIG_D_ABSENT\n"
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=ActivationRunner(output))
        self.assertEqual((plan.state, plan.action), ("INCLUDE_MISSING", "BLOCKED"))

    def test_existing_config_authorized_plans_top_level_insertion(self):
        content = "Host *\n    User rafael\n\nHost oracle\n    User rafael\n"
        output = "NETBOT_CONFIG_PRESENT\n" + content + "NETBOT_CONFIG_D_ABSENT\n"
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test",
                                         runner=ActivationRunner(output),
                                         authorize_existing_config=True)
        self.assertEqual((plan.state, plan.action), ("READY", "INSERT_INCLUDE"))
        self.assertEqual(plan.safety, "EXISTING_CONFIG_SAFE_FOR_INCLUDE")
        self.assertEqual(plan.config_d_action, "CREATE")
        self.assertEqual(plan.desired_content, INCLUDE + "\n" + content)

    def test_existing_config_authorized_activation_is_verified(self):
        content = "Host *\n    User rafael\n"
        inspect = "NETBOT_CONFIG_PRESENT\n" + content + "NETBOT_CONFIG_D_ABSENT\n"
        class InsertRunner:
            def __init__(self):
                self.calls = []
                self.current = None
            def __call__(self, command, **kwargs):
                self.calls.append((command, kwargs))
                if "rollback" in command[-1]:
                    self.current = kwargs["input"]
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, self.current or inspect, "")
        runner = InsertRunner()
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test",
                                         runner=ActivationRunner(inspect),
                                         authorize_existing_config=True)
            result = activate_target(plan, Path(d) / "topology.yaml", runner=runner)
        self.assertEqual(result["result"], "WRITE_VERIFIED")
        self.assertEqual(runner.current, plan.desired_content)
        self.assertIn("sha256sum", runner.calls[0][0][-1])
        self.assertIn("mv \"$tmp\" \"$HOME/.ssh/config\"", runner.calls[0][0][-1])

    def test_include_after_host_is_conflict(self):
        output = "NETBOT_CONFIG_PRESENT\nHost human\nInclude ~/.ssh/config.d/*\nNETBOT_CONFIG_D_PRESENT\n"
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=ActivationRunner(output))
        self.assertEqual((plan.state, plan.action), ("INCLUDE_CONFLICT", "BLOCKED"))

    def test_duplicate_safe_include_is_idempotent(self):
        output = "NETBOT_CONFIG_PRESENT\nInclude ~/.ssh/config.d/*\nInclude ~/.ssh/config.d/*\nHost human\nNETBOT_CONFIG_D_PRESENT\n"
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=ActivationRunner(output))
        self.assertEqual((plan.state, plan.action), ("ACTIVE", "NO_CHANGE"))

    def test_create_is_exact_and_verified(self):
        inspect = ActivationRunner("NETBOT_CONFIG_ABSENT\nNETBOT_CONFIG_D_ABSENT\n")
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=inspect)
            verify = ActivationRunner(INCLUDE + "\n")
            result = activate_target(plan, Path(d) / "topology.yaml", runner=verify)
        self.assertEqual(result["result"], "WRITE_VERIFIED")
        self.assertEqual(verify.calls[0][0][-1], CREATE_COMMAND)
        self.assertEqual(verify.calls[1][0][-1], 'cat "$HOME/.ssh/config"')

    def test_dry_run_performs_no_write(self):
        runner = ActivationRunner("NETBOT_CONFIG_ABSENT\nNETBOT_CONFIG_D_ABSENT\n")
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=runner)
        self.assertEqual(plan.action, "CREATE_SUBSTRATE")
        self.assertEqual(len(runner.calls), 1)
        self.assertNotIn("mv", runner.calls[0][0][-1])

    def test_unavailable_transport_is_structured(self):
        runner = ActivationRunner("")
        with tempfile.TemporaryDirectory() as d, patch("netbot.target_activation.resolve_observation_transport", return_value=None):
            plan = build_activation_plan(Path(d) / "topology.yaml", "netbot-test", runner=runner)
        self.assertEqual((plan.state, plan.action), ("UNAVAILABLE", "BLOCKED"))

    def test_lost_response_recovers_exact_expected_commit(self):
        original = "Host *\n    User rafael\n"
        expected = INCLUDE + "\n" + original
        plan = TargetActivationPlan("netbot-test", "READY", "INSERT_INCLUDE", desired_content=expected,
                                    transport_alias="netbot-test", transport_spec=SPEC,
                                    transport_source="verified-bootstrap-ordinary-ssh")
        class RecoveryRunner:
            def __init__(self): self.calls = 0
            def __call__(self, command, **kwargs):
                self.calls += 1
                if self.calls == 1: return (None, "connection lost after commit")
                return subprocess.CompletedProcess(command, 0,
                    "NETBOT_CONFIG_PRESENT\n" + expected + "NETBOT_CONFIG_D_PRESENT\n", "")
        with patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            result = activate_target(plan, Path("topology.yaml"), runner=RecoveryRunner())
        self.assertEqual((result["result"], result["commit_state"]), ("WRITE_VERIFIED", "COMMITTED_AND_VERIFIED"))

    def test_lost_response_recovers_exact_original_as_not_committed(self):
        original = "Host *\n    User rafael\n"
        expected = INCLUDE + "\n" + original
        plan = TargetActivationPlan("netbot-test", "READY", "INSERT_INCLUDE", desired_content=expected,
                                    transport_alias="netbot-test", transport_spec=SPEC,
                                    transport_source="verified-bootstrap-ordinary-ssh")
        class RecoveryRunner:
            def __init__(self): self.calls = 0
            def __call__(self, command, **kwargs):
                self.calls += 1
                if self.calls == 1: return (None, "connection lost after rollback")
                return subprocess.CompletedProcess(command, 0,
                    "NETBOT_CONFIG_PRESENT\n" + original + "NETBOT_CONFIG_D_ABSENT\n", "")
        with patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            result = activate_target(plan, Path("topology.yaml"), runner=RecoveryRunner())
        self.assertEqual((result["result"], result["commit_state"]), ("WRITE_FAILED", "NOT_COMMITTED"))

    def test_lost_response_without_recovery_is_indeterminate(self):
        original = "Host *\n    User rafael\n"
        plan = TargetActivationPlan("netbot-test", "READY", "INSERT_INCLUDE",
                                    desired_content=INCLUDE + "\n" + original,
                                    transport_alias="netbot-test", transport_spec=SPEC,
                                    transport_source="verified-bootstrap-ordinary-ssh")
        class UnavailableRunner:
            def __call__(self, command, **kwargs): return (None, "connection lost")
        with patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            result = activate_target(plan, Path("topology.yaml"), runner=UnavailableRunner())
        self.assertEqual((result["result"], result["commit_state"]),
                         ("ACTIVATION_STATE_INDETERMINATE", "COMMIT_OUTCOME_UNKNOWN"))

    def test_insert_transaction_contains_rollback_verification(self):
        from netbot.target_activation import _insert_command
        command = _insert_command("a" * 64, "b" * 64, "netbot-test")
        self.assertIn("mv \"$restore_tmp\" \"$HOME/.ssh/config\"", command)
        self.assertNotIn("mv \"$backup\" \"$HOME/.ssh/config\"", command)
        self.assertIn("restored_hash", command)
        for operation in ("restore_tmp=$(mktemp", "cp \"$backup\"", "chmod 600 \"$restore_tmp\"",
                          "mv \"$restore_tmp\""):
            self.assertIn("if ! " + operation, command)

    def test_insert_transaction_validates_original_before_rename(self):
        import hashlib
        from netbot.target_activation import _insert_command
        original = "Host *\n    User rafael\n"
        expected = INCLUDE + "\n" + original
        command = _insert_command(hashlib.sha256(expected.encode()).hexdigest(),
                                  hashlib.sha256(original.encode()).hexdigest(), None)
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            (home / ".ssh").mkdir()
            (home / ".ssh" / "config").write_text(original)
            result = subprocess.run(["/bin/sh", "-c", command], input=expected,
                                    text=True, capture_output=True, check=False,
                                    env={"HOME": str(home)}, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((home / ".ssh" / "config").read_text(), expected)

    def test_remote_verified_rollback_is_explicit(self):
        plan = TargetActivationPlan("netbot-test", "READY", "INSERT_INCLUDE",
                                    desired_content=INCLUDE + "\nHost *\n",
                                    transport_alias="netbot-test", transport_spec=SPEC,
                                    transport_source="verified-bootstrap-ordinary-ssh")
        runner = lambda command, **kwargs: subprocess.CompletedProcess(command, 48, "", "")
        with patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            result = activate_target(plan, Path("topology.yaml"), runner=runner)
        self.assertEqual(result["rollback_state"], "ACTIVATION_ROLLBACK_SUCCEEDED")

    def test_remote_concurrent_rollback_is_first_class(self):
        plan = TargetActivationPlan("netbot-test", "READY", "INSERT_INCLUDE",
                                    desired_content=INCLUDE + "\nHost *\n",
                                    transport_alias="netbot-test", transport_spec=SPEC,
                                    transport_source="verified-bootstrap-ordinary-ssh")
        runner = lambda command, **kwargs: subprocess.CompletedProcess(command, 50, "", "")
        with patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            result = activate_target(plan, Path("topology.yaml"), runner=runner)
        self.assertEqual(result["result"], "ACTIVATION_ROLLBACK_BLOCKED_BY_CONCURRENT_CHANGE")

    def test_remote_rollback_failure_is_first_class(self):
        plan = TargetActivationPlan("netbot-test", "READY", "INSERT_INCLUDE",
                                    desired_content=INCLUDE + "\nHost *\n",
                                    transport_alias="netbot-test", transport_spec=SPEC,
                                    transport_source="verified-bootstrap-ordinary-ssh")
        runner = lambda command, **kwargs: subprocess.CompletedProcess(command, 49, "", "")
        with patch("netbot.target_activation.resolve_observation_transport", return_value=SPEC):
            result = activate_target(plan, Path("topology.yaml"), runner=runner)
        self.assertEqual(result["result"], "ACTIVATION_ROLLBACK_FAILED")


if __name__ == "__main__":
    unittest.main()
