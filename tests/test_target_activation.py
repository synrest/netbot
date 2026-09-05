import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netbot.target_activation import (CREATE_COMMAND, INCLUDE, build_activation_plan,
                                      activate_target)


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


if __name__ == "__main__":
    unittest.main()
