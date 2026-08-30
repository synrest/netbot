import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from netbot.cli import main
from netbot.discovery.remote_ssh import inspect_target, validate_alias


EFFECTIVE = """hostname 100.73.226.72
user zero
port 22
proxyjump none
proxycommand none
identityfile ~/.ssh/id_ed25519
"""


class Runner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append((command, kwargs))
        result = self.outputs.pop(0)
        if isinstance(result, BaseException):
            raise result
        return subprocess.CompletedProcess(command, result[0], result[1], result[2])


class RemoteSSHTests(unittest.TestCase):
    def config(self, root):
        path = root / "topology.yaml"
        path.write_text("""version: 1
authority: arasaka
hosts:
  kiroshi:
    class: satellite
    bindings:
      ssh:
        aliases:
          - kiroshi
  arasaka:
    class: core
    bindings:
      ssh:
        aliases:
          - arasaka
        user: zero
""")
        return path

    def test_explicit_alias_and_effective_values(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = Runner([
                (0, "hostname 100.100.57.74\nuser rafael\nport 22\n", ""),
                (0, EFFECTIVE, ""),
                (0, "EXACT 1\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n", ""),
            ])
            result = inspect_target(str(self.config(root)), "kiroshi", "arasaka", runner=runner)
            self.assertEqual(result.provenance, "EXPLICIT")
            self.assertEqual(result.status, "OK")
            self.assertEqual(result.effective["hostname"], "100.73.226.72")
            self.assertEqual(result.transport_user, "rafael")
            self.assertIn("/usr/bin/ssh -G arasaka", runner.commands[1][0][-1])
            self.assertNotIn("netbot", " ".join(runner.commands[1][0]))

    def test_wildcard_defaults_are_not_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner([(0, "hostname x\nuser u\nport 22\n", ""), (0, EFFECTIVE, ""),
                             (0, "EXACT 0\nWILDCARD 1\nINCLUDE 0\nINVALID 0\n", "")])
            result = inspect_target(str(self.config(Path(d))), "kiroshi", "arasaka", runner=runner)
            self.assertEqual(result.provenance, "ABSENT")
            self.assertEqual(result.status, "OK")

    def test_literal_alias_remains_explicit_with_wildcard_rules(self):
        with tempfile.TemporaryDirectory() as d:
            for provenance in [
                "EXACT 1\nWILDCARD 1\nINCLUDE 0\nINVALID 0\n",
                "EXACT 1\nWILDCARD 1\nINCLUDE 0\nINVALID 0\n",
            ]:
                runner = Runner([(0, "hostname x\nuser u\nport 22\n", ""),
                                 (0, EFFECTIVE, ""), (0, provenance, "")])
                result = inspect_target(str(self.config(Path(d))), "kiroshi", "arasaka", runner=runner)
                self.assertEqual(result.provenance, "EXPLICIT")
                self.assertEqual(result.status, "OK")

    def test_absent_and_generated_fragment_provenance_are_not_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner([(0, "hostname x\nuser u\nport 22\n", ""), (0, EFFECTIVE, ""),
                             (0, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n", "")])
            result = inspect_target(str(self.config(Path(d))), "kiroshi", "arasaka", runner=runner)
            self.assertEqual(result.provenance, "ABSENT")
            self.assertIn("50-netbot.conf", runner.commands[2][0][-1])

    def test_include_is_unknown_and_duplicate_is_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            for provenance, expected in [
                ("EXACT 1\nWILDCARD 0\nINCLUDE 1\nINVALID 0\n", "UNKNOWN"),
                ("EXACT 2\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n", "CONFLICT"),
            ]:
                runner = Runner([(0, "hostname x\nuser u\nport 22\n", ""), (0, EFFECTIVE, ""), (0, provenance, "")])
                result = inspect_target(str(self.config(Path(d))), "kiroshi", "arasaka", runner=runner)
                self.assertEqual(result.provenance, expected)

    def test_invalid_alias_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner([])
            result = inspect_target(str(self.config(Path(d))), "kiroshi", "bad;alias", runner=runner)
            self.assertEqual(result.status, "INVALID")
            self.assertEqual(runner.commands, [])
            self.assertFalse(validate_alias("bad alias"))

    def test_transport_failure_is_structured(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner([(0, "hostname x\nuser u\nport 22\n", ""),
                             subprocess.TimeoutExpired(["ssh"], 8)])
            result = inspect_target(str(self.config(Path(d))), "kiroshi", "arasaka", runner=runner)
            self.assertEqual(result.status, "UNAVAILABLE")
            self.assertEqual(result.reason, "transport timeout")

    def test_malformed_effective_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner([(0, "hostname x\nuser u\nport 22\n", ""), (0, "not ssh output", "")])
            result = inspect_target(str(self.config(Path(d))), "kiroshi", "arasaka", runner=runner)
            self.assertEqual(result.status, "INVALID")
            self.assertIn("missing hostname", result.reason)

    def test_no_binding_or_unvalidated_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.config(Path(d))
            runner = Runner([])
            self.assertEqual(inspect_target(str(path), "missing", "arasaka", runner=runner).status, "UNAVAILABLE")
            self.assertEqual(inspect_target(str(path), "kiroshi", "not-in-topology", runner=runner).status, "INVALID")

    def test_cli_serializes_typed_observation(self):
        # The CLI wiring is exercised with an invalid alias so no SSH process
        # is started; this still verifies the typed result serialization path.
        with tempfile.TemporaryDirectory() as d:
            output = StringIO()
            with redirect_stdout(output):
                main(["ssh", "inspect-target", "kiroshi", "bad;alias",
                      "--config", str(self.config(Path(d)))])
            self.assertIn('"status": "INVALID"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
