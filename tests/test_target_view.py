import subprocess
import tempfile
import unittest
from pathlib import Path

from netbot.target_view import build_ssh_view


EFFECTIVE_ARASAKA = "hostname 100.73.226.72\nuser zero\nport 22\nproxyjump none\nproxycommand none\n"
EFFECTIVE_ORION = "hostname 100.100.57.80\nuser lourdes\nport 22\nproxyjump none\nproxycommand none\n"


class Runner:
    def __init__(self, effective, provenance):
        self.effective = effective
        self.provenance = provenance
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[0] == "ssh" and len(command) == 3 and command[1] == "-G":
            return subprocess.CompletedProcess(command, 0, "hostname 100.100.57.74\nuser rafael\nport 22\n", "")
        if "/usr/bin/ssh -G" in command[-1]:
            return subprocess.CompletedProcess(command, 0, self.effective, "")
        return subprocess.CompletedProcess(command, 0, self.provenance, "")


class TargetViewTests(unittest.TestCase):
    def config(self, root, extra="", policy="peer_policy:\n  default: topology\n"):
        path = root / "topology.yaml"
        path.write_text("version: 1\n" + policy + "hosts:\n" + """
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
  orion:
    bindings:
      tailscale:
        node_id: orion-id
        name: orion
      ssh:
        aliases: [orion]
        user: lourdes
""" + extra)
        return path

    def observed(self, *items):
        return [{"identity": identity, "status": "present", "name": name,
                 "dns_name": name + ".tail", "addresses": [address]}
                for identity, name, address in items]

    def test_view_enumerates_topology_bound_identities(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", self.observed(
                ("arasaka", "arasaka", "100.73.226.72"),
                ("kiroshi", "kiroshi", "100.100.57.74"),
                ("orion", "orion", "100.100.57.80")), runner=runner)
            self.assertEqual([x.identity for x in view.relationships], ["arasaka", "orion"])

    def test_target_self_is_not_a_relationship_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", self.observed(
                ("kiroshi", "kiroshi", "100.100.57.74")), runner=runner)
            self.assertNotIn("kiroshi", [item.identity for item in view.relationships])

    def test_explicit_manual_alias_is_valid_manual(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 1\nWILDCARD 1\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", self.observed(
                ("arasaka", "arasaka", "100.73.226.72")), runner=runner)
            self.assertEqual(view.relationships[0].state, "VALID_MANUAL")

    def test_explicit_unproven_destination_is_unknown_not_valid_manual(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner("hostname mystery.example\nuser zero\nport 22\n", "EXACT 1\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", self.observed(
                ("arasaka", "arasaka", "100.73.226.72")), runner=runner)
            self.assertEqual(view.relationships[0].state, "UNKNOWN")

    def test_absent_alias_is_missing_and_portable_route_proposed(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(EFFECTIVE_ORION, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", self.observed(
                ("orion", "orion", "100.100.57.80")), runner=runner)
            item = next(x for x in view.relationships if x.identity == "orion")
            self.assertEqual(item.state, "MISSING")
            self.assertEqual(item.action, "would-generate")
            self.assertEqual(item.candidate_endpoint, "orion:22")
            self.assertNotIn("ProxyJump", " ".join(" ".join(command) for command in runner.commands))

    def test_managed_fragment_is_valid_managed_not_missing(self):
        with tempfile.TemporaryDirectory() as d:
            class ManagedRunner(Runner):
                def __call__(self, command, **kwargs):
                    self.commands.append(command)
                    if "/usr/bin/ssh -G" in command[-1]:
                        effective = EFFECTIVE_ORION.replace("100.100.57.80", "orion").replace("lourdes", "lourdes") if "-G orion" in command[-1] else EFFECTIVE_ARASAKA.replace("100.73.226.72", "arasaka")
                        return subprocess.CompletedProcess(command, 0, effective, "")
                    if "NETBOT_MANAGED_PROVENANCE=1" in command[-1]:
                        return subprocess.CompletedProcess(command, 0,
                            "EXACT 1\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n", "")
                    return subprocess.CompletedProcess(command, 0,
                        "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n", "")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", [], runner=ManagedRunner("", ""))
            self.assertTrue(all(item.state == "VALID_MANAGED" for item in view.relationships))

    def test_loopback_route_is_not_portable_to_target(self):
        with tempfile.TemporaryDirectory() as d:
            extra = """  mikoshi:
    bindings:
      tailscale:
        node_id: mikoshi-id
      ssh:
        aliases: [mikoshi]
        user: zero
        hostname: 127.0.0.1
        port: 2222
        controller: arasaka
"""
            runner = Runner("hostname 127.0.0.1\nuser zero\nport 2222\n", "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d), extra), "kiroshi", self.observed(
                ("mikoshi", "mikoshi", "100.100.57.90")), runner=runner)
            item = next(x for x in view.relationships if x.identity == "mikoshi")
            self.assertEqual(item.state, "NOT_ROUTABLE_FROM_TARGET")
            self.assertEqual(item.action, "none")

    def test_unknown_provenance_and_unavailable_target_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 1\nWILDCARD 0\nINCLUDE 1\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d)), "kiroshi", self.observed(
                ("arasaka", "arasaka", "100.73.226.72")), runner=runner)
            self.assertTrue(all(item.state == "UNKNOWN" for item in view.relationships))

            # A target without a topology binding is represented without any
            # transport attempt and fails closed.
            missing = build_ssh_view(self.config(Path(d)), "unknown", [], runner=runner)
            self.assertEqual(missing.status, "UNKNOWN")

    def test_duplicate_alias_is_conflict_without_remote_probe(self):
        with tempfile.TemporaryDirectory() as d:
            extra = """  duplicate:
    bindings:
      tailscale:
        node_id: duplicate-id
      ssh:
        aliases: [arasaka]
"""
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 1\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d), extra), "kiroshi", [], runner=runner)
            self.assertEqual([x.state for x in view.relationships[:2]], ["CONFLICT", "CONFLICT"])
            self.assertFalse(any("/usr/bin/ssh -G arasaka" in command[-1] for command in runner.commands))

    def test_policy_is_authoritative_candidate_source(self):
        with tempfile.TemporaryDirectory() as d:
            extra = """  hidden:
    bindings:
      tailscale:
        node_id: hidden-id
      ssh:
        aliases: [hidden]
"""
            policy = """peer_policy:
  default: topology
  overrides:
    kiroshi:
      exclude:
        - hidden
"""
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d), extra, policy), "kiroshi", [], runner=runner)
            self.assertNotIn("hidden", [item.identity for item in view.relationships])

    def test_policy_absence_propagates_in_target_view(self):
        with tempfile.TemporaryDirectory() as d:
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d), policy=""), "kiroshi", [], runner=runner)
            self.assertEqual(view.status, "POLICY_ABSENT")
            self.assertEqual(view.relationships, [])

    def test_unknown_class_bound_destination_is_included_by_topology_default(self):
        with tempfile.TemporaryDirectory() as d:
            extra = """  oracle:
    class: unknown
    bindings:
      tailscale:
        node_id: oracle-id
      ssh:
        aliases: [oracle]
"""
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d), extra), "kiroshi", [], runner=runner)
            self.assertIn("oracle", [item.identity for item in view.relationships])

    def test_unbound_source_policy_state_propagates(self):
        with tempfile.TemporaryDirectory() as d:
            extra = """  unbound:
    bindings:
      ssh:
        aliases: [unbound]
"""
            runner = Runner(EFFECTIVE_ARASAKA, "EXACT 0\nWILDCARD 0\nINCLUDE 0\nINVALID 0\n")
            view = build_ssh_view(self.config(Path(d), extra), "unbound", [], runner=runner)
            self.assertEqual(view.status, "SOURCE_UNBOUND")
            self.assertEqual(view.relationships, [])


if __name__ == "__main__":
    unittest.main()
