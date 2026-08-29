import subprocess
import unittest
from types import SimpleNamespace

from netbot.bootstrap import (
    Eligibility, bootstrap_eligibility, bootstrap_plan, managed_key_line,
    classify_managed_keys, ordinary_ssh_command, parse_host_key_observation,
    verify_host_key_continuity, teardown_capability,
    attempt_teardown, observe_teardown_capability,
    bootstrap_provider, bootstrap_authentication_outcome, validate_bootstrap_user,
    teardown_preconditions, classify_post_teardown, advance_bootstrap,
    bootstrap_command_set,
    execute_bootstrap,
    parse_host_key_material, temporary_known_hosts_line,
    adoption_decision,
)
from netbot.tailscale_prefs import TailscalePreferenceObserver, parse_preference
from netbot.state import State


class BootstrapTests(unittest.TestCase):
    def test_provider_requires_explicit_evidence(self):
        tagged = SimpleNamespace(raw={"Tags": ["tag:netbot-bootstrap"]})
        personal = SimpleNamespace(raw={"Tags": [], "User": "user@example.com"})
        unknown = SimpleNamespace(raw={"Tags": []})
        self.assertEqual(bootstrap_provider(tagged)["provider"], "infrastructure")
        self.assertEqual(bootstrap_provider(personal)["provider"], "personal")
        self.assertEqual(bootstrap_provider(unknown)["provider"], "unknown")

    def test_explicit_user_is_required(self):
        self.assertEqual(validate_bootstrap_user(None)["state"], "unknown")
        self.assertEqual(validate_bootstrap_user("zero")["state"], "known")
        self.assertEqual(validate_bootstrap_user("bad user")["state"], "invalid")

    def test_authentication_outcomes_remain_distinct(self):
        self.assertEqual(bootstrap_authentication_outcome(0)["state"], "authenticated")
        self.assertEqual(bootstrap_authentication_outcome(1, "browser reauthentication required")["state"], "check-human-authentication-required")
        self.assertEqual(bootstrap_authentication_outcome(1, "tailnet policy does not permit")["state"], "policy-denied")

    def test_guarded_transition_requires_all_evidence(self):
        plan = bootstrap_plan("x", "x", "zero", Eligibility("eligible", "tag", "tag:netbot-bootstrap"), {"state": "available"})
        missing = teardown_preconditions(plan, authenticated=True, key_installed=True, openssh_prepared=True, host_key_captured=True, tailscale_ssh_enabled=True, capability={"state": "blocked"})
        self.assertEqual(missing["state"], "authorization_required")
        ready = teardown_preconditions(plan, authenticated=True, key_installed=True, openssh_prepared=True, host_key_captured=True, tailscale_ssh_enabled=True, capability={"state": "available"})
        self.assertEqual(ready["state"], "ready")

    def test_post_teardown_cannot_be_managed_without_fresh_ssh(self):
        self.assertFalse(classify_post_teardown(observed_disabled=True, ordinary_ssh_verified=False, host_key_state="match")["managed"])
        self.assertTrue(classify_post_teardown(observed_disabled=True, ordinary_ssh_verified=True, host_key_state="match")["managed"])
        self.assertFalse(classify_post_teardown(observed_disabled=True, ordinary_ssh_verified=True, host_key_state="HOST_KEY_MISMATCH")["managed"])

    def test_state_advancement_requires_verified_evidence(self):
        self.assertEqual(advance_bootstrap("discovered", {"candidate": False})["state"], "discovered")
        self.assertEqual(advance_bootstrap("discovered", {"candidate": True})["state"], "bootstrap_candidate")
        self.assertEqual(advance_bootstrap("bootstrap_teardown_ready", {"tailscale_ssh_disabled": True})["state"], "bootstrap_disabled")

    def test_command_set_contains_no_agent_activation(self):
        commands = bootstrap_command_set("host", "zero", "ssh-ed25519 AAAA", "arasaka")
        rendered = repr(commands)
        self.assertNotIn("agent-temporary on", rendered)
        self.assertIn("tailscale", rendered)

    def test_executor_blocks_before_teardown_when_authority_is_missing(self):
        plan = bootstrap_plan("x", "x", "zero", Eligibility("eligible", "tag", "tag:netbot-bootstrap"), {"state": "blocked"})
        calls = []
        def op(name, **values):
            def run():
                calls.append(name)
                return {"success": True, **values}
            return run
        result = execute_bootstrap(plan, {
            "authenticate": op("authenticate", authenticated=True),
            "install_key": op("install_key", key_installed=True),
            "precheck": op("precheck", openssh_prepared=True),
            "capture_host_key": op("capture_host_key", host_key_captured=True),
            "teardown_capability": lambda: {"state": "blocked"},
            "teardown": op("teardown", success=True),
        })
        self.assertEqual(result["state"], "authorization_required")
        self.assertNotIn("teardown", calls)

    def test_executor_reaches_managed_only_after_all_verified_results(self):
        plan = bootstrap_plan("x", "x", "zero", Eligibility("eligible", "tag", "tag:netbot-bootstrap"), {"state": "available"})
        def ok(**values): return lambda: {"success": True, **values}
        result = execute_bootstrap(plan, {
            "authenticate": ok(authenticated=True),
            "install_key": ok(key_installed=True),
            "precheck": ok(openssh_prepared=True),
            "capture_host_key": ok(host_key_captured=True),
            "teardown_capability": lambda: {"state": "available"},
            "teardown": ok(),
            "observe_disabled": lambda: {"disabled": True},
            "ordinary_ssh": ok(),
            "host_key_continuity": lambda: {"state": "match"},
        })
        self.assertEqual(result["state"], "managed")
        self.assertTrue(result["managed"])

    def test_existing_openSSH_is_adopted_without_bootstrap(self):
        result = adoption_decision(identity="kiroshi", identity_status="mapped",
            ordinary_openssh={"result": "reachable-authenticated"},
            tailscale_ssh={"result": "unknown", "eligible": True}, intended_user="rafael")
        self.assertEqual(result["state"], "managed_existing_openssh")
        self.assertFalse(result["bootstrap_required"])

    def test_existing_access_does_not_require_netbot_key_authorship(self):
        result = adoption_decision(identity="mikoshi", identity_status="mapped",
            ordinary_openssh={"result": "authenticated"}, tailscale_ssh=None, intended_user="zero")
        self.assertFalse(result["netbot_key_required"])

    def test_adoption_blocks_identity_and_host_key_conflicts(self):
        ambiguous = adoption_decision(identity="mikoshi", identity_status="ambiguous",
            ordinary_openssh={"result": "reachable-authenticated"}, tailscale_ssh=None, intended_user="zero")
        conflict = adoption_decision(identity="mikoshi", identity_status="mapped",
            ordinary_openssh={"result": "reachable-authenticated"}, tailscale_ssh=None, intended_user="zero", host_key_state="HOST_KEY_MISMATCH")
        self.assertEqual(ambiguous["state"], "ambiguous")
        self.assertEqual(conflict["state"], "ambiguous")

    def test_eligible_tailscale_bootstrap_is_fallback(self):
        result = adoption_decision(identity="new-node", identity_status="mapped",
            ordinary_openssh={"result": "timeout/unreachable"},
            tailscale_ssh={"result": "authenticated", "eligible": True}, intended_user="zero")
        self.assertEqual(result["state"], "bootstrap_candidate")

    def test_no_authenticated_path_is_discovered_blocked(self):
        result = adoption_decision(identity="oracle", identity_status="mapped",
            ordinary_openssh={"result": "timeout/unreachable"},
            tailscale_ssh={"result": "policy-denied", "eligible": True}, intended_user="rafael")
        self.assertEqual(result["state"], "discovered_blocked")
    def test_explicit_tag_is_required(self):
        tagged = SimpleNamespace(raw={"Tags": ["tag:netbot-bootstrap"]})
        untagged = SimpleNamespace(raw={"Tags": []})
        unavailable = SimpleNamespace(raw={})
        self.assertEqual(bootstrap_eligibility(tagged).state, "eligible")
        self.assertEqual(bootstrap_eligibility(untagged).state, "ineligible")
        self.assertEqual(bootstrap_eligibility(unavailable).state, "unknown")

    def test_managed_key_is_normalized_without_private_material(self):
        line = managed_key_line("ssh-ed25519 AAAA original-comment", "controller-1")
        self.assertEqual(line, "ssh-ed25519 AAAA netbot:controller:controller-1")
        with self.assertRaises(ValueError): managed_key_line("not-a-key", "controller-1")

    def test_host_keys_are_fingerprint_metadata(self):
        output = "NETBOT_HOST_KEY_FILE=/etc/ssh/ssh_host_ed25519_key.pub\n256 SHA256:abc host (ED25519)\n"
        self.assertEqual(parse_host_key_observation(output)[0]["fingerprint"], "SHA256:abc")

    def test_host_key_material_is_public_and_can_seed_temporary_verification(self):
        output = "NETBOT_HOST_KEY_MATERIAL=ssh-ed25519 AAAAonly-public-data\n"
        key = parse_host_key_material(output)[0]
        self.assertEqual(temporary_known_hosts_line("100.0.0.1", key), "100.0.0.1 ssh-ed25519 AAAAonly-public-data")

    def test_host_key_continuity_fails_closed(self):
        key = [{"fingerprint": "SHA256:abc"}]
        self.assertEqual(verify_host_key_continuity(key, key)["state"], "match")
        self.assertEqual(verify_host_key_continuity(key, [{"fingerprint": "SHA256:def"}])["state"], "HOST_KEY_MISMATCH")
        self.assertEqual(verify_host_key_continuity(key, [])["state"], "host-key-unavailable")

    def test_conflicting_managed_key_is_not_replaced(self):
        expected = "ssh-ed25519 AAAA netbot:controller:arasaka"
        result = classify_managed_keys(["ssh-ed25519 BBBB netbot:controller:arasaka"], expected, "arasaka")
        self.assertEqual(result["state"], "conflict")

    def test_strict_post_transition_command_never_disables_checks(self):
        command = ordinary_ssh_command("host", "zero", "/key", "/known_hosts.tmp")
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertNotIn("/dev/null", " ".join(command))

    def test_teardown_requires_explicit_effective_sudo_capability(self):
        blocked = teardown_capability("sudo: a password is required")
        listed_only = teardown_capability("(ALL) NOPASSWD: /usr/bin/tailscale set --ssh=false")
        allowed = teardown_capability("(ALL) NOPASSWD: /usr/bin/tailscale set --ssh=false", 0)
        self.assertEqual(blocked["state"], "blocked")
        self.assertEqual(listed_only["state"], "unknown")
        self.assertEqual(allowed["state"], "available")
        self.assertEqual(blocked["authority"], "maintain")

    def test_teardown_observer_queries_exact_operation(self):
        captured = []

        class Completed:
            returncode = 0
            stdout = "/usr/bin/tailscale set --ssh=false\n"
            stderr = ""

        def runner(command, **kwargs):
            captured.append(command)
            return Completed()

        result = observe_teardown_capability("orthanc-db", "zero", runner=runner)
        self.assertEqual(result["state"], "available")
        command_text = " ".join(captured[0])
        self.assertIn("sudo", command_text)
        self.assertIn("-l", command_text)
        self.assertIn("/usr/bin/tailscale", command_text)
        self.assertIn("--ssh=false", command_text)

    def test_alpine_sudo_listing_does_not_prove_execution(self):
        self.assertEqual(teardown_capability("(ALL) NOPASSWD: ALL", 1)["state"], "blocked")
        self.assertEqual(teardown_capability("(ALL) NOPASSWD: ALL /usr/bin/tailscale set --ssh=false", 0)["state"], "available")

    def test_tailscale_preference_get_and_debug_fallback(self):
        self.assertEqual(parse_preference("tailscale get --json", 0, '{"ssh":true}').ssh, True)
        self.assertEqual(parse_preference("tailscale get --json", 0, '{"ssh":false}').ssh, False)
        calls = []
        def run(command):
            calls.append(command)
            return {"returncode": 1, "stdout": "", "stderr": "unknown command get"} if len(calls) == 1 else {"returncode": 0, "stdout": '{"RunSSH":false}', "stderr": ""}
        result = TailscalePreferenceObserver(run).observe()
        self.assertEqual(result.state, "observed")
        self.assertIs(result.ssh, False)
        self.assertEqual(calls, ["tailscale get --json", "tailscale debug prefs"])

    def test_tailscale_preference_failure_is_not_false(self):
        result = TailscalePreferenceObserver(lambda command: {"returncode": 1, "stdout": "", "stderr": "failed"}).observe()
        self.assertIn(result.state, {"unavailable", "unsupported"})
        self.assertIsNone(result.ssh)

    def test_bootstrap_history_migrates_and_keeps_node_id_nullable(self):
        import tempfile, sqlite3
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.db"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE bootstrap_events(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, identity TEXT, state TEXT NOT NULL, details_json TEXT NOT NULL)")
            db.commit(); db.close()
            state = State(path)
            state.bootstrap_event("now", "netbot-test", "bootstrap_candidate", {"hostname":"netbot-test"}, "147")
            self.assertEqual(state.db.execute("SELECT node_id FROM bootstrap_events").fetchone()[0], "147")
            state.close()

    def test_new_state_creates_bootstrap_tables_with_nullable_node_id(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            state = State(Path(d) / "new.db")
            tables = {row[0]: row[1] for row in state.db.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")}
            self.assertIn("node_id", tables["bootstrap_events"])
            self.assertIn("node_id", tables["bootstrap_observations"])
            state.close()

    def test_managed_access_does_not_adopt_unbound_topology(self):
        result = adoption_decision(identity=None, identity_status="unbound", ordinary_openssh={"result":"authenticated"}, tailscale_ssh=None, intended_user="zero")
        self.assertEqual(result["state"], "discovered_blocked")

    def test_teardown_failure_is_blocked_not_success(self):
        class Completed:
            returncode = 1
            stdout = ""
            stderr = "sudo: a password is required"
        result = attempt_teardown("host", runner=lambda *args, **kwargs: Completed())
        self.assertEqual(result["state"], "blocked")

    def test_plan_blocks_unknown_tag_and_maintain(self):
        plan = bootstrap_plan("orthanc-postgres", "orthanc-db", "zero", Eligibility("unknown", "peer", "tags unavailable"), {"state": "blocked"})
        self.assertEqual(plan["stages"][1]["status"], "blocked")
        self.assertEqual(plan["stages"][5]["status"], "blocked")
        self.assertFalse(plan["maintenance_authorized"])

    def test_plan_allows_candidate_only_from_verified_tag(self):
        plan = bootstrap_plan("x", "x", "zero", Eligibility("eligible", "peer tag", "tag:netbot-bootstrap"), {"state": "available"})
        self.assertEqual(plan["stages"][1]["status"], "ready")
        self.assertEqual(plan["stages"][5]["status"], "ready")
        self.assertTrue(plan["maintenance_authorized"])

    def test_state_names_include_teardown_blocked(self):
        from netbot.bootstrap import BOOTSTRAP_STATES
        self.assertIn("bootstrap_teardown_blocked", BOOTSTRAP_STATES)
        self.assertIn("managed", BOOTSTRAP_STATES)

    def test_bootstrap_blocked_state_persists_idempotently(self):
        import sqlite3
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from netbot.state import State
        with TemporaryDirectory() as directory:
            state = State(Path(directory) / "state.sqlite3")
            state.bootstrap_event("now", "orthanc-db", "bootstrap_teardown_blocked", {"reason": "sudo"})
            state.bootstrap_event("later", "orthanc-db", "bootstrap_teardown_blocked", {"reason": "sudo"})
            state.close()
            db = sqlite3.connect(Path(directory) / "state.sqlite3")
            self.assertEqual(db.execute("select count(*) from bootstrap_events").fetchone()[0], 1)
            db.close()


if __name__ == "__main__": unittest.main()
