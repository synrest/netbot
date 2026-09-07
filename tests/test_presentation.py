import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from netbot.cli import main
from netbot.presentation import dashboard, topology, render_dashboard, render_topology
from netbot.state import State
from netbot.discovery.acceptance import accept_node


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.config = self.root / "topology.yaml"
        self.config.write_text(
            "version: 1\nauthority: arasaka\nhosts:\n"
            "  arasaka:\n    class: core\n    bindings:\n      tailscale:\n        node_id: self\n"
            "  orion:\n    class: satellite\n    parent: arasaka\n    bindings:\n"
            "      tailscale:\n        node_id: orion-id\n      ssh:\n"
            "        aliases:\n          - orion\n        user: lourdes\n"
        )
        self.db = self.root / "state.sqlite3"

    def add_discovery(self):
        state = State(self.db)
        state.record_discovery_cycle(
            "run-1", "controller", "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00",
            "OK", "OK", "COMPLETE", None,
            {"nodes": [{"observation_identity": "tailscale:new", "observed_from": "controller",
                         "aliases": [], "provider_peers": [{"provider": "tailscale",
                         "provider_node_id": "new", "advertised_name": "new-host",
                         "addresses": ["100.64.0.3"], "online": True,
                         "observed_at": "2026-01-01T00:00:00+00:00"}]}], "relationships": [], "sources": []},
            [{"provider": "tailscale", "provider_node_id": "new", "advertised_name": "new-host",
              "addresses": ["100.64.0.3"], "online": True, "metadata": {},
              "observed_at": "2026-01-01T00:00:00+00:00"}])
        state.close()

    def add_acceptance_discovery(self):
        state = State(self.db)
        state.record_discovery_cycle(
            "run-accept", "controller", "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00",
            "OK", "OK", "COMPLETE", None, {"nodes": [], "relationships": [], "sources": []},
            [{"provider": "tailscale", "provider_node_id": "new", "advertised_name": "new-host",
              "addresses": ["100.64.0.3"], "online": True, "metadata": {},
              "observed_at": "2026-01-01T00:00:00+00:00"}])
        state.close()

    def invoke(self, *args):
        output = StringIO()
        with redirect_stdout(output):
            main([*args, "--config", str(self.config), "--db", str(self.db)])
        return output.getvalue()

    def invoke_help(self, *args):
        output = StringIO()
        with redirect_stdout(output):
            main(list(args))
        return output.getvalue()

    def test_dashboard_and_status_are_read_only(self):
        with patch("netbot.cli.scheduler_status", return_value={"installed": False, "enabled": False, "configured_interval": "30m"}):
            dashboard_output = self.invoke()
            status_output = self.invoke("status")
        self.assertIn("NETBOT", dashboard_output)
        self.assertIn("NETBOT STATUS", status_output)
        self.assertFalse(self.db.exists())

    def test_dashboard_json_is_structured(self):
        with patch("netbot.presentation.scheduler_status", return_value={"installed": False, "enabled": False, "configured_interval": "30m"}):
            payload = json.loads(self.invoke("--json"))
        self.assertEqual(payload["command"], "dashboard")
        self.assertEqual(payload["schema"], "netbot.cli/v1")

    def test_dashboard_box_has_stable_width(self):
        for controller in ("a", "arasaka", "a-controller-with-a-long-name"):
            output = render_dashboard({"controller": controller, "topology": "OK", "nodes": 0,
                "online": 0, "offline": 0, "unknown": 0, "observed": 0, "attention": 0,
                "last_maintain": "never", "scheduler": {"enabled": False}})
            lines = output.splitlines()[:3]
            self.assertEqual(len({len(line) for line in lines}), 1)
            self.assertEqual(len(lines[0]), len(lines[1]))
            self.assertEqual(len(lines[1]), len(lines[2]))

    def test_topology_separates_accepted_and_observed(self):
        self.add_discovery()
        view = topology(self.config, self.db)
        self.assertEqual([item["identity"] for item in view["accepted"]], ["arasaka", "orion"])
        self.assertEqual(view["observed"][0]["advertised_name"], "new-host")
        rendered = self.invoke("topology")
        self.assertIn("◇ ● NEW-HOST", rendered)

    def test_topology_does_not_render_ssh_evidence_as_hierarchy(self):
        state = State(self.db)
        state.record_discovery_cycle(
            "run-1", "controller", "t1", "t2", "OK", "OK", "COMPLETE", None,
            {"nodes": [], "relationships": [{"source": "orion", "destination": "arasaka",
             "alias": "arasaka", "effective": {}, "auth_state": "PUBLIC_KEY_PROVEN",
             "provenance": "SSH_CONFIG_HUMAN", "observed_from": "orion"}], "sources": []}, [])
        state.close()
        self.assertNotIn("orion -> arasaka", self.invoke("topology"))

    def test_topology_flat_peer_rows_have_no_false_vertical_relationships(self):
        rendered = self.invoke("topology")
        self.assertNotIn("\n│\n", rendered)
        self.assertNotIn("┼", rendered)

    def test_topology_filters_retired_and_superseded_hosts(self):
        self.config.write_text(self.config.read_text() +
            "  retired:\n    lifecycle: retired\n"
            "  old-node:\n    superseded_by: orion\n")
        view = topology(self.config, self.db)
        identities = [item["identity"] for item in view["accepted"]]
        self.assertEqual(identities, ["arasaka", "orion"])
        rendered = self.invoke("topology")
        self.assertNotIn("RETIRED", rendered)
        self.assertNotIn("OLD-NODE", rendered)

    def test_topology_uses_unknown_when_provider_is_unavailable(self):
        data = dashboard(self.config, self.db)
        self.assertEqual(data["unknown"], 2)
        self.assertEqual(data["online"], 0)
        self.assertEqual(data["offline"], 0)
        self.assertIn("Unknown", self.invoke())

    def test_topology_uses_exact_provider_row_for_online_state(self):
        state = State(self.db)
        state.record_discovery_cycle(
            "run-provider", "controller", "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00",
            "OK", "OK", "COMPLETE", None,
            {"nodes": [{"observation_identity": "tailscale:orion-id", "observed_from": "controller",
                         "aliases": [], "provider_peers": []}], "relationships": [], "sources": []},
            [{"provider": "tailscale", "provider_node_id": "orion-id", "advertised_name": "different-name",
              "addresses": ["100.64.0.9"], "online": True, "metadata": {},
              "observed_at": "2026-01-01T00:00:00+00:00"}])
        state.close()
        view = topology(self.config, self.db)
        self.assertEqual(next(node for node in view["accepted"] if node["identity"] == "orion")["state"], "online")

    def test_topology_does_not_use_hostname_or_ip_as_provider_identity_fallback(self):
        state = State(self.db)
        state.record_discovery_cycle(
            "run-provider", "controller", "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00",
            "OK", "OK", "COMPLETE", None,
            {"nodes": [], "relationships": [], "sources": []},
            [{"provider": "tailscale", "provider_node_id": "other-id", "advertised_name": "orion",
              "addresses": ["100.64.0.9"], "online": True, "metadata": {},
              "observed_at": "2026-01-01T00:00:00+00:00"}])
        state.close()
        self.assertEqual(next(node for node in topology(self.config, self.db)["accepted"] if node["identity"] == "orion")["state"], "unknown")

    def test_controller_display_uses_exact_provider_self_binding(self):
        self.config.write_text("version: 1\nhosts:\n  arasaka:\n    class: core\n    bindings:\n      tailscale:\n        node_id: self-node\n")
        state = State(self.db)
        controller_id = state.controller_identity()
        state.record_discovery_cycle(
            "run-self", controller_id, "2026-01-01T00:00:00+00:00", "2026-01-01T00:01:00+00:00",
            "OK", "OK", "COMPLETE", None,
            {"nodes": [], "relationships": [], "sources": []},
            [{"provider": "tailscale", "provider_node_id": "self-node", "advertised_name": "arasaka",
              "addresses": [], "online": True, "metadata": {"_netbot_self": True},
              "observed_at": "2026-01-01T00:00:00+00:00"}])
        state.close()
        self.assertEqual(dashboard(self.config, self.db)["controller"], "arasaka")
        self.assertIn("Controller     arasaka", self.invoke("status"))

    def test_topology_summary_separates_attention_from_conflicts(self):
        state = State(self.db)
        state.record_event("TARGET_UNAVAILABLE", "ATTENTION", "orion", "target:orion", "Target unavailable")
        state.commit_events(); state.close()
        rendered = render_topology(topology(self.config, self.db))
        self.assertIn("1 attention · 0 conflicts", rendered)

    def test_command_deck_wide_mode_is_flat_and_semantic(self):
        data = {"authority": "arasaka", "accepted": [
            {"identity": "arasaka", "state": "online"},
            {"identity": "orion", "state": "online"},
            {"identity": "kiroshi", "state": "offline"},
            {"identity": "mikoshi", "state": "offline"},
            {"identity": "orthanc-postgres", "state": "unknown"}],
            "observed": [{"advertised_name": "orthanc-db", "online": False}],
            "attention": [{"event_id": 1}], "conflicts": []}
        output = render_topology(data, 80)
        self.assertIn("CONTROLLER · ARASAKA", output)
        self.assertIn("ACCEPTED CONTACTS", output)
        self.assertIn("OBSERVED", output)
        self.assertIn("◇ ○ ORTHANC-DB", output)
        self.assertNotIn("→", output)
        self.assertNotIn("┼", "\n".join(line for line in output.splitlines() if "ORION" in line))
        self.assertIn("1 attention · 0 conflicts", output)
        lines = output.splitlines()
        self.assertEqual(len({len(lines[index]) for index in (0, 1, 2)}), 1)
        self.assertTrue(all(len(line) <= 80 for line in lines))
        self.assertEqual(len(lines[0]), len(lines[2]))

    def test_topology_width_modes_are_deterministic(self):
        data = {"authority": "arasaka", "accepted": [
            {"identity": "arasaka", "state": "online"},
            {"identity": "a-very-long-canonical-identity", "state": "unknown"}],
            "observed": [{"advertised_name": "contact", "online": None}],
            "attention": [], "conflicts": []}
        compact = render_topology(data, 70)
        linear = render_topology(data, 50)
        self.assertNotIn("╔", compact)
        self.assertNotIn("╔", linear)
        self.assertIn("ACCEPTED", compact)
        self.assertIn("Controller: ● ARASAKA", linear)
        self.assertIn("· A-VERY-LONG-CANONICAL-IDENTITY", linear)
        self.assertIn("◇ · CONTACT", linear)

    def test_command_help_is_concise_for_core_commands(self):
        for command, expected in (("accept", "Accept a discovered topology candidate."),
                                  ("reject", "Reject a discovered topology candidate."),
                                  ("merge", "Merge a duplicate topology identity")):
            output = self.invoke_help(command, "--help")
            self.assertIn(expected, output)
            self.assertNotIn("[{version,doctor,status", output)
        top = self.invoke_help("--help")
        self.assertIn("Core commands:", top)
        self.assertIn("accept <node>", top)
        self.assertIn("reject <node>", top)
        self.assertIn("merge ...", top)

    def test_reconciliation_timestamp_is_labeled_accurately(self):
        state = State(self.db)
        run_id = state.begin("2026-01-01T00:00:00+00:00", "status")
        state.finish(run_id, "2026-01-01T00:01:00+00:00", True, {}, "available", None)
        state.close()
        output = self.invoke("status")
        self.assertIn("Last reconcile", output)
        self.assertNotIn("Last maintain", output)

    def test_reconciliation_json_retains_legacy_timestamp_alias(self):
        state = State(self.db)
        run_id = state.begin("2026-01-01T00:00:00+00:00", "status")
        state.finish(run_id, "2026-01-01T00:01:00+00:00", True, {}, "available", None)
        state.close()
        payload = json.loads(self.invoke("status", "--json"))
        self.assertEqual(payload["data"]["last_reconcile"], payload["data"]["last_maintain"])

    def test_sparse_inspect_omits_empty_sections_and_raw_ids(self):
        output = self.invoke("inspect", "orion")
        self.assertNotIn("Network\n", output)
        self.assertNotIn("Evidence\n", output)
        self.assertNotIn("0227e3d8810040e8a784fc52493506b9", output)

    def test_accept_node_resolves_current_candidate_without_reconcile(self):
        self.add_acceptance_discovery()
        with patch("netbot.cli.reconcile") as reconcile:
            output = self.invoke("accept", "new-host")
        reconcile.assert_not_called()
        self.assertIn("Accepted new-host", output)
        self.assertNotIn("proposal_id", output)
        self.assertIn("new-host", self.config.read_text())

    def test_accept_node_no_match_does_not_mutate_topology(self):
        before = self.config.read_bytes()
        output = self.invoke("accept", "missing")
        self.assertIn("Cannot accept missing", output)
        self.assertEqual(self.config.read_bytes(), before)

    def test_accept_node_json_retains_resolution_identity(self):
        self.add_acceptance_discovery()
        payload = json.loads(self.invoke("accept", "new-host", "--dry-run", "--json"))
        self.assertEqual(payload["result"], "WOULD_ACCEPT")
        self.assertEqual(payload["requested_node"], "new-host")
        self.assertTrue(payload["resolved_proposal_id"])
        self.assertEqual(payload["canonical_identity"], "new-host")
        self.assertNotIn("new-host:\n", self.config.read_text())

    def test_accept_node_refuses_already_accepted_identity(self):
        result = accept_node(self.config, self.db, "orion")
        self.assertEqual(result["result"], "ALREADY_ACCEPTED")

    def test_accept_node_refuses_ambiguous_candidates(self):
        proposals = [
            {"proposal_type": "NEW_IDENTITY_CANDIDATE", "proposal_id": "p1", "proposed_alias": "same", "target_entity": "a"},
            {"proposal_type": "NEW_IDENTITY_CANDIDATE", "proposal_id": "p2", "proposed_alias": "same", "target_entity": "b"},
        ]
        with patch("netbot.discovery.acceptance.generate_proposals", return_value=proposals):
            result = accept_node(self.config, self.db, "same")
        self.assertEqual(result["result"], "AMBIGUOUS")

    def test_accept_node_preserves_existing_stale_refusal(self):
        self.add_acceptance_discovery()
        with patch("netbot.discovery.acceptance.accept_proposal",
                   return_value={"result": "STALE_PROPOSAL", "topology_changed": False,
                                 "reconciliation_performed": False}):
            result = accept_node(self.config, self.db, "new-host")
        self.assertEqual(result["result"], "STALE_PROPOSAL")

    def test_inspect_json_and_human_do_not_probe(self):
        self.add_discovery()
        with patch("netbot.cli.reconcile") as legacy:
            payload = json.loads(self.invoke("inspect", "new-host", "--json"))
        legacy.assert_not_called()
        self.assertEqual(payload["state"], "OBSERVED")
        self.assertIn("NEW-HOST", self.invoke("inspect", "new-host"))

    def test_probe_remains_explicit(self):
        result = {"desired": [], "access_paths": [], "rows": [], "summary": {}, "ssh_aliases": [],
                  "controller_identity": "controller", "topology": {}, "unknown": [], "changes": [],
                  "events": [], "error": None, "observer_status": "OK", "run_id": 1, "last": None}
        with patch("netbot.cli.reconcile", return_value=result) as legacy:
            self.invoke("inspect", "orion", "--probe")
        legacy.assert_called_once()
        self.assertTrue(legacy.call_args.kwargs["probe"])

    def test_events_human_and_json(self):
        state = State(self.db)
        state.record_event("NEW_TOPOLOGY_PROPOSAL", "ATTENTION", "new-host", "proposal:p1", "New machine discovered")
        state.commit_events(); state.close()
        self.assertIn("ATTENTION", self.invoke("events"))
        self.assertEqual(json.loads(self.invoke("events", "--json"))["events"][0]["event_type"], "NEW_TOPOLOGY_PROPOSAL")

    def test_events_omits_empty_recent_section(self):
        output = self.invoke("events")
        self.assertIn("Nothing needs attention", output)
        self.assertNotIn("RECENT", output)

    def test_maintain_rendering_and_conflict(self):
        result = {"status": "OK", "dry_run": True, "discovery": {"status": "OK"},
                  "proposals": {"total": 0, "counts": {}}, "reconciliation": {"status": "OK"},
                  "summary": {"proposal_count": 0, "reconcile_unchanged": 2, "reconcile_changed": 0}}
        with patch("netbot.cli.run_maintenance", return_value=result):
            self.assertIn("DRY RUN", self.invoke("maintain", "--dry-run"))
            self.assertIn('"status": "OK"', self.invoke("maintain", "--json"))
            self.assertIn('"status": "OK"', self.invoke("maintain", "-v"))
            with self.assertRaises(SystemExit):
                self.invoke("maintain", "--json", "--verbose")

    def test_doctor_human_and_json(self):
        payload = {"version": "0.4.4", "checks": [{"name": "python", "status": "OK", "detail": "3.14"}]}
        with patch("netbot.cli.diagnose", return_value=payload):
            self.assertIn("NETBOT DOCTOR", self.invoke("doctor"))
            self.assertEqual(json.loads(self.invoke("doctor", "--json"))["checks"], payload["checks"])

    def test_doctor_human_labels_are_normalized(self):
        payload = {"checks": [{"name": name, "status": "OK", "detail": "ok"}
                               for name in ("python", "tailscale", "ssh", "launchctl",
                                            "tailscale-version", "tailscale-status", "topology",
                                            "state", "runtime", "logs", "supervisor", "watcher-service")]}
        with patch("netbot.cli.diagnose", return_value=payload):
            output = self.invoke("doctor")
        for label in ("Python", "Tailscale", "SSH", "launchctl", "Tailscale version",
                      "Tailscale status", "Topology", "State", "Runtime", "Logs",
                      "Supervisor", "Watcher service"):
            self.assertIn(label, output)


if __name__ == "__main__":
    unittest.main()
