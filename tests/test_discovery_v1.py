import fcntl
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from netbot.discovery.cycle import run_cycle
from netbot.discovery.crawl import RemoteSourceObservation, crawl
from netbot.state import State
from netbot.discovery.provider import DiscoveredPeer
from netbot.discovery.seed import (AUTH_PASSWORD, AUTH_PUBLIC_KEY, AUTH_UNKNOWN,
                                   AUTH_UNAVAILABLE, discover_local_ssh)


class FakeRunner:
    def __init__(self, auth=None):
        self.auth = auth or {}
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        if command[:2] == ["ssh", "-G"]:
            alias = command[-1]
            values = {
                "human": "hostname machine20\nuser rafael\nport 2222\nidentityfile ~/.ssh/id_ed25519\nproxyjump bastion\nproxycommand none\n",
                "managed": "hostname machine20\nuser lourdes\nport 22\nidentityfile ~/.ssh/id_ed25519_arasaka\nproxyjump none\nproxycommand none\n",
            }
            return subprocess.CompletedProcess(command, 0, values.get(alias, values["human"]), "")
        if command[:2] == ["ssh-keygen", "-lf"]:
            return subprocess.CompletedProcess(command, 0, "256 SHA256:known host (ED25519)\n", "")
        alias = command[-2] if len(command) > 1 and command[-1] == "true" else ""
        outcome = self.auth.get(alias, (0, ""))
        if isinstance(outcome, Exception):
            raise outcome
        code, stderr = outcome
        return subprocess.CompletedProcess(command, code, "", stderr)


class DiscoveryV1Tests(unittest.TestCase):
    def home(self):
        root = Path(tempfile.mkdtemp())
        ssh = root / ".ssh"
        (ssh / "config.d").mkdir(parents=True)
        (ssh / "config").write_text("""Host *
    User inherited
Host human
    HostName machine20
    Port 2222
""")
        (ssh / "config.d" / "50-netbot.conf").write_text("""Host managed
    HostName machine20
    User lourdes
    Port 22
""")
        (ssh / "known_hosts").write_text("machine20 ssh-ed25519 AAAA\n")
        return root

    def test_seed_separates_explicit_human_and_managed_aliases(self):
        root = self.home()
        runner = FakeRunner({"human": (255, "Permission denied (publickey,password)."),
                             "managed": (0, "")})
        peers = [DiscoveredPeer("tailscale", "node-1", "machine20", ["100.0.0.20"], True)]
        result = discover_local_ssh(root, peers, runner=runner)
        self.assertEqual([x["alias"] for x in result["human_aliases"]], ["human"])
        self.assertEqual([x["alias"] for x in result["managed_aliases"]], ["managed"])
        human = result["human_aliases"][0]
        self.assertEqual(human["effective"]["user"], "rafael")
        self.assertEqual(human["effective"]["port"], 2222)
        self.assertEqual(human["effective"]["proxyjump"], "bastion")
        self.assertEqual(human["auth_state"], AUTH_PASSWORD)
        self.assertEqual(result["managed_aliases"][0]["auth_state"], AUTH_PUBLIC_KEY)
        self.assertEqual(human["correlation"]["provider_node_id"], "node-1")

    def test_auth_failure_without_password_evidence_is_unknown(self):
        root = self.home()
        runner = FakeRunner({"human": (255, "Permission denied (publickey)."), "managed": (255, "no route")})
        result = discover_local_ssh(root, [], runner=runner)
        self.assertEqual(result["human_aliases"][0]["auth_state"], AUTH_UNKNOWN)

    def test_unmatched_peer_remains_unbound_and_known_hosts_is_evidence_only(self):
        root = self.home()
        runner = FakeRunner({"human": (255, "connection timed out"), "managed": (255, "connection timed out")})
        peer = DiscoveredPeer("tailscale", "unbound", "other", ["100.0.0.30"], False)
        result = discover_local_ssh(root, [peer], runner=runner)
        self.assertEqual(result["unresolved_provider_peers"][0]["provider_node_id"], "unbound")
        self.assertEqual(result["known_hosts"]["status"], "available")
        self.assertEqual([x["alias"] for x in result["human_aliases"]], ["human"])

    def test_cycle_dry_run_is_structured_and_lock_is_single_flight(self):
        root = self.home()
        config = root / "topology.yaml"
        config.write_text("version: 1\nhosts:\n")
        db = root / "state" / "netbot.sqlite3"
        provider = SimpleNamespace(name="tailscale", observe=lambda: ([], None))
        runner = FakeRunner()
        result = run_cycle(config, db, home=root, runtime=root / "run", dry_run=True,
                           provider=provider, runner=runner)
        self.assertEqual(result["status"], "OK")
        self.assertTrue(result["dry_run"])
        self.assertIn("human_aliases", result["ssh"])
        self.assertFalse(any(any(token in " ".join(command) for token in ("mkdir", "mv", "rm ", "cat >"))
                             for command in runner.commands))

        runtime = root / "locked-run"
        runtime.mkdir()
        lock_path = runtime / "cycle.lock"
        with lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            blocked = run_cycle(config, db, home=root, runtime=runtime,
                                provider=provider, runner=runner)
        self.assertEqual(blocked["status"], "BLOCKED")

    def test_cycle_provider_failure_is_partial_without_remote_crawl(self):
        root = self.home()
        config = root / "topology.yaml"
        config.write_text("version: 1\nhosts:\n")
        provider = SimpleNamespace(name="tailscale", observe=lambda: ([], "socket unavailable"))
        result = run_cycle(config, root / "db.sqlite3", home=root, provider=provider, runner=FakeRunner())
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["provider"]["error"], "socket unavailable")

    def seed(self, *items):
        return {"human_aliases": [dict(alias=alias, provenance="SSH_CONFIG_HUMAN",
                                        source="config", effective={"hostname": destination},
                                        correlation={"provider_node_id": destination},
                                        auth_state=auth, auth_evidence="fixture")
                              for alias, destination, auth in items],
                "managed_aliases": [], "unresolved_provider_peers": []}

    def remote(self, mapping):
        class Observer:
            def observe(self, source):
                return mapping.get(source, RemoteSourceObservation(source, (), status="SOURCE_UNAVAILABLE"))
        return Observer()

    def edge(self, source, alias, destination, auth="UNKNOWN"):
        from netbot.discovery.seed import SSHSeed
        return SSHSeed(alias, "SSH_CONFIG_HUMAN", "remote-config",
                       {"hostname": destination, "user": "zero", "port": 22},
                       {"provider_node_id": destination}, auth, "fixture")

    def test_recursive_crawl_records_directed_edges_and_depth(self):
        mapping = {
            "b": RemoteSourceObservation("b", (self.edge("b", "c", "c", AUTH_PUBLIC_KEY),)),
            "c": RemoteSourceObservation("c", (self.edge("c", "a", "a"),)),
        }
        graph = crawl("a", self.seed(("b", "b", AUTH_PUBLIC_KEY)), self.remote(mapping), max_depth=3)
        self.assertEqual([(x.source, x.destination) for x in graph.relationships],
                         [("a", "b"), ("b", "c"), ("c", "a")])
        self.assertEqual(len(graph.sources), 2)

    def test_password_and_unavailable_edges_are_not_crawl_sources(self):
        graph = crawl("a", self.seed(("password", "p", "PASSWORD_GATED"),
                                      ("offline", "o", AUTH_UNAVAILABLE)), self.remote({}))
        self.assertEqual(graph.sources, [])
        self.assertEqual(len(graph.relationships), 2)

    def test_duplicate_source_is_visited_once_and_budget_truncates(self):
        mapping = {"b": RemoteSourceObservation("b", (self.edge("b", "c", "c", AUTH_PUBLIC_KEY),))}
        graph = crawl("a", self.seed(("b", "b", AUTH_PUBLIC_KEY), ("b2", "b", AUTH_PUBLIC_KEY)),
                      self.remote(mapping), max_nodes=1)
        self.assertEqual(len(graph.sources), 1)
        self.assertTrue(graph.truncated)

    def test_cycle_does_not_revisit_source(self):
        mapping = {
            "b": RemoteSourceObservation("b", (self.edge("b", "a", "a", AUTH_PUBLIC_KEY),)),
            "a": RemoteSourceObservation("a", (self.edge("a", "b", "b", AUTH_PUBLIC_KEY),)),
        }
        graph = crawl("a", self.seed(("b", "b", AUTH_PUBLIC_KEY)), self.remote(mapping))
        self.assertEqual([x["source"] for x in graph.sources], ["b"])

    def test_operation_failure_isolated_from_graph(self):
        graph = crawl("a", self.seed(("bad", "bad", AUTH_PUBLIC_KEY),
                                      ("good", "good", AUTH_PUBLIC_KEY)),
                      self.remote({"bad": RemoteSourceObservation("bad", (), status="SOURCE_INSPECTION_FAILED"),
                                   "good": RemoteSourceObservation("good", (), status="OBSERVED")}))
        self.assertEqual(len(graph.sources), 2)
        self.assertEqual(graph.sources[0]["status"], "SOURCE_INSPECTION_FAILED")

    def persisted_graph(self, run_id, auth_state="PUBLIC_KEY_PROVEN", source="a"):
        return {"nodes": [{"observation_identity": "tailscale:node-1", "observed_from": source,
                           "aliases": ["b"], "provider_peers": [], "status": "OBSERVED"}],
                "relationships": [{"source": source, "destination": "node-1", "alias": "b",
                                    "effective": {"hostname": "b", "user": "zero", "port": 22},
                                    "auth_state": auth_state, "provenance": "SSH_CONFIG_HUMAN",
                                    "observed_from": source, "evidence": "fixture"}],
                "sources": [], "truncated": False, "reason": None}

    def test_non_dry_cycle_persists_run_and_directed_evidence(self):
        root = self.home(); config = root / "topology.yaml"; config.write_text("version: 1\nhosts:\n")
        db = root / "history.sqlite3"
        provider = SimpleNamespace(name="tailscale", observe=lambda: ([DiscoveredPeer(
            "tailscale", "node-1", "machine20", ["100.0.0.20"], True)], None))
        result = run_cycle(config, db, home=root, provider=provider, runner=FakeRunner())
        self.assertEqual(result["status"], "OK")
        state = State(db)
        run = state.latest_discovery_run(); graph = state.discovery_graph()
        state.close()
        self.assertEqual(run["run_id"], result["cycle_id"])
        self.assertEqual(run["crawl_status"], "COMPLETE")
        self.assertTrue(graph["nodes"])

    def test_dry_run_does_not_persist_discovery_history(self):
        root = self.home(); config = root / "topology.yaml"; config.write_text("version: 1\nhosts:\n")
        db = root / "history.sqlite3"
        provider = SimpleNamespace(name="tailscale", observe=lambda: ([], None))
        run_cycle(config, db, home=root, dry_run=True, provider=provider, runner=FakeRunner())
        state = State(db); self.assertIsNone(state.latest_discovery_run()); state.close()

    def test_history_preserves_provenance_and_auth_transitions(self):
        root = Path(tempfile.mkdtemp()); db = root / "history.sqlite3"
        state = State(db)
        state.record_discovery_cycle("r1", "controller", "t1", "t1", "OK", "OK", "COMPLETE", None,
                                     self.persisted_graph("r1", "PUBLIC_KEY_PROVEN", "a"), [])
        state.record_discovery_cycle("r2", "controller", "t2", "t2", "PARTIAL", "FAILED", "PARTIAL", None,
                                     self.persisted_graph("r2", "UNAVAILABLE", "b"), [])
        graph = state.discovery_graph(); rows = state.db.execute(
            "select auth_state,provenance,observed_from from discovery_relationship_evidence order by id").fetchall()
        state.close()
        self.assertEqual([row[0] for row in rows], ["PUBLIC_KEY_PROVEN", "UNAVAILABLE"])
        self.assertEqual([row[2] for row in rows], ["a", "b"])
        self.assertEqual(len(graph["relationships"]), 1)

    def test_different_provider_ids_do_not_merge_by_name_or_ip(self):
        root = Path(tempfile.mkdtemp()); db = root / "history.sqlite3"; state = State(db)
        for run, node in (("r1", "one"), ("r2", "two")):
            state.record_discovery_cycle(run, "controller", run, run, "OK", "OK", "COMPLETE", None,
                {"nodes": [], "relationships": [], "sources": [], "truncated": False, "reason": None},
                [{"provider": "tailscale", "provider_node_id": node, "advertised_name": "same",
                  "addresses": ["100.0.0.1"], "online": True, "metadata": {}, "observed_at": run}])
        count = state.db.execute("select count(distinct evidence_key) from discovery_node_evidence").fetchone()[0]
        state.close(); self.assertEqual(count, 2)

    def test_provider_failure_retains_prior_evidence(self):
        root = Path(tempfile.mkdtemp()); db = root / "history.sqlite3"; state = State(db)
        state.record_discovery_cycle("r1", "controller", "t1", "t1", "OK", "OK", "COMPLETE", None,
                                     self.persisted_graph("r1"), [])
        state.record_discovery_cycle("r2", "controller", "t2", "t2", "PARTIAL", "FAILED", "COMPLETE", None,
                                     {"nodes": [], "relationships": [], "sources": [], "truncated": False, "reason": None}, [])
        self.assertIsNotNone(state.latest_discovery_run())
        self.assertEqual(state.db.execute("select count(*) from discovery_relationship_evidence").fetchone()[0], 1)
        state.close()

    def test_persistence_failure_is_explicit(self):
        root = self.home(); config = root / "topology.yaml"; config.write_text("version: 1\nhosts:\n")
        provider = SimpleNamespace(name="tailscale", observe=lambda: ([], None))
        with patch("netbot.discovery.cycle.State.record_discovery_cycle", side_effect=RuntimeError("disk failure")):
            result = run_cycle(config, root / "history.sqlite3", home=root,
                               provider=provider, runner=FakeRunner())
        self.assertEqual(result["status"], "PERSISTENCE_FAILED")
        self.assertIn("disk failure", result["persistence_error"])


if __name__ == "__main__":
    unittest.main()
