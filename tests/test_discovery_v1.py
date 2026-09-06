import fcntl
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from netbot.discovery.cycle import run_cycle
from netbot.discovery.crawl import RemoteSourceObservation, crawl
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


if __name__ == "__main__":
    unittest.main()
