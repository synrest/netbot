import tempfile
import unittest
import json
import os
import plistlib
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from netbot.sync import run_sync
from netbot.watcher import JSONStreamDecoder, relevant, next_backoff, watch
from netbot import service


class SyncTests(unittest.TestCase):
    def result(self, run_id):
        return {"run_id": run_id, "observer_status": "available"}

    def test_sync_runs_reconciler_with_reason_and_generates_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); calls = []
            def reconcile(config, db, home, reason):
                calls.append(reason); return self.result(1)
            output = root / "generated.json"
            result = run_sync(root / "topology.yaml", root / "state.sqlite3",
                              root / "home", output, "ipn", root / "run", reconcile,
                              lambda *args: None)
            self.assertEqual(calls, ["ipn"])
            self.assertEqual(result["state"], "completed")

    def test_concurrent_sync_becomes_one_pending_request(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); runtime = root / "run"; runtime.mkdir()
            import fcntl
            with (runtime / "sync.lock").open("a+") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                result = run_sync(root / "topology.yaml", root / "state.sqlite3",
                                  root / "home", root / "generated.json", "calendar",
                                  runtime, lambda *args: self.result(1), lambda *args: None)
                self.assertEqual(result["state"], "coalesced")
                self.assertTrue((runtime / "sync.pending").exists())
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def test_pending_request_runs_one_followup(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); runtime = root / "run"; calls = []
            def reconcile(config, db, home, reason):
                calls.append(reason)
                if len(calls) == 1:
                    runtime.mkdir(parents=True, exist_ok=True)
                    (runtime / "sync.pending").write_text("pending\n")
                return self.result(len(calls))
            result = run_sync(root / "topology.yaml", root / "state.sqlite3",
                              root / "home", root / "generated.json", "manual",
                              runtime, reconcile, lambda *args: None)
            self.assertEqual(calls, ["manual", "followup"])
            self.assertTrue(result["followup"])

    def test_stale_lock_file_does_not_wedge_sync(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); runtime = root / "run"; runtime.mkdir()
            (runtime / "sync.lock").write_text("stale")
            result = run_sync(root / "topology.yaml", root / "state.sqlite3",
                              root / "home", root / "generated.json", runtime=runtime,
                              reconcile_fn=lambda *args: self.result(1),
                              generate_fn=lambda *args: None)
            self.assertEqual(result["state"], "completed")

    def test_cli_sync_is_the_single_canonical_entry_point(self):
        import netbot.cli as cli
        with mock.patch.object(cli, "run_sync", return_value={"state": "completed"}) as run:
            output = StringIO()
            with redirect_stdout(output):
                cli.main(["sync", "--reason", "calendar"])
            run.assert_called_once()
            self.assertEqual(json.loads(output.getvalue())["state"], "completed")

    def test_launchd_agents_are_user_local_and_have_no_socket(self):
        for filename in ("com.netbot.sync.plist", "com.netbot.watch.plist"):
            with open(Path(__file__).parents[1] / "launchd" / filename, "rb") as stream:
                plist = plistlib.load(stream)
            if filename.endswith("watch.plist"):
                self.assertTrue(plist["ProgramArguments"][0].startswith("__NETBOT_"))
            else:
                self.assertTrue(plist["ProgramArguments"][0].startswith("/"))
            self.assertNotIn("Sockets", plist)
            self.assertIn("WorkingDirectory", plist)
        with open(Path(__file__).parents[1] / "launchd" / "com.netbot.watch.plist", "rb") as stream:
            watcher = plistlib.load(stream)
        self.assertNotIn("/Users/zero/Developer/netbot", str(watcher))

    def test_watcher_launchd_supervision_contract(self):
        with open(Path(__file__).parents[1] / "launchd" / "com.netbot.watch.plist", "rb") as stream:
            plist = plistlib.load(stream)
        self.assertTrue(plist["RunAtLoad"])
        self.assertEqual(plist["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(plist["ThrottleInterval"], 60)
        self.assertNotIn("StartInterval", plist)
        self.assertNotIn("StartCalendarInterval", plist)
        self.assertNotIn("NetworkState", plist)
        self.assertNotIn("WatchPaths", plist)
        self.assertNotIn("PathState", plist)

    @mock.patch.object(service, "launchctl")
    @unittest.skipUnless(sys.platform == "darwin", "requires macOS launchd")
    def test_service_lifecycle_uses_user_launchd_domain(self, launchctl):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"NETBOT_PREFIX": d}):
            launchctl.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            service.start()
            launchctl.assert_called_with("bootstrap", service.domain(), str(service.plist_path()))
            service.stop()
            launchctl.assert_called_with("bootout", f"{service.domain()}/{service.LABEL}")

    @mock.patch.object(service, "launchctl")
    @unittest.skipUnless(sys.platform == "darwin", "requires macOS launchd")
    def test_service_restart_boots_out_then_bootstraps(self, launchctl):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"NETBOT_PREFIX": d}):
            launchctl.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            result = service.restart()
            self.assertTrue(result["ok"])
            self.assertEqual([call.args for call in launchctl.call_args_list], [
                ("bootout", f"{service.domain()}/{service.LABEL}"),
                ("bootstrap", service.domain(), str(service.plist_path())),
            ])


class WatcherTests(unittest.TestCase):
    def values(self, chunks):
        decoder = JSONStreamDecoder(); values = []
        for chunk in chunks:
            values.extend(decoder.feed(chunk))
        decoder.finish()
        return values

    def test_pretty_printed_ipn_patch(self):
        values = self.values(['{\n  "PeerChangedPatch": [\n',
                              '    {"NodeID": 1479759345960161, "Online": false}\n',
                              '  ]\n}\n'])
        self.assertEqual(values[0]["PeerChangedPatch"][0]["NodeID"], 1479759345960161)
        self.assertTrue(relevant(values[0]))

    def test_compact_and_multiple_values_with_whitespace(self):
        values = self.values([' {"PeersRemoved":[1]}\n\n',
                              '{"Prefs":{"RunSSH":true}}'])
        self.assertEqual(len(values), 2)
        self.assertTrue(relevant(values[0])); self.assertFalse(relevant(values[1]))

    def test_arbitrary_chunk_boundaries(self):
        payload = '{"PeerChangedPatch":[{"NodeID":1479759345960161,"Online":false}]}'
        values = self.values([payload[:4], payload[4:19], payload[19:37], payload[37:]])
        self.assertEqual(values[0]["PeerChangedPatch"][0]["Online"], False)

    def test_non_mapping_values_are_ignored_safely(self):
        values = self.values(['"text" 42 false null [] ', '{"NetMap":{"Peer":{}}}'])
        self.assertEqual(values[:5], ["text", 42, False, None, []])
        self.assertTrue(relevant(values[5]))

    def test_incomplete_stream_is_retained_then_rejected_at_finish(self):
        decoder = JSONStreamDecoder()
        self.assertEqual(decoder.feed('{"PeerChangedPatch":'), [])
        self.assertEqual(decoder.feed('[{"NodeID":1}]}'), [{"PeerChangedPatch": [{"NodeID": 1}]}])
        decoder.finish()
        broken = JSONStreamDecoder(); broken.feed('{"unterminated":')
        with self.assertRaises(ValueError): broken.finish()

    def test_filters_to_peer_or_netmap_notifications(self):
        self.assertTrue(relevant({"PeersChanged": [{"NodeID": 1}]}))
        self.assertTrue(relevant({"PeersRemoved": [1]}))
        self.assertTrue(relevant({"NetMap": {"Peer": {}}}))
        self.assertFalse(relevant({"Prefs": {"RunSSH": True}}))
        self.assertFalse(relevant({"State": "Running"}))

    def test_watcher_backoff_avoids_restart_storm(self):
        self.assertEqual(next_backoff(1.0, 0.1), 2.0)
        self.assertEqual(next_backoff(16.0, 0.1), 30.0)
        self.assertEqual(next_backoff(30.0, 0.1), 30.0)
        self.assertEqual(next_backoff(30.0, 10.0), 1.0)

    def test_missing_watcher_executable_is_unrecoverable_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            result = watch(Path(d) / "topology.yaml", Path(d) / "state.sqlite3",
                           Path(d) / "home", Path(d) / "generated.json",
                           command="/definitely/missing/tailscale")
            self.assertEqual(result, 1)
