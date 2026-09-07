import json
import os
import plistlib
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from netbot.doctor import diagnose
from netbot import service
from netbot.version import __version__


ROOT = Path(__file__).parents[1]


class DeploymentTests(unittest.TestCase):
    def test_version_is_consistent(self):
        self.assertEqual(__version__, "0.4.2")
        self.assertIn(__version__, (ROOT / "pyproject.toml").read_text())

    def test_installed_plist_has_no_source_checkout_dependency(self):
        with tempfile.TemporaryDirectory() as d:
            plist = ROOT / "launchd" / "com.netbot.watch.plist"
            data = plistlib.loads(plist.read_bytes())
            prefix = str(Path(d) / "Netbot")
            data["ProgramArguments"] = [prefix + "/bin/netbot-watch"]
            data["WorkingDirectory"] = prefix
            self.assertNotIn("/Users/zero/Developer/netbot", str(data))
            self.assertTrue(data["ProgramArguments"][0].startswith(prefix))

    def test_install_runtime_uses_stable_wrapper_location(self):
        script = (ROOT / "install.sh").read_text()
        self.assertIn('data["ProgramArguments"] = [bin_dir + "/netbot-watch"]', script)
        self.assertNotIn('prefix + "/bin/netbot-watch"', script)

    def test_doctor_is_read_only_and_classifies_missing_install(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"NETBOT_PREFIX": d}), \
             mock.patch("netbot.doctor.service_status", return_value={"loaded": False, "running": False, "watcher": False, "pid": None}):
            result = diagnose()
            self.assertEqual(result["version"], __version__)
            self.assertEqual(result["install_prefix"], d)
            self.assertFalse((Path(d) / "config").exists())

    def test_service_uses_installed_prefix_and_user_domain(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"NETBOT_PREFIX": d}):
            installed = Path(d) / "current" / "launchd"
            installed.mkdir(parents=True)
            (installed / "com.netbot.watch.plist").write_bytes(b"<?xml version=\"1.0\"?><plist><dict/></plist>")
            self.assertEqual(service.plist_path(), installed / "com.netbot.watch.plist")
            self.assertTrue(service.domain().startswith("gui/"))

    def test_release_script_includes_runtime_and_excludes_local_state(self):
        subprocess.run(["./scripts/build-release.sh"], cwd=ROOT, check=True,
                       stdout=subprocess.PIPE, text=True)
        archive = ROOT / "dist" / f"netbot-{__version__}.zip"
        try:
            with zipfile.ZipFile(archive) as zf:
                names = set(zf.namelist())
            prefix = f"netbot-{__version__}/"
            self.assertIn(prefix + "install.sh", names)
            self.assertIn(prefix + "config/topology.yaml", names)
            self.assertIn(prefix + "netbot/cli.py", names)
            self.assertIn(prefix + "systemd/netbot-watch.service", names)
            self.assertIn(prefix + "openrc/netbot-watch", names)
            self.assertNotIn(prefix + "state/netbot.sqlite3", names)
            self.assertFalse(any("__pycache__" in name or ".git/" in name for name in names))
            self.assertTrue((archive.with_suffix(".zip.sha256")).is_file())
        finally:
            archive.unlink(missing_ok=True)
            archive.with_suffix(".zip.sha256").unlink(missing_ok=True)

    def test_linux_supervisor_templates_have_bounded_restart_contract(self):
        systemd = (ROOT / "systemd/netbot-watch.service").read_text()
        self.assertIn("Restart=on-failure", systemd)
        self.assertIn("RestartSec=60s", systemd)
        self.assertNotIn("Restart=always", systemd)
        openrc = (ROOT / "openrc/netbot-watch").read_text()
        self.assertIn('supervisor="supervise-daemon"', openrc)
        self.assertIn("respawn_delay=30", openrc)
        self.assertIn("respawn_max=5", openrc)

    def test_service_backend_detection_is_capability_based(self):
        with mock.patch.object(service.sys, "platform", "linux"), \
             mock.patch.object(service.shutil, "which", side_effect=lambda name: "/usr/bin/systemctl" if name == "systemctl" else None), \
             mock.patch.object(service.Path, "exists", return_value=True), \
             mock.patch.object(service.subprocess, "run", return_value=mock.Mock(returncode=0)):
            self.assertEqual(service.detect_backend(), "systemd")
