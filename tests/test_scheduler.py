import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netbot import scheduler


class SchedulerTests(unittest.TestCase):
    def test_launchd_is_one_shot_and_uses_absolute_command(self):
        data = plistlib.loads(scheduler.render("darwin", "/opt/netbot", home=Path("/tmp/user"))["plist"])
        self.assertEqual(data["ProgramArguments"], ["/opt/netbot", "maintain"])
        self.assertEqual(data["StartInterval"], 1800)
        self.assertNotIn("KeepAlive", data)
        self.assertTrue(data["NetbotManaged"])

    def test_linux_is_oneshot_and_periodic(self):
        rendered = scheduler.render("linux", "/opt/netbot", "15m", home=Path("/tmp/user"))
        self.assertIn("Type=oneshot", rendered["service"].decode())
        self.assertIn("ExecStart=/opt/netbot maintain", rendered["service"].decode())
        self.assertIn("OnUnitActiveSec=900s", rendered["timer"].decode())
        self.assertIn("Persistent=true", rendered["timer"].decode())

    def test_interval_minimum_is_enforced(self):
        with self.assertRaises(ValueError):
            scheduler.interval_seconds("4m")

    def test_incompatible_path_launcher_is_rejected(self):
        with patch("netbot.scheduler.shutil.which", return_value="/usr/local/bin/netbot"), \
             patch("netbot.scheduler.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "usage: netbot {version,reconcile}"
            with self.assertRaises(ValueError):
                scheduler.resolve_executable()

    def test_compatible_path_launcher_is_accepted(self):
        with patch("netbot.scheduler.shutil.which", return_value="/usr/local/bin/netbot"), \
             patch("netbot.scheduler.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "usage: netbot {maintain,scheduler}"
            self.assertEqual(scheduler.resolve_executable(), ["/usr/local/bin/netbot"])

    def test_install_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            result = scheduler.install(home=Path(d), platform_name="linux", executable="/opt/netbot", dry_run=True, native=False)
            self.assertEqual(result["result"], "WOULD_INSTALL")
            self.assertFalse((Path(d) / ".config").exists())

    def test_install_is_atomic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            first = scheduler.install(home=home, platform_name="linux", executable="/opt/netbot", native=False)
            second = scheduler.install(home=home, platform_name="linux", executable="/opt/netbot", native=False)
            self.assertEqual(first["result"], "INSTALLED")
            self.assertEqual(second["result"], "ALREADY_INSTALLED")
            self.assertIn(scheduler.MARKER, (home / ".config/systemd/user/netbot-maintain.timer").read_text())

    def test_foreign_and_symlink_artifacts_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            path = scheduler.paths(home, platform_name="linux")["timer"]
            path.parent.mkdir(parents=True)
            path.write_text("foreign")
            self.assertEqual(scheduler.install(home=home, platform_name="linux", executable="/opt/netbot", native=False)["result"], "CONFLICT")
            path.unlink()
            path.symlink_to(home / "elsewhere")
            self.assertEqual(scheduler.install(home=home, platform_name="linux", executable="/opt/netbot", native=False)["result"], "CONFLICT")

    def test_remove_owned_artifacts_preserves_unrelated_files(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            scheduler.install(home=home, platform_name="linux", executable="/opt/netbot", native=False)
            unrelated = home / ".config/systemd/user/unrelated"
            unrelated.write_text("keep")
            self.assertEqual(scheduler.remove(home=home, platform_name="linux", native=False)["result"], "REMOVED")
            self.assertTrue(unrelated.exists())

    def test_status_distinguishes_present_from_enabled(self):
        with tempfile.TemporaryDirectory() as d, patch("netbot.scheduler.subprocess.run") as run:
            scheduler.install(home=Path(d), platform_name="linux", executable="/opt/netbot", native=False)
            run.return_value.returncode = 1
            result = scheduler.status(home=Path(d), platform_name="linux")
            self.assertTrue(result["installed"])
            self.assertFalse(result["enabled"])

    def test_unsupported_platform_is_structured(self):
        self.assertEqual(scheduler.install(platform_name="win32", dry_run=True)["result"], "UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
