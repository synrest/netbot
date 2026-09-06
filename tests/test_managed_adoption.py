import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netbot.managed_adoption import adoption_plan, apply_adoption
from netbot.state import State


TOPOLOGY = """version: 1
authority: arasaka
hosts:
  arasaka:
    bindings:
      tailscale:
        node_id: arasaka-id
"""


class ManagedAdoptionTests(unittest.TestCase):
    def setup_tree(self):
        root = Path(tempfile.mkdtemp())
        config = root / "config" / "topology.yaml"
        config.parent.mkdir()
        config.write_text(TOPOLOGY)
        ssh = root / "home" / ".ssh"
        managed = ssh / "config.d" / "50-netbot.conf"
        managed.parent.mkdir(parents=True)
        managed.write_text("# legacy\nHost orion\n    HostName orion\n")
        managed.chmod(0o600)
        state = State(root / "state" / "netbot.sqlite3")
        controller = state.controller_identity()
        state.close()
        return root, config, managed, controller

    def test_explicit_hash_adoption_persists_without_rewriting_file(self):
        root, config, managed, controller = self.setup_tree()
        before = managed.read_bytes()
        digest = hashlib.sha256(before).hexdigest()
        with patch("netbot.managed_adoption._paths", return_value=(managed.parents[1], managed.parent, managed)):
            plan = adoption_plan(config, "arasaka", digest, db_path=root / "state" / "netbot.sqlite3")
            self.assertEqual((plan["state"], plan["action"]), ("READY", "WOULD_ADOPT"))
            result = apply_adoption(plan, config, db_path=root / "state" / "netbot.sqlite3")
        self.assertEqual((result["state"], result["action"]), ("OWNED", "ADOPTED"))
        self.assertEqual(managed.read_bytes(), before)
        state = State(root / "state" / "netbot.sqlite3")
        record = state.managed_ssh_ownership("arasaka")
        state.close()
        self.assertEqual(record["controller_id"], controller)
        self.assertEqual(record["content_hash"], digest)

    def test_wrong_hash_and_symlink_are_blocked_without_state(self):
        root, config, managed, _ = self.setup_tree()
        db = root / "state" / "netbot.sqlite3"
        with patch("netbot.managed_adoption._paths", return_value=(managed.parents[1], managed.parent, managed)):
            wrong = adoption_plan(config, "arasaka", "0" * 64, db_path=db)
            self.assertEqual(wrong["action"], "BLOCKED")
        link = managed.with_name("link")
        link.symlink_to(managed)
        with patch("netbot.managed_adoption._paths", return_value=(managed.parents[1], managed.parent, link)):
            blocked = adoption_plan(config, "arasaka", "0" * 64, db_path=db)
        self.assertEqual(blocked["action"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
