"""Explicit, hash-bound adoption of a legacy local managed SSH fragment."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .apply_target import MANAGED_PATH
from .config import load_topology_authority, load_topology
from .state import State


def _paths():
    ssh = Path.home() / ".ssh"
    return ssh, ssh / "config.d", ssh / "config.d" / "50-netbot.conf"


def _target_node_id(config_path, target_identity):
    _, hosts = load_topology(config_path)
    host = next((h for h in hosts if h.identity == target_identity), None)
    return (host.attrs.get("bindings", {}).get("tailscale", {}).get("node_id")
            if host else None)


def _safe_file(path: Path, mode: int | None = None) -> tuple[bool, str | None]:
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return False, "managed file is absent"
    except OSError as exc:
        return False, f"managed file cannot be inspected: {exc}"
    if not path.is_file() or path.is_symlink():
        return False, "managed path is not a regular non-symlink file"
    if stat.st_uid != os.getuid():
        return False, "managed file is not owned by the current user"
    if mode is not None and stat.st_mode & 0o777 != mode:
        return False, f"managed file mode is not {mode:04o}"
    return True, None


def adoption_plan(config_path, target_identity: str, expected_sha256: str, *, db_path=None) -> dict[str, Any]:
    ssh, config_dir, managed = _paths()
    result: dict[str, Any] = {
        "target_identity": target_identity, "managed_path": MANAGED_PATH,
        "expected_sha256": expected_sha256, "action": "BLOCKED",
        "state": "BLOCKED", "reason": None, "dry_run_safe": True,
    }
    if load_topology_authority(config_path) != target_identity:
        result["reason"] = "legacy adoption is supported only for the local topology authority"
        return result
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        result["reason"] = "expected SHA-256 must be 64 lowercase hexadecimal characters"
        return result
    try:
        ssh_stat = ssh.lstat()
        if not ssh.is_dir() or ssh.is_symlink() or ssh_stat.st_uid != os.getuid():
            result["reason"] = "~/.ssh is not a regular non-symlink directory owned by the current user"
            return result
        if config_dir.exists() and (config_dir.is_symlink() or not config_dir.is_dir()):
            result["reason"] = "config.d is not a regular non-symlink directory"
            return result
        ok, reason = _safe_file(managed, 0o600)
        if not ok:
            result["reason"] = reason
            return result
        content = managed.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        result["current_sha256"] = actual
        if actual != expected_sha256:
            result["reason"] = "current managed file hash differs from operator-supplied hash"
            return result
        state = State(Path(db_path) if db_path else Path(config_path).parent.parent / "state" / "netbot.sqlite3")
        controller_id = state.controller_identity(create=False)
        record = state.managed_ssh_ownership(target_identity)
        state.close()
        result["controller_id"] = controller_id
        result["existing_record"] = record
        if not controller_id:
            result["reason"] = "current controller identity is unavailable"
            return result
        target_node_id = _target_node_id(config_path, target_identity)
        if record:
            if (record.get("controller_id") != controller_id or record.get("managed_path") != MANAGED_PATH or
                    record.get("target_identity") != target_identity or
                    str(record.get("target_node_id")) != str(target_node_id) or
                    record.get("content_hash") != actual):
                result["reason"] = "conflicting ownership record exists"
                return result
            result.update({"state": "OWNED", "action": "NO_CHANGE", "reason": "ownership already recorded"})
            return result
        marker = next((line for line in content.decode("utf-8", errors="replace").splitlines()
                       if line.startswith("# netbot-controller: ")), None)
        if marker and marker != "# netbot-controller: " + controller_id:
            result["reason"] = "managed file contains a foreign controller marker"
            return result
        result.update({"state": "READY", "action": "WOULD_ADOPT",
                       "reason": "explicit hash-bound adoption would persist local ownership"})
        return result
    except (OSError, UnicodeError) as exc:
        result["reason"] = f"adoption preflight failed: {exc}"
        return result


def apply_adoption(plan: dict[str, Any], config_path, *, db_path=None) -> dict[str, Any]:
    if plan.get("action") != "WOULD_ADOPT":
        return plan
    _, _, managed = _paths()
    try:
        ok, reason = _safe_file(managed, 0o600)
        if not ok:
            return {**plan, "state": "BLOCKED", "action": "BLOCKED", "reason": reason}
        content = managed.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != plan["expected_sha256"]:
            return {**plan, "state": "BLOCKED", "action": "BLOCKED",
                    "reason": "managed file changed before ownership commit"}
        state = State(Path(db_path) if db_path else Path(config_path).parent.parent / "state" / "netbot.sqlite3")
        controller_id = state.controller_identity(create=False)
        if not controller_id:
            state.close()
            return {**plan, "state": "BLOCKED", "action": "BLOCKED", "reason": "controller identity unavailable"}
        if state.managed_ssh_ownership(plan["target_identity"]):
            state.close()
            return {**plan, "state": "BLOCKED", "action": "BLOCKED", "reason": "conflicting ownership record appeared before commit"}
        state.save_managed_ssh_ownership(plan["target_identity"], controller_id, MANAGED_PATH,
                                         _target_node_id(config_path, plan["target_identity"]), actual, "adopted")
        state.close()
        return {**plan, "state": "OWNED", "action": "ADOPTED", "reason": "durable ownership persisted; file unchanged"}
    except Exception as exc:
        return {**plan, "state": "OWNERSHIP_UNPROVEN", "action": "BLOCKED",
                "reason": f"ownership persistence failed: {exc}"}
