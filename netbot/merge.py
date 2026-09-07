"""Conservative, explicit accepted-topology identity merges."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from .config import load_topology, load_topology_authority
from .state import State


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _active(host) -> bool:
    return host.attrs.get("lifecycle") != "retired" and not host.attrs.get("superseded_by")


def _provider(host):
    bindings = host.attrs.get("bindings", {})
    candidates = [(name, value) for name, value in bindings.items()
                  if isinstance(value, dict) and value.get("node_id") is not None]
    if len(candidates) != 1:
        return None
    name, value = candidates[0]
    return name, str(value["node_id"])


def _aliases(host):
    return list(host.attrs.get("bindings", {}).get("ssh", {}).get("aliases", []) or [])


def _controller_identity(db: Path):
    if not db.exists():
        return None
    try:
        connection = sqlite3.connect(f"file:{db.resolve()}?mode=ro", uri=True)
        try:
            row = connection.execute("SELECT value FROM controller_identity WHERE id=1").fetchone()
            return row[0] if row else None
        finally:
            connection.close()
    except sqlite3.Error:
        return None


def _pending_merge_readonly(db: Path, source: str, survivor: str):
    """Read a pending journal without creating or migrating the state DB."""
    if not db.exists():
        return None
    try:
        connection = sqlite3.connect(f"file:{db.resolve()}?mode=ro", uri=True)
        try:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM topology_merges WHERE source=? AND survivor=? "
                "AND state='PENDING' ORDER BY decided_at DESC LIMIT 1",
                (source, survivor)).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()
    except sqlite3.Error:
        return None


def _topology_reflects_merge(config: Path, source: str, survivor: str) -> bool:
    try:
        _, hosts = load_topology(config)
        by_identity = {host.identity: host for host in hosts}
        source_host = by_identity.get(source)
        return bool(source_host and source_host.attrs.get("lifecycle") == "retired"
                    and source_host.attrs.get("superseded_by") == survivor)
    except Exception:
        return False


def _plan(source, survivor, before_hash, *, result="SAFE", conflicts=None,
          evidence=None, operation=None):
    return {"schema": "netbot.cli/v1", "command": "merge", "source": source,
            "survivor": survivor, "result": result, "safe": result in {"SAFE", "ALREADY_MERGED"},
            "conflicts": list(conflicts or []), "evidence": dict(evidence or {}),
            "lifecycle": {"source": "retired", "superseded_by": survivor},
            "binding_effect": "unchanged", "relationship_effect": "unchanged",
            "alias_effect": "unchanged", "before_hash": before_hash,
            "topology_changed": False, "reconciliation_performed": False,
            "operation": operation}


def plan_merge(config: Path, db: Path, source: str, survivor: str) -> dict:
    """Build a deterministic, read-only merge plan."""
    before_hash = _sha(config)
    _, hosts = load_topology(config)
    by_identity = {host.identity: host for host in hosts}
    source_host, survivor_host = by_identity.get(source), by_identity.get(survivor)
    if source == survivor:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["source and survivor must differ"])
    if source_host is None:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["source identity does not exist"])
    if survivor_host is None:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["survivor identity does not exist"])
    authority = load_topology_authority(config)
    controller = _controller_identity(db)
    if source in {authority, controller}:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["source is the active controller/authority"])
    if survivor in {authority, controller}:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["survivor is the active controller/authority"])
    if source_host.attrs.get("superseded_by") == survivor and source_host.attrs.get("lifecycle") == "retired":
        return _plan(source, survivor, before_hash, result="ALREADY_MERGED",
                     evidence={"reason": "source is already superseded by survivor"})
    if source_host.attrs.get("lifecycle") == "retired" or source_host.attrs.get("superseded_by"):
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["source is already retired or superseded"])
    if not _active(survivor_host):
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["survivor is retired or superseded"])

    source_provider, survivor_provider = _provider(source_host), _provider(survivor_host)
    if not source_provider or not survivor_provider:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["insufficient provider identity evidence"])
    if source_provider[0] != survivor_provider[0]:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["provider scopes differ"])
    if source_provider[1] != survivor_provider[1]:
        return _plan(source, survivor, before_hash, result="BLOCKED",
                     conflicts=["conflicting provider node IDs"])

    conflicts = []
    for host in hosts:
        if host.identity in {source, survivor}:
            continue
        if host.attrs.get("parent") in {source, survivor}:
            conflicts.append(f"{host.identity} depends on a merge identity")
    if source_host.attrs.get("parent"):
        conflicts.append("source has a parent relationship")
    if survivor_host.attrs.get("parent"):
        conflicts.append("survivor has a parent relationship")
    for field in ("class", "kind"):
        if source_host.attrs.get(field) and survivor_host.attrs.get(field) and source_host.attrs[field] != survivor_host.attrs[field]:
            conflicts.append(f"incompatible {field} values")
    source_aliases, survivor_aliases = set(_aliases(source_host)), set(_aliases(survivor_host))
    if source_aliases & survivor_aliases:
        conflicts.append("source and survivor share an SSH alias")
    active_aliases = {}
    for host in hosts:
        if not _active(host):
            continue
        for alias in _aliases(host):
            active_aliases.setdefault(alias, []).append(host.identity)
    for alias, owners in sorted(active_aliases.items()):
        if len(owners) > 1 and survivor in owners:
            conflicts.append(f"SSH alias '{alias}' is claimed by multiple active identities")
    if conflicts:
        return _plan(source, survivor, before_hash, result="BLOCKED", conflicts=conflicts,
                     evidence={"provider": source_provider[0], "provider_node_id": source_provider[1]})
    return _plan(source, survivor, before_hash,
                 evidence={"provider": source_provider[0], "provider_node_id": source_provider[1],
                           "basis": "same explicit provider-scoped node ID"})


def _mutated_text(original: bytes, source: str, survivor: str) -> bytes:
    lines = original.decode("utf-8").splitlines(True)
    starts = [(index, line.strip()[:-1]) for index, line in enumerate(lines)
              if len(line) - len(line.lstrip()) == 2 and line.strip().endswith(":")]
    names = [name for _, name in starts]
    if source not in names:
        raise ValueError("source identity disappeared during merge")
    position = names.index(source)
    start = starts[position][0]
    end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
    block = [line for line in lines[start:end]
             if not line.startswith("    lifecycle:") and not line.startswith("    superseded_by:")]
    if block and not block[-1].endswith("\n"):
        block[-1] += "\n"
    block.extend(["    lifecycle: retired\n", f"    superseded_by: {survivor}\n"])
    lines[start:end] = block
    return "".join(lines).encode("utf-8")


def _atomic_merge_replace(config: Path, content: bytes, expected_hash: str) -> str:
    if config.is_symlink() or not config.is_file() or config.parent.is_symlink():
        raise ValueError("topology path must be a regular non-symlink file")
    if _sha(config) != expected_hash:
        raise ValueError("topology changed during merge")
    fd, name = tempfile.mkstemp(prefix=f".{config.name}.merge.", dir=config.parent)
    temp = Path(name)
    try:
        os.fchmod(fd, config.stat().st_mode & 0o777)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, config)
    finally:
        if temp.exists():
            temp.unlink()
    return _sha(config)


def _merge_locked(config: Path, db: Path, source: str, survivor: str) -> dict:
    state = None
    try:
        current_hash = _sha(config)
        pending_recovery = _pending_merge_readonly(db, source, survivor)
        if pending_recovery:
            if current_hash == pending_recovery.get("after_hash"):
                if _topology_reflects_merge(config, source, survivor):
                    state = State(db)
                    try:
                        state.update_merge(pending_recovery["merge_id"], "COMMITTED", current_hash)
                    except Exception as exc:
                        return _plan(source, survivor, current_hash, result="AUDIT_PENDING",
                                     conflicts=[f"merge journal finalization failed: {exc}"],
                                     operation=pending_recovery)
                    finalized = {**pending_recovery, "state": "COMMITTED",
                                  "actual_after_hash": current_hash}
                    return _plan(source, survivor, current_hash, result="ALREADY_MERGED",
                                 evidence={"reason": "pending merge finalized after topology replacement"},
                                 operation=finalized) | {"recovery": "PENDING_FINALIZED"}
                return _plan(source, survivor, current_hash, result="RECOVERY_REQUIRED",
                             conflicts=["pending merge after-hash does not match topology contents"],
                             operation=pending_recovery)
            if current_hash != pending_recovery.get("before_hash"):
                return _plan(source, survivor, current_hash, result="RECOVERY_REQUIRED",
                             conflicts=["pending merge has unexpected topology hash"],
                             operation=pending_recovery)

        plan = plan_merge(config, db, source, survivor)
        if plan["result"] == "ALREADY_MERGED":
            state = State(db)
            pending = state.pending_merge(source, survivor)
            if pending and pending.get("after_hash") == plan["before_hash"]:
                state.update_merge(pending["merge_id"], "COMMITTED", plan["before_hash"])
                plan["result"] = "ALREADY_MERGED"
                plan["recovery"] = "PENDING_FINALIZED"
            return plan
        if plan["result"] != "SAFE":
            return plan
        state = State(db)
        merge_id = hashlib.sha256(f"merge-v1:{source}:{survivor}:{plan['before_hash']}".encode()).hexdigest()[:20]
        pending = state.merge_operation(merge_id)
        if pending and pending.get("state") == "COMMITTED":
            return {**plan, "result": "ALREADY_MERGED", "operation": pending}
        try:
            after_content = _mutated_text(config.read_bytes(), source, survivor)
        except Exception as exc:
            return {**plan, "result": "STALE_TOPOLOGY", "conflicts": [str(exc)]}
        fd, name = tempfile.mkstemp(prefix=f".{config.name}.merge-validate.", dir=config.parent)
        temp = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(after_content)
            _, validated = load_topology(temp)
            source_after = next(host for host in validated if host.identity == source)
            survivor_after = next(host for host in validated if host.identity == survivor)
            if source_after.attrs.get("lifecycle") != "retired" or source_after.attrs.get("superseded_by") != survivor:
                raise ValueError("validated topology did not contain the requested supersession")
            if survivor_after.attrs != next(host for host in load_topology(config)[1] if host.identity == survivor).attrs:
                raise ValueError("merge changed survivor attributes")
        except Exception as exc:
            try:
                os.close(fd)
            except OSError:
                pass
            if pending:
                state.update_merge(merge_id, "FAILED", None)
            return {**plan, "result": "BLOCKED", "conflicts": [str(exc)]}
        finally:
            if temp.exists():
                temp.unlink()
        after_hash = hashlib.sha256(after_content).hexdigest()
        state.record_merge_pending({"merge_id": merge_id, "source": source, "survivor": survivor,
                                    "before_hash": plan["before_hash"], "after_hash": after_hash,
                                    "evidence_json": json.dumps(plan["evidence"], sort_keys=True)})
        try:
            actual_after = _atomic_merge_replace(config, after_content, plan["before_hash"])
        except Exception as exc:
            state.update_merge(merge_id, "FAILED", None)
            return {**plan, "result": "TOPOLOGY_WRITE_FAILED", "conflicts": [str(exc)],
                    "operation": state.merge_operation(merge_id)}
        try:
            state.update_merge(merge_id, "COMMITTED", actual_after)
        except Exception as exc:
            return {**plan, "result": "AUDIT_PENDING", "topology_changed": True,
                    "after_hash": actual_after, "operation_state": "PENDING",
                    "recovery_required": True, "audit_error": str(exc)}
        return {**plan, "result": "MERGED", "safe": True, "topology_changed": True,
                "after_hash": actual_after, "operation_state": "COMMITTED",
                "merge_id": merge_id, "audit_result": "RECORDED"}
    finally:
        if state is not None:
            state.close()


def merge_topology(config: Path, db: Path, source: str, survivor: str, *, dry_run=False) -> dict:
    """Plan or execute one explicit topology merge under the topology lock."""
    if dry_run:
        plan = plan_merge(config, db, source, survivor)
        plan["dry_run"] = True
        return plan
    lock_path = config.parent / ".netbot-topology.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _merge_locked(config, db, source, survivor)
