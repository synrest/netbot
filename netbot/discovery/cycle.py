"""One-shot, single-controller Discovery V1 cycle."""

from __future__ import annotations

import fcntl
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .provider import TailscaleProvider
from .seed import discover_local_ssh
from .crawl import RemoteSSHSeedObserver, crawl
from .crawl import NodeObservation
from ..state import State


def run_cycle(config_path: Path, db_path: Path, *, home: Path | None = None,
              runtime: Path | None = None, dry_run: bool = False,
              provider: Any | None = None,
              runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    home = home or Path.home()
    runtime = runtime or (db_path.parent / "run")
    runtime.mkdir(parents=True, exist_ok=True)
    lock_path = runtime / "cycle.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"cycle_id": None, "controller_id": None, "status": "BLOCKED",
                    "reason": "another discovery cycle is already running", "dry_run": dry_run,
                    "provider": {"name": "tailscale", "peers": []},
                    "ssh": {"human_aliases": [], "managed_aliases": [], "includes": [],
                            "known_hosts": {"status": "not-run"}, "unresolved_provider_peers": []}}

        cycle_id = uuid.uuid4().hex
        state = State(db_path)
        controller_id = state.controller_identity()
        state.close()
        started_at = datetime.now(timezone.utc).isoformat()
        provider = provider or TailscaleProvider()
        peers, provider_error = provider.observe()
        ssh = discover_local_ssh(home, peers, runner=runner or subprocess.run)
        graph = crawl(controller_id, ssh, RemoteSSHSeedObserver(runner=runner or subprocess.run))
        for peer in peers:
            key = f"{peer.provider}:{peer.provider_node_id}" if peer.provider_node_id else f"peer:{peer.advertised_name}"
            graph.add_node(NodeObservation(key, controller_id, (), (peer.as_dict(),)))
        crawl_status = "BUDGET_EXHAUSTED" if graph.truncated else (
            "PARTIAL" if any(source.get("status") != "OBSERVED" for source in graph.sources) else "COMPLETE")
        status = "PARTIAL" if provider_error or crawl_status != "COMPLETE" else "OK"
        local_peer = next((peer.as_dict() for peer in peers
                           if peer.metadata.get("_netbot_self")), None)
        result = {"cycle_id": cycle_id, "controller_id": controller_id, "dry_run": dry_run,
                  "status": status,
                  "controller": local_peer,
                  "provider": {"name": provider.name, "error": provider_error,
                               "peers": [peer.as_dict() for peer in peers]},
                  "ssh": ssh, "crawl": graph.as_dict()}
        if not dry_run:
            try:
                state = State(db_path)
                state.record_discovery_cycle(
                    cycle_id, controller_id, started_at, datetime.now(timezone.utc).isoformat(),
                    status, "FAILED" if provider_error else "OK", crawl_status,
                    graph.reason, graph.as_dict(), [peer.as_dict() for peer in peers])
                state.close()
            except Exception as exc:
                try:
                    state.close()
                except Exception:
                    pass
                result["status"] = "PERSISTENCE_FAILED"
                result["persistence_error"] = str(exc)
        return result
