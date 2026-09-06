"""One-shot, single-controller Discovery V1 cycle."""

from __future__ import annotations

import fcntl
import subprocess
import uuid
from pathlib import Path
from typing import Any, Callable

from .provider import TailscaleProvider
from .seed import discover_local_ssh
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
        provider = provider or TailscaleProvider()
        peers, provider_error = provider.observe()
        ssh = discover_local_ssh(home, peers, runner=runner or subprocess.run)
        status = "PARTIAL" if provider_error else "OK"
        local_peer = next((peer.as_dict() for peer in peers
                           if peer.metadata.get("_netbot_self")), None)
        result = {"cycle_id": cycle_id, "controller_id": controller_id, "dry_run": dry_run,
                  "status": status,
                  "controller": local_peer,
                  "provider": {"name": provider.name, "error": provider_error,
                               "peers": [peer.as_dict() for peer in peers]},
                  "ssh": ssh}
        if not dry_run:
            state = State(db_path)
            rows = [{"identity": peer.advertised_name, "provider": peer.provider,
                     "provider_node_id": peer.provider_node_id, "addresses": peer.addresses,
                     "online": peer.online, "status": "present"} for peer in peers]
            if rows:
                state.observations(cycle_id, rows)
            state.close()
        return result
