"""Single-flight entry point for all reconciliation wake sources."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Callable

from .reconcile import generate, reconcile

REASONS = {"manual", "launch", "calendar", "ipn", "followup"}


def runtime_directory(home: Path) -> Path:
    """Return local runtime state; it is intentionally outside the repository."""
    return home / "Library" / "Application Support" / "Netbot" / "run"


def run_sync(config: Path, db: Path, home: Path, generated: Path,
             reason: str = "manual", runtime: Path | None = None,
             reconcile_fn: Callable = reconcile,
             generate_fn: Callable = generate) -> dict:
    if reason not in REASONS:
        raise ValueError(f"unknown sync reason: {reason}")
    runtime = runtime or runtime_directory(home)
    runtime.mkdir(parents=True, exist_ok=True)
    lock_path = runtime / "sync.lock"
    pending_path = runtime / "sync.pending"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pending_path.write_text("pending\n")
            return {"state": "coalesced", "reason": reason, "pending": True}

        runs = []
        next_reason = reason
        while True:
            result = reconcile_fn(config, db, home, next_reason)
            generate_fn(result, generated)
            runs.append({"reason": next_reason, "run_id": result["run_id"],
                         "observer_status": result["observer_status"]})
            if not pending_path.exists():
                break
            try:
                pending_path.unlink()
            except FileNotFoundError:
                break
            next_reason = "followup"
        return {"state": "completed", "runs": runs,
                "followup": len(runs) > 1}
