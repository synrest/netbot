"""Read-only local Tailscale IPN wake watcher."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from .sync import run_sync

MAX_BACKOFF = 30.0
DEBOUNCE_SECONDS = 1.0


class JSONStreamDecoder:
    """Incrementally decode concatenated JSON values from arbitrary chunks."""
    def __init__(self):
        self.decoder = json.JSONDecoder()
        self.buffer = ""

    def feed(self, chunk: str) -> list[object]:
        self.buffer += chunk
        values = []
        while self.buffer.strip():
            stripped = self.buffer.lstrip()
            try:
                value, end = self.decoder.raw_decode(stripped)
            except json.JSONDecodeError:
                # A stream chunk may end anywhere, including inside a quoted
                # string or number. Keep it until another chunk arrives.
                break
            values.append(value)
            self.buffer = stripped[end:]
        return values

    def finish(self) -> None:
        if self.buffer.strip():
            raise ValueError("incomplete or malformed JSON stream")


def next_backoff(current: float, connected_seconds: float) -> float:
    """Back off failed/restarting watches without creating a restart storm."""
    if connected_seconds >= 10.0:
        return 1.0
    return min(current * 2, MAX_BACKOFF)


def relevant(notification: dict) -> bool:
    """Return true only for peer/netmap-shaped notifications."""
    if not isinstance(notification, dict):
        return False
    return bool(notification.get("PeersChanged") or
                notification.get("PeersRemoved") or
                notification.get("PeerChangedPatch") or
                notification.get("NetMap"))


def watch(config: Path, db: Path, home: Path, generated: Path,
          command: str = "tailscale") -> None:
    backoff = 1.0
    while True:
        try:
            proc = subprocess.Popen(
                [command, "debug", "watch-ipn", "--peer-changes", "--peer-patches"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except OSError as exc:
            print(f"netbot-watch degraded: {exc}", file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)
            continue
        connected_at = time.monotonic()
        last_wake = 0.0
        parser = JSONStreamDecoder()
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if line.strip() == "Connected.":
                    continue
                for notification in parser.feed(line):
                    now = time.monotonic()
                    if relevant(notification) and now - last_wake >= DEBOUNCE_SECONDS:
                        last_wake = now
                        print(f"netbot-watch ipn-wake epoch={time.time():.6f}", flush=True)
                        run_sync(config, db, home, generated, reason="ipn")
            try:
                parser.finish()
            except ValueError as exc:
                print(f"netbot-watch degraded: {exc}", file=sys.stderr, flush=True)
            returncode = proc.wait()
            if returncode:
                print(f"netbot-watch degraded: tailscale watcher exited {returncode}",
                      file=sys.stderr, flush=True)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()
        connected_seconds = time.monotonic() - connected_at
        backoff = next_backoff(backoff, connected_seconds)
        time.sleep(backoff)


def main() -> None:
    watch(Path("config/topology.yaml"), Path("state/netbot.sqlite3"),
          Path.home(), Path("generated/topology.json"))


if __name__ == "__main__":
    main()
