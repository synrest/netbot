# Netbot

Netbot is a small, deterministic, read-only topology reconciler. Desired topology lives in `config/topology.yaml`; SQLite stores observations and reconciliation history as a rebuildable cache.

## Usage

```sh
python3 -m netbot.cli topology
python3 -m netbot.cli discover
python3 -m netbot.cli diff
python3 -m netbot.cli reconcile
python3 -m netbot.cli sync
python3 -m netbot.cli status
python3 -m netbot.cli inspect orion
python3 -m netbot.cli agent status orion
python3 -m netbot.cli enroll
```

The default database is `state/netbot.sqlite3` and generated output is `generated/topology.json`. Override paths with `--config`, `--db`, and `--generated`.

`netbot sync` is the canonical reconciliation command; `--reason` accepts `manual`, `launch`, `calendar`, `ipn`, or `followup` for diagnostics only. Concurrent wake requests use a single-flight lock under `~/Library/Application Support/Netbot/run/`; one pending follow-up is coalesced after the active sync. The lock is an OS file lock and is released automatically if the process exits.

`netbot-watch` is an optional local Tailscale IPN wake hint. It requests `netbot sync --reason ipn` after peer/netmap notifications, using a one-second debounce, and never treats those notifications as authoritative state. Periodic launchd reconciliation remains the correctness fallback. Access lifecycle and topology identity remain independent.

Phase 7 launchd artifacts are generated but not installed: `launchd/com.netbot.sync.plist` runs at load and at minutes 0 and 30; `launchd/com.netbot.watch.plist` runs the optional resident watcher. Install only after review with `mkdir -p "$HOME/Library/Logs/Netbot"` followed by `launchctl bootstrap gui/$(id -u) ...`; no install/load is performed by the project.

The retired local webhook spike measured approximately 15 MB RSS for a persistent receiver and approximately 32 MB for the Python-plus-Tailscale IPN wrapper. It confirmed that a public HTTP/Funnel path is unnecessary for local discovery; IPN is an optimization and calendar/manual sync remain the correctness paths.

Phase 1 performs no remote SSH commands and no Tailscale writes. It reads the local SSH configuration and public-key metadata only.

The supported Python baseline is 3.10+. SSH access probes are explicit (`netbot access` or `netbot inspect HOST --probe`); routine status and reconciliation do not probe remote hosts.

`netbot agent status HOST` performs a read-only SSH observation of agent-temporary and effective `sudo -n -l`. It does not enable, disable, or execute privileged commands.

`netbot enroll` is informational only. It prints the canonical human-run Tailscale enrollment hints and performs no network, topology, or state operation. Bootstrap planning requires an explicit target Unix user; Netbot never infers that user from a hostname or topology identity.

Bootstrap access and topology identity are separate lifecycles. `MANAGED` means permanent OpenSSH access and host identity were verified; it does not adopt an unbound node into desired topology. Tailscale node IDs anchor observed bootstrap history but never create a topology binding by themselves.

Explicit topology adoption is planned with `netbot adopt plan OBSERVED-NODE --as TOPOLOGY-ID` and applied with `netbot adopt apply OBSERVED-NODE --as TOPOLOGY-ID`. Apply reobserves the node and changes only topology intent; it does not reprovision SSH, Tailscale, privilege, or the machine itself.
