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

Netbot v1 has a hard dependency on Tailscale. Tailscale supplies network identity, peer/topology observation, connectivity, and the primary event wake source. The canonical runtime is `Tailscale IPN -> netbot-watch -> netbot sync -> deterministic reconciliation`; `netbot sync` is the universal explicit entry point.

`netbot-watch` is an optional local Tailscale IPN wake hint. It requests `netbot sync --reason ipn` after peer/netmap notifications, using a one-second debounce, and never treats those notifications as authoritative state. Tailscale is the only supported networking provider in v1. Alternative providers such as ZeroTier are future research only and must provide stable node identity, peer/topology observation, connectivity, and a useful local change mechanism.

Service managers are deployment/process-lifetime adapters, not core Netbot architecture. Netbot remains runnable without launchd, systemd, or OpenRC through `netbot sync` and `netbot-watch`. The current macOS launchd integration is supported for login/reboot startup, watcher crash restart, and the optional `:00`/`:30` correctness fallback; periodic scheduling is not required for core correctness.

Phase 7 launchd artifacts are provided as a macOS deployment adapter. Production installation installs only the watcher LaunchAgent using the safe supervision contract; the legacy `com.netbot.sync` `:00`/`:30` job is not installed by default. Service managers are not part of the reconciliation core.

The retired local webhook spike measured approximately 15 MB RSS for a persistent receiver and approximately 32 MB for the Python-plus-Tailscale IPN wrapper. It confirmed that a public HTTP/Funnel path is unnecessary for local discovery; IPN is an optimization and calendar/manual sync remain the correctness paths.

Phase 1 performs no remote SSH commands and no Tailscale writes. It reads the local SSH configuration and public-key metadata only.

The supported Python baseline is 3.10+. SSH access probes are explicit (`netbot access` or `netbot inspect HOST --probe`); routine status and reconciliation do not probe remote hosts.

Netbot 0.2.0 supports two deployment modes. For development, clone the repository and run `./install.sh --dev`. For production, unpack a versioned `netbot-X.Y.Z.zip` and run `./install.sh`; Git and the extracted source tree are not required afterward. The installer keeps a private per-user runtime under `~/Library/Application Support/Netbot/`, with stable wrappers in `~/.local/bin/`, so users do not need to activate a virtual environment or configure import paths.

Production installation preserves `config/topology.yaml` and `state/netbot.sqlite3` outside versioned runtime directories. Reinstalling switches the private runtime without deleting desired topology or history. `./uninstall.sh` removes only Netbot runtime integration, wrappers, installed versions, transient runtime files, and logs; it retains configuration and state, the user's SSH configuration/keys, Tailscale, and remote hosts.

Use `netbot --version`, `netbot doctor`, and `netbot service status` to verify an installation. The v1 external requirements are Python >= 3.10, the Tailscale CLI, and the OpenSSH client; macOS service integration additionally requires launchd/launchctl. Netbot does not install Tailscale automatically.

`agent-temporary` remains a separate project and lifecycle. Netbot does not require it for OBSERVE or MANAGE. It is optional target-side infrastructure for bounded MAINTAIN authority after explicit human activation; Netbot may observe and lower that authority but never raises it or activates it.

Release archives are built with `./scripts/build-release.sh` and produce `dist/netbot-X.Y.Z.zip` plus a SHA-256 sidecar. Archives exclude Git metadata, caches, local databases, generated output, logs, virtual environments, and private credentials. `agent-temporary` is never bundled.

`netbot agent status HOST` performs a read-only SSH observation of agent-temporary and effective `sudo -n -l`. It does not enable, disable, or execute privileged commands.

`netbot enroll` is informational only. It prints the canonical human-run Tailscale enrollment hints and performs no network, topology, or state operation. Bootstrap planning requires an explicit target Unix user; Netbot never infers that user from a hostname or topology identity.

Bootstrap access and topology identity are separate lifecycles. `MANAGED` means permanent OpenSSH access and host identity were verified; it does not adopt an unbound node into desired topology. Tailscale node IDs anchor observed bootstrap history but never create a topology binding by themselves.

Explicit topology adoption is planned with `netbot adopt plan OBSERVED-NODE --as TOPOLOGY-ID` and applied with `netbot adopt apply OBSERVED-NODE --as TOPOLOGY-ID`. Apply reobserves the node and changes only topology intent; it does not reprovision SSH, Tailscale, privilege, or the machine itself.
