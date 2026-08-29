# Netbot

Netbot is a small, deterministic, read-only topology reconciler. Desired topology lives in `config/topology.yaml`; SQLite stores observations and reconciliation history as a rebuildable cache.

## Usage

```sh
python3 -m netbot.cli topology
python3 -m netbot.cli discover
python3 -m netbot.cli diff
python3 -m netbot.cli reconcile
python3 -m netbot.cli status
python3 -m netbot.cli inspect orion
python3 -m netbot.cli agent status orion
python3 -m netbot.cli enroll
```

The default database is `state/netbot.sqlite3` and generated output is `generated/topology.json`. Override paths with `--config`, `--db`, and `--generated`.

Phase 1 performs no remote SSH commands and no Tailscale writes. It reads the local SSH configuration and public-key metadata only.

The supported Python baseline is 3.10+. SSH access probes are explicit (`netbot access` or `netbot inspect HOST --probe`); routine status and reconciliation do not probe remote hosts.

`netbot agent status HOST` performs a read-only SSH observation of agent-temporary and effective `sudo -n -l`. It does not enable, disable, or execute privileged commands.

`netbot enroll` is informational only. It prints the canonical human-run Tailscale enrollment hints and performs no network, topology, or state operation. Bootstrap planning requires an explicit target Unix user; Netbot never infers that user from a hostname or topology identity.

Bootstrap access and topology identity are separate lifecycles. `MANAGED` means permanent OpenSSH access and host identity were verified; it does not adopt an unbound node into desired topology. Tailscale node IDs anchor observed bootstrap history but never create a topology binding by themselves.

Explicit topology adoption is planned with `netbot adopt plan OBSERVED-NODE --as TOPOLOGY-ID` and applied with `netbot adopt apply OBSERVED-NODE --as TOPOLOGY-ID`. Apply reobserves the node and changes only topology intent; it does not reprovision SSH, Tailscale, privilege, or the machine itself.
