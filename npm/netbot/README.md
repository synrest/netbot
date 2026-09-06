# Netbot npm bootstrap

This package is a thin bootstrapper; the Netbot application remains Python.
The published package must provide immutable release metadata and a SHA-256
verified `netbot-<version>.zip` payload (matching the repository release
builder). Installation creates a private
user-level runtime under the existing Netbot application root, switches its
`current` symlink atomically, and maintains `~/.local/bin/netbot` as the stable
launcher. Topology, SQLite history, events, SSH configuration, and scheduler
artifacts are never removed or rewritten by an application upgrade.

The package does not install a scheduler, accept proposals, run discovery,
reconcile SSH, mutate Tailscale, or require sudo. The current unpublished
development package uses `NETBOT_RELEASE_ARTIFACT` and
`NETBOT_RELEASE_SHA256`; a published package will carry equivalent immutable
release metadata.
