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
development package may override the artifact with `NETBOT_RELEASE_ARTIFACT`
and `NETBOT_RELEASE_SHA256`; the package release metadata otherwise points to
the immutable version-specific GitHub asset and its trusted digest.

The same release ZIP can be installed without npm through the published
`bootstrap.sh VERSION IMMUTABLE_ZIP_URL SHA256` GitHub Release asset. That
path verifies the digest and delegates to the release's existing `install.sh
--no-service`, converging on the same versioned root and stable launcher.
