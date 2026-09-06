# Distribution

The public npm package is `@synrest/netbot`; the installed command is
`netbot`. npm is a thin bootstrap layer around the Python application.

```sh
npm install -g @synrest/netbot
```

Direct installation is also available from the immutable assets in the
[GitHub Releases](https://github.com/synrest/netbot/releases) page. For a
specific release, use its published `bootstrap.sh`, ZIP asset, and SHA-256
value:

```sh
curl -fsSL https://github.com/synrest/netbot/releases/download/v0.4.2/bootstrap.sh \
  | sh -s -- 0.4.2 \
      https://github.com/synrest/netbot/releases/download/v0.4.2/netbot-0.4.2.zip \
      <SHA256-from-the-release>
```

The bootstrap verifies the immutable ZIP and installs the Python application
under the user-level Netbot application root. Versioned applications are kept
alongside one another, `current` is switched atomically, and
`~/.local/bin/netbot` remains the stable launcher.

Topology, SQLite history, events, controller identity, SSH ownership records,
human SSH configuration, and scheduler configuration live outside the
replaceable application payload. Installation and upgrade do not run discovery,
reconciliation, proposal acceptance, or Tailscale operations.
