# Scheduling

Netbot remains a bounded one-shot process. The native operating-system
scheduler invokes:

```sh
netbot maintain
```

Enable it explicitly:

```sh
netbot scheduler install
netbot scheduler status
netbot scheduler remove
```

The default interval is 30 minutes. macOS uses a user LaunchAgent under
`~/Library/LaunchAgents/`; Linux uses a user-level systemd timer when
available, with the supported fallback selected by the installer.

The scheduler stores an absolute stable launcher path and does not require an
interactive shell PATH. It does not install itself during application
installation or upgrade. Scheduled maintenance discovers and remembers facts,
reports proposals, and reconciles accepted topology only; it never
auto-accepts proposals or changes Tailscale.
