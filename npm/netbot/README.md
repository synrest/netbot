# Netbot

Know your network. Keep it consistent.

Netbot is an agentless topology discovery and SSH reconciliation tool for
private networks.

It discovers machines and relationships from Tailscale and SSH evidence,
builds a persistent view of your topology, detects meaningful changes, and
keeps Netbot-managed SSH configuration consistent across authorized hosts.

No agents on managed machines. No cloud service. No AI required.

## Install

```sh
npm install -g @synrest/netbot
```

Then:

```sh
netbot status
netbot maintain --dry-run
netbot events
```

## What Netbot does

- Discovers machines from Tailscale and existing SSH configuration
- Recursively inspects SSH-reachable peers without installing remote agents
- Builds durable topology evidence and history
- Detects new machines, conflicts, drift, failures, and recoveries
- Proposes topology changes instead of silently accepting them
- Reconciles Netbot-owned SSH configuration across authorized hosts
- Runs manually or periodically through native OS scheduling

## Safety model

Discovery is not authority.

Finding a machine does not automatically:

- add it to the accepted topology
- grant SSH access
- authorize Netbot to manage it
- modify Tailscale
- modify human-owned SSH configuration

Netbot only reconciles explicitly managed state. Scheduled maintenance never
automatically accepts topology proposals.

## Platforms

Netbot supports macOS and Linux. Python 3.10 or newer is required for the
runtime. npm is one installation path; Netbot itself remains a Python
application.

## Direct installation

Netbot can also be installed without npm from its immutable, versioned
[GitHub Releases](https://github.com/synrest/netbot/releases). The release
asset includes a direct bootstrap script. For a specific release, use the
bootstrap script, that release's `netbot-<version>.zip`, and the SHA-256 value
published with that release:

```sh
curl -fsSL https://github.com/synrest/netbot/releases/download/v0.4.4/bootstrap.sh \
  | sh -s -- 0.4.4 \
      https://github.com/synrest/netbot/releases/download/v0.4.4/netbot-0.4.4.zip \
      <SHA256-from-the-release>
```

## Upgrading

For npm installations:

```sh
npm install -g @synrest/netbot@latest
```

Netbot upgrades preserve durable topology, evidence/history, events, SSH
configuration, controller identity, and scheduler state.

## Scheduling

Periodic maintenance is optional and uses the native scheduler for your OS:

```sh
netbot scheduler install
netbot scheduler status
netbot scheduler remove
```

Installing or upgrading Netbot does not enable scheduling, accept topology
proposals, or run reconciliation automatically.

## Installation integrity

Releases use immutable versioned ZIP artifacts whose SHA-256 is verified before
installation. Application versions are installed side by side, activation
uses the stable Netbot launcher, and upgrades preserve durable user state.
