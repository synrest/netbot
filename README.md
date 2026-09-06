# Netbot

**Know your network. Keep it consistent.**

Netbot is an agentless topology discovery and SSH reconciliation tool for
private networks.

It discovers machines and relationships from Tailscale and OpenSSH evidence,
builds a persistent view of the network, detects meaningful changes, and keeps
Netbot-managed SSH configuration consistent across authorized hosts.

**No agents on managed machines. No cloud service. No AI required.**

## Why Netbot?

Private networks accumulate machines, VMs, changing addresses, Tailscale
identities, SSH aliases, stale configuration, and relationships that exist only
in someone's memory.

Netbot turns that administrative evidence into a durable topology. It can show
what it sees, what changed, what is unreachable, what has not been accepted,
and what SSH state would need reconciliation.

Netbot is deliberately conservative: discovering something does not give it
permission to manage that thing.

## What it does

- Discovers nodes from Tailscale and existing SSH configuration.
- Follows existing public-key SSH relationships to inspect reachable peers
  without installing agents.
- Builds durable topology evidence and observation history.
- Distinguishes observed infrastructure from explicitly accepted topology.
- Detects new, missing, unavailable, and conflicting nodes.
- Proposes topology changes without silently accepting them.
- Reconciles Netbot-owned SSH configuration across authorized hosts.
- Preserves human-owned SSH configuration.
- Records meaningful events and recovery transitions.
- Runs manually or periodically from a single controller.

The important distinction is:

    OBSERVED != ACCEPTED
    CAN ACCESS != CAN MANAGE

## Install

### npm

```sh
npm install -g @synrest/netbot
```

The npm package is a thin bootstrapper. Netbot itself is installed as a
verified, versioned Python application while the command remains available
through `~/.local/bin/netbot`.

### GitHub Release

Versioned release archives are also published through
[GitHub Releases](https://github.com/synrest/netbot/releases). They use the
same verified runtime layout as the npm bootstrap. See
[distribution details](docs/distribution.md) for the direct bootstrap command.

Installing or upgrading Netbot does not automatically start periodic
maintenance.

## Start here

Inspect Netbot's current view:

```sh
netbot status
```

See what a maintenance cycle would observe and reconcile without applying
changes:

```sh
netbot maintain --dry-run
```

Inspect operator events:

```sh
netbot events
```

Run one maintenance cycle:

```sh
netbot maintain
```

Enable periodic maintenance explicitly:

```sh
netbot scheduler install
netbot scheduler status
```

The default scheduled interval is 30 minutes.

## How it works

Netbot normally runs on one controller:

```text
                         Netbot
                       controller
                           |
                   Tailscale + SSH
                           |
              +------------+------------+
              |            |            |
              v            v            v
            host A       host B       host C
            no agent     no agent     no agent
```

The controller observes network identity and SSH relationships, maintains
accepted topology and evidence history, and projects authorized topology into
Netbot-owned SSH configuration. Managed hosts remain ordinary machines using
ordinary OpenSSH and Tailscale; they do not need a resident Netbot agent.

Netbot separates four questions:

1. What has been observed?
2. What identity does the evidence belong to?
3. What topology has the operator accepted?
4. What state is Netbot authorized to manage?

This prevents visibility or SSH reachability from silently becoming management
authority.

## Safety model

- Observation does not imply acceptance.
- Knowing about a host does not imply SSH access.
- SSH access does not imply management authority.
- Discovery never silently changes accepted topology.
- Netbot never stores, requests, or guesses passwords.
- Netbot does not overwrite human-owned SSH configuration.
- Netbot does not mutate Tailscale configuration.
- Installation does not silently enable scheduled maintenance.
- Dry-run operations do not persist operational mutations.

Netbot owns only the state explicitly assigned to it.

## Scheduling

`netbot maintain` is a bounded one-shot command. Scheduling is an explicit
operator decision:

```sh
netbot scheduler install
```

The default interval is 30 minutes. macOS uses a user LaunchAgent; supported
Linux installations use the appropriate user-level scheduling integration.
Application upgrades keep the stable launcher, so the scheduler does not need
to be recreated for every release. See [scheduling details](docs/scheduling.md).

## Requirements

- macOS or Linux
- Python 3.10+
- OpenSSH client
- Tailscale

Node.js/npm is required only for the npm installation path. Netbot does not
install or configure Tailscale automatically.

## Development

For development from a repository checkout:

```sh
./install.sh --dev
```

Production installations do not require the Git checkout afterward. For
implementation details, see [architecture](docs/architecture.md) and the
supporting distribution and scheduling documentation.
