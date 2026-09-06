# Netbot architecture

Netbot is a deterministic, single-controller application. Its main cycle is:

```text
observe -> discover -> remember -> propose -> accept (human) -> reconcile
```

Discovery builds current observations and durable evidence. Proposals are
derived from that evidence, but only an explicit operator action can change
accepted topology. The reconciler consumes accepted topology, never raw
discovery evidence.

The durable layers remain separate:

1. Current observation
2. Durable evidence and history
3. Accepted/desired topology
4. Netbot-managed SSH projection

The controller uses Tailscale for provider identity and peer observation, and
OpenSSH for effective configuration and bounded agentless inspection. Remote
inspection is read-only and uses existing non-interactive SSH access.

Human SSH configuration remains authoritative for human entries. Netbot only
writes its explicitly owned managed projection on authorized targets.

Netbot has no cloud service, resident managed-host agent, password store, or
AI dependency.
