# Quip Network Foundation

Quip exists to give us a real base layer for a decentralized distributed network.

That means the network cannot depend on one central app server being alive, one vendor owning the control plane, or one deployment shape being the "real" version while every other environment behaves differently. A Quip node should be able to run under a personal machine, a rented server, or an orchestrated production environment and still follow the same core model.

## What A Node Is

A Quip node is a long-lived network participant with:
- its own durable identity
- its own durable local network state
- a daemon that owns live runtime behavior
- transport paths that may be direct, relayed, or upgraded over time
- a policy and membership view that comes from signed authority data

The node is the unit of identity, connectivity, and recovery.

## What The Daemon Owns

`quipd` is the authority for live runtime behavior on a machine.

That includes:
- live sessions
- transport state
- path selection
- reconnect behavior
- runtime health
- reconciliation against durable state

The CLI should not pretend to own runtime truth when the daemon is the thing actually holding open sessions and managing network state transitions.

The production daemon control boundary is documented in [`docs/daemon-api.md`](./daemon-api.md).

## What Durable State Is For

Durable state is there so a node can restart without becoming a new node.

We split durable assets by concern:
- `~/.quip/identity/node.json` holds the node identity
- `~/.quip/net/state.json` holds durable network and control-plane state

We do not use nested product-name directories because they hide what the data is actually for. The layout should stay readable and stable even if the product surface changes.

## How Nodes Join The Same Network

Nodes do not join by talking to one magical central server.

They join by:
- loading their local identity
- loading durable local state
- bootstrapping from configured authority material
- learning membership and policy state
- discovering reachable peers and paths
- establishing encrypted connectivity directly or through relay infrastructure when needed

This is the foundation that lets higher-level services run on top of the network without rebuilding identity, membership, and connectivity rules in every application.

## Why Authority Exists

Quip is decentralized, but not directionless.

The authority layer exists so nodes can agree on:
- who is allowed into a network
- what identities and records are trusted
- what capabilities or roles a member has
- when access has been revoked

That data must be signed, distributable, and strong enough to drive runtime decisions. Otherwise every node turns into its own ad hoc trust policy engine and the network becomes impossible to operate safely.

## Why Relay Exists

Direct connectivity is not always possible.

Some nodes are behind NAT, some are unstable, and some network topologies simply will not permit clean direct sessions. Relay support is part of the real network, not an embarrassing fallback. The production architecture has to treat direct and relayed paths as first-class runtime choices managed by the same daemon-owned session model.

## What "Production" Means Here

For this repo, production means:
- one runtime model across environments
- durable state that survives restart
- explicit identity handling
- explicit authority bootstrap
- deterministic operational behavior
- deployment assets that reflect the real runtime model

It does not mean:
- compatibility hacks that preserve a broken layout
- local tooling that lies about runtime ownership
- docs that describe a different system from the one we deploy

## What Sits On Top Of This

The point of Quip is not just to have a networking project.

The point is to create a dependable base that higher-level distributed systems can use for:
- peer-to-peer application traffic
- replicated state distribution
- private service meshes
- operator-controlled membership networks
- decentralized coordination layers

If this layer is clean, durable, and predictable, everything above it gets easier to build.

The durable-versus-runtime state contract behind that predictability is documented in [`docs/state-model.md`](./state-model.md).
