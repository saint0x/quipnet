# Quip

Quip is the base layer for our decentralized distributed network.

This repository is where we build the core node, daemon, transport, identity, routing, and deployment foundation that lets independently run machines join the same network without depending on a centralized application server. The goal is simple: every node should be able to identify itself, discover peers, establish encrypted connectivity, exchange signed state, and keep operating across direct and relayed paths in a way we can actually ship and run in production.

The plain-language architecture overview is in [docs/network-foundation.md](docs/network-foundation.md).

## What This Repo Is For

This repo is the production foundation for:
- node identity and local keystore handling
- daemon-managed network state
- direct and relay connectivity
- peer and route selection
- authority and membership distribution
- operator tooling
- deployment targets for real environments

In practice, this is the codebase that turns "we want a decentralized network" into something concrete we can run, debug, deploy, and evolve.

## What A Node Needs

Every Quip node needs the same core inputs:
- durable network state at `~/.quip/net/state.json`
- durable node identity at `~/.quip/identity/node.json`
- an injected `QUIP_IDENTITY_PASSPHRASE`
- an authority bootstrap source, usually `QUIP_AUTHORITY_ORIGIN`

We use the same contract across local development, systemd, Docker, Kubernetes, and Nix so the runtime model stays consistent instead of drifting by environment.

## Storage Layout

All durable local node data belongs under `~/.quip/`.

The minimum durable split is:
- `~/.quip/identity/node.json`
- `~/.quip/net/state.json`

We do not want product-nested layouts like `~/.quip/product/`. Storage is organized by concern, not by legacy product name.

The full storage contract is in [docs/storage-layout.md](docs/storage-layout.md).
Backup and restore handling is in [docs/backup-and-restore.md](docs/backup-and-restore.md).

## Deployment

The deploy assets in [`deploy/`](deploy/) are built around the same node contract:
- the same durable identity path
- the same durable network state path
- the same bootstrap environment variables
- the same daemon-first runtime model

Operator deployment guidance lives in [docs/operator-deployment.md](docs/operator-deployment.md).
Operator procedures live in [docs/operator-workflows.md](docs/operator-workflows.md).
Authority inspection and mismatch handling live in [docs/authority-operations.md](docs/authority-operations.md).
The daemon/runtime control boundary lives in [docs/daemon-api.md](docs/daemon-api.md).
The durable-versus-runtime state boundary lives in [docs/state-model.md](docs/state-model.md).
The allowed durable on-disk network schema lives in [docs/state-schema.md](docs/state-schema.md).
The intended operator command surface lives in [docs/cli-surface.md](docs/cli-surface.md).
The release gate for calling this production-ready lives in [docs/production-readiness.md](docs/production-readiness.md).
The concrete verification program lives in [docs/verification-plan.md](docs/verification-plan.md).
The architecture-to-implementation bridge lives in [docs/implementation-map.md](docs/implementation-map.md).
The execution phases for finishing production work live in [docs/milestones.md](docs/milestones.md).
The concrete daemon request/response contract lives in [docs/daemon-api-schema.md](docs/daemon-api-schema.md).
The final ship gate checklist lives in [docs/release-checklist.md](docs/release-checklist.md).
Core runtime behavior details live in [docs/runtime-lifecycle.md](docs/runtime-lifecycle.md), [docs/authority-reevaluation.md](docs/authority-reevaluation.md), and [docs/path-and-reconnect.md](docs/path-and-reconnect.md).
Concrete control and data examples live in [docs/daemon-api-examples.md](docs/daemon-api-examples.md), [docs/state-schema-example.md](docs/state-schema-example.md), and [docs/runtime-events.md](docs/runtime-events.md).
Machine-readable validation targets live under [schemas/README.md](/Users/deepsaint/Desktop/quipnet/schemas/README.md).
Machine-readable verification assets live under [verification/fozzy/README.md](/Users/deepsaint/Desktop/quipnet/verification/fozzy/README.md).

## Repository Shape

This repository includes:
- core Rust crates for identity, transport, routing, policy, control, and fabric behavior
- the `quip` operator CLI
- the `quipd` daemon
- relay and supporting command surfaces
- deployment and release assets
- the production work plan in [PLAN.md](PLAN.md)
- the remaining production checklist in [checklist.md](checklist.md)

## Development Direction

We are intentionally building this the production way:
- no fake compatibility layers
- no legacy layout preservation
- no split-brain between local tooling and deployed runtime behavior

If a design choice makes the real network harder to reason about or operate, it should be fixed here instead of hidden behind a shim.
