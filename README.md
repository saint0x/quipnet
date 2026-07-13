# Quipnet

Quipnet is a production-oriented cryptographic peer fabric for identity-native, encrypted, topology-aware connectivity across direct, relayed, and future multipath transports.

This repository contains the Quipnet core workspace, protocol RFCs, deployment assets, and operational tooling defined in [PLAN.md](PLAN.md):

- architecture and protocol RFCs;
- canonical IDs, signed records, and membership primitives;
- a transport-neutral Rust workspace;
- daemon and operator CLIs;
- deterministic simulation tooling;
- deployment, release, and operational foundations.

The code takes the target architecture seriously and intentionally avoids compatibility shims that would distort the production design.

## Production Bootstrap Contract

Every real Quipnet node needs the same four inputs, regardless of whether it runs under systemd, Docker, Kubernetes, or Nix:

- a durable state path, usually `~/.quip/quicnet/state.json`
- a durable identity path, usually `~/.quip/quicnet/identity.json`
- an injected `QUICNET_IDENTITY_PASSPHRASE` secret
- an authority bootstrap source, usually `QUICNET_AUTHORITY_ORIGIN`

The deployment assets in [`deploy/`](deploy/) are wired around that contract. Production nodes should use durable storage for both state and identity, enable `--sync` and `--revocation-sync`, and inject the identity passphrase from a secret store rather than baking it into images.

For the concrete operator setup across systemd, Docker, Kubernetes, and Nix, see [docs/operator-deployment.md](docs/operator-deployment.md).
