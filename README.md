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
