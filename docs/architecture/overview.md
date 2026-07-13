# Architecture Overview

Quipnet is layered as identity and membership, routing intelligence, delivery semantics, and application protocols.

## Production Boundaries

- `model`, `crypto`, `identity`, `membership`, and `records` define the trust substrate.
- `transport`, `quic`, `routing`, `relaywire`, and `relay` define reachability and movement across paths.
- `protocol`, `policy`, `fabric`, and the `cmd/` binaries define the stable operator and application surfaces.
- `testkit` and `tests/` provide deterministic simulation, fuzzing, and scenario coverage.

## Architectural Rule

The control plane distributes signed state and policy. The data plane carries encrypted peer traffic directly whenever possible and falls back to relays only when needed or explicitly allowed.

