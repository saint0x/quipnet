# Schemas

This directory contains machine-readable production contracts for Quip.

Current schema groups:
- `state/`
  - durable network state validation targets
- `daemon/`
  - local daemon request/response envelope and operation response targets
- `events/`
  - runtime event validation targets

These schemas are intended to back:
- startup state validation
- migration tests
- daemon API integration tests
- CLI rendering tests
- runtime event assertions
- Fozzy scenario assertions

Concrete example payloads that should validate against these contracts live under [`../fixtures/`](../fixtures/README.md).
