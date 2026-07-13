# Quip Production Readiness

This document defines the minimum release gate for calling Quip production-ready.

It is intentionally strict. A decentralized distributed network base layer is only production-ready when the runtime model, storage model, operator model, and verification model all agree with each other.

## Non-Negotiable Production Criteria

Quip is not production-ready unless all of the following are true:
- the daemon owns live runtime truth
- the CLI uses the daemon for runtime inspection and runtime mutation
- durable state is schema-validated and separated from runtime-only state
- operator workflows map to real commands instead of file-level guesswork
- authority behavior is enforceable, inspectable, and testable
- reconnect and path behavior are daemon-owned and restart-safe
- deployment assets reflect the real runtime model
- deterministic and replayable verification exists for the shipped behavior

## Runtime Ownership Gate

The runtime gate is passed only when:
- `quipd` is the single authority for live sessions
- `quipd` is the single authority for active path decisions
- runtime reconnect behavior is daemon-owned
- session close, upgrade, and reconcile go through the daemon API
- no persisted session snapshot is treated as current truth after restart

Fail this gate if the CLI can still present cached session state as though it were live runtime truth.

## Durable State Gate

The durable state gate is passed only when:
- `~/.quip/identity/node.json` and `~/.quip/net/state.json` are the canonical durable roots
- `~/.quip/net/state.json` has a defined schema version
- durable fields are explicitly allowlisted
- runtime-only fields are rejected from the durable schema
- migration behavior is explicit, validated, and tested
- network state can be reset without unintentionally rotating identity

Fail this gate if restart behavior still depends on persisted runtime handles or ambiguous on-disk state.

## Operator Surface Gate

The operator gate is passed only when the documented workflows are backed by real commands:
- status inspection
- runtime inspection
- session lifecycle control
- authority inspection and sync
- identity inspection
- durable state validation
- safe state reset

The command surface must stay honest about whether it is showing:
- live daemon-owned runtime state
- durable remembered state
- mismatch between the two

Fail this gate if operators still need undocumented file surgery for normal runtime control.

## Authority Gate

The authority gate is passed only when:
- authority origin and subject are inspectable
- authority sync status is inspectable
- membership and capability state are visible to operators
- revocation behavior is enforced in runtime behavior
- authority mismatch handling is diagnosable without guesswork

Fail this gate if membership denial, capability drift, or revocation can still be mistaken for a generic transport problem.

## Path And Reconnect Gate

The path/reconnect gate is passed only when:
- path selection is daemon-owned
- path history and live path state are clearly separated
- reconnect policy is explicit
- downgrade and upgrade behavior are explicit
- runtime explanations exist for why a path was chosen or abandoned

Fail this gate if path behavior is still a mix of metadata persistence and implicit runtime side effects.

## Deployment Gate

The deployment gate is passed only when:
- systemd, Docker, Kubernetes, and Nix all use the same node contract
- durable assets live under `~/.quip/{concern}/...` or the environment-specific equivalent
- secrets are injected rather than baked into images
- operator docs match the actual runtime surface

Fail this gate if deployment docs describe a cleaner model than the code actually implements.

## Verification Gate

The verification gate is passed only when:
- deterministic test coverage exists for the real runtime model
- restart behavior is tested
- authority reevaluation behavior is tested
- reconnect and path behavior are tested
- at least one real runtime trace is recorded and replay-verified
- the production command surface is validated through system-level scenarios

The concrete scenario and trace program for that gate is documented in [`docs/verification-plan.md`](./verification-plan.md).

## Fozzy Standard

The default production-readiness verification standard should use Fozzy first.

At minimum, the release gate should include:
- strict deterministic scenario validation
- replay verification of recorded traces
- CI-grade validation on recorded traces
- host-backed runs where feasible for real runtime behavior

A release is not production-ready if the verification only exercises unit tests while leaving runtime orchestration, authority behavior, or restart semantics unproven.

The machine-readable release verification expectations for this standard live in [`../verification/fozzy/release-gate.json`](../verification/fozzy/release-gate.json).

## Documentation Gate

The documentation gate is passed only when these documents still match the implementation:
- [`docs/network-foundation.md`](./network-foundation.md)
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/state-model.md`](./state-model.md)
- [`docs/state-schema.md`](./state-schema.md)
- [`docs/cli-surface.md`](./cli-surface.md)
- [`docs/operator-workflows.md`](./operator-workflows.md)
- [`docs/authority-operations.md`](./authority-operations.md)
- [`docs/backup-and-restore.md`](./backup-and-restore.md)

Fail this gate if the docs are cleaner than the shipped behavior.

## Final Rule

Quip is not production-ready because the naming is cleaner or the deployment files look finished.

Quip is production-ready only when the daemon-owned node model, durable schema, operator controls, and replayable validation are all true at the same time.
