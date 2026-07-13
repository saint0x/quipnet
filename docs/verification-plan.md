# Quip Verification Plan

This document defines the minimum verification program for Quip before a production release.

It complements:
- [`docs/production-readiness.md`](./production-readiness.md)
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/state-model.md`](./state-model.md)
- [`docs/state-schema.md`](./state-schema.md)
- [`docs/cli-surface.md`](./cli-surface.md)

The goal is not broad test volume for its own sake. The goal is to prove that the real daemon-owned node model behaves correctly under restart, authority change, path change, and operator control.

## Verification Principles

Production verification must prove:
- runtime truth is daemon-owned
- durable state survives restart honestly
- runtime-only state is not falsely restored from disk
- authority changes affect runtime behavior correctly
- path and reconnect logic behave deterministically under known scenarios
- operator commands reflect the documented CLI surface

## Required Fozzy Modes

The default verification program should use Fozzy first.

Minimum required command classes:
- deterministic scenario doctor runs
- deterministic strict scenario tests
- recorded trace runs
- trace verification
- trace replay
- CI-style trace validation
- host-backed runs where feasible

The machine-readable scenario catalog, trace requirements, and release-gate manifest for this plan live under [`../verification/fozzy/`](../verification/fozzy/README.md).

## Scenario Set

The minimum release scenario set should include:

### 1. Clean Bootstrap

Proves:
- a node can start from valid durable identity and durable network state
- daemon health and status reporting are correct
- authority bootstrap succeeds

Expected focus:
- startup
- status inspection
- authority visibility

### 2. Restart With Preserved Identity

Proves:
- identity persists across restart
- durable network state remains valid
- runtime sessions are not falsely restored as live handles

Expected focus:
- stop/start behavior
- durable-versus-runtime boundary
- post-restart runtime inspection

### 3. Network State Reset With Preserved Identity

Proves:
- `net/state.json` can be reset without rotating identity
- the node rejoins as the same logical participant
- stale runtime ownership is not recovered from disk

Expected focus:
- reset semantics
- re-bootstrap
- authority rejoin behavior

### 4. Authority Sync And Membership Update

Proves:
- authority sync status is visible
- accepted authority facts are updated durably
- runtime behavior reevaluates against changed authority state

Expected focus:
- sync behavior
- membership visibility
- runtime reevaluation

### 5. Revocation Enforcement

Proves:
- revocation changes propagate into runtime behavior
- stale trust is not silently retained
- operator-visible diagnostics explain the result

Expected focus:
- revocation
- session closure or denial
- authority mismatch diagnosis

### 6. Capability Change

Proves:
- capability changes affect runtime behavior correctly
- durable accepted facts and runtime enforcement stay aligned

Expected focus:
- authority-driven policy drift
- runtime reevaluation

### 7. Direct Path Success

Proves:
- direct path establishment works
- active path selection is visible through runtime inspection

Expected focus:
- session connect
- runtime path reporting

### 8. Relay Fallback

Proves:
- the node can use relay when direct connectivity is not viable
- runtime path ownership remains daemon-controlled

Expected focus:
- relay selection
- operator visibility into chosen path

### 9. Path Migration

Proves:
- active path can change without corrupting session ownership
- runtime state reflects migration honestly

Expected focus:
- path transitions
- runtime explanation

### 10. Reconnect After Drop

Proves:
- reconnect policy is daemon-owned
- retry behavior is deterministic under scenario control
- stale sessions are not treated as healthy durable state

Expected focus:
- drop detection
- reconnect lifecycle
- operator diagnostics

This scenario should explicitly validate the runtime behavior documented in [`docs/path-and-reconnect.md`](./path-and-reconnect.md) and [`docs/runtime-lifecycle.md`](./runtime-lifecycle.md).

### 11. Durable State Validation Failure

Proves:
- invalid or unexpected durable fields are rejected
- schema enforcement works
- migration or validation errors are visible to operators

Expected focus:
- state schema validation
- startup rejection path

### 12. Backup And Restore

Proves:
- a backed-up node can be restored as the same logical participant
- identity restore and network restore semantics remain distinct from identity rotation

Expected focus:
- restore workflow
- post-restore runtime correctness

## Required Trace Set

At minimum, production readiness should include recorded traces for:
- clean bootstrap
- restart with preserved identity
- authority revocation handling
- reconnect after drop
- relay fallback or path migration

Each recorded trace should be:
- verified
- replayed
- CI-validated

## Host-Backed Expectations

Where feasible, verification should include host-backed runs for:
- filesystem-backed durable state behavior
- process lifecycle behavior
- local daemon/operator command interaction
- network behavior that benefits from real host execution

Host-backed verification matters because some failure modes only appear when real process and file boundaries exist.

Where possible, verification should also validate implementation output against the machine-readable contracts under [`schemas/`](../schemas/).
The validation set should also use the example fixtures under [`../fixtures/`](../fixtures/README.md) for positive and negative contract checks.

## CLI Verification Targets

The verification program must cover at least:
- `quip status`
- runtime inspection commands
- session lifecycle commands
- authority inspection and sync commands
- identity inspection commands
- durable state validation and reset commands

The goal is to prove that the real operator surface matches [`docs/cli-surface.md`](./cli-surface.md).

Where possible, scenario assertions should also validate runtime transition visibility through the event model documented in [`docs/runtime-events.md`](./runtime-events.md).

## Failure Classification

Verification output should distinguish at least:
- schema failure
- authority failure
- runtime ownership failure
- reconnect/path failure
- operator-surface failure
- deployment contract failure

That lets the release process fail for the right reason instead of reducing everything to one generic test failure bucket.

## Release Rule

Quip should not ship as production-ready until this verification plan is implemented as runnable checks, not just documentation.
