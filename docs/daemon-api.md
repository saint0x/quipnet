# Quip Daemon API

This document defines the production role of the Quip daemon API and the ownership boundary between `quip`, `quipd`, durable state, and live runtime state.

## Why The Daemon API Exists

The daemon API exists because the CLI is not the owner of live network behavior.

`quipd` owns:
- live sessions
- transport listeners
- reconnect behavior
- path selection
- runtime health
- authority-driven runtime reevaluation

That means any operator action that depends on current runtime truth must go through the daemon, not through cached files or local guesses.

## Ownership Boundary

The boundary is simple:

- `~/.quip/identity/node.json`
  - durable node identity
- `~/.quip/net/state.json`
  - durable control-plane and network state that is safe to persist
- `quipd`
  - live runtime authority
- `quip`
  - operator client that talks to `quipd` for runtime truth and runtime mutations

If a question is about what is happening right now, the answer belongs to the daemon API.

The durable-versus-runtime storage boundary underneath this API is documented in [`docs/state-model.md`](./state-model.md).

## What Must Be In The API

The production daemon API must cover four classes of behavior:

### 1. Runtime Inspection

Operators need to inspect:
- daemon health
- runtime sessions
- transport listeners
- path decisions
- reconnect state
- authority sync status

This is read-only runtime truth.

### 2. Runtime Lifecycle Actions

Operators need controlled runtime actions for:
- connect
- session close
- session upgrade
- session reconcile
- authority re-sync
- safe export or snapshot requests when supported

These are authenticated local control operations, not file edits.

### 3. Durable Versus Runtime State Explanation

Operators need a clear split between:
- durable remembered state
- current live runtime state
- drift or mismatch between them

The API should make that split visible instead of forcing operators to infer it from multiple commands or raw files.

### 4. Machine-Readable Failure

The API must return structured error classes for:
- invalid request
- not found
- unauthorized local caller
- runtime not available
- runtime state not owned here
- stale session reference
- authority mismatch
- operation rejected by policy

The point is to make automation and operator tooling trustworthy.

## What Must Not Be In The API

The daemon API should not pretend to expose stable semantics for internal implementation details that are not part of the operator contract.

Examples:
- raw in-memory pointer identity
- transport backend private internals
- accidental file layout details outside the documented durable contract

The API is for stable operational truth, not debug leakage.

## Authentication And Scope

The daemon API is a local privileged control surface.

At minimum it needs:
- authenticated local callers
- explicit authorization boundaries for mutating operations
- timeouts
- resource limits
- abuse protection for repeated requests

A production daemon API should be safe to expose to trusted local automation without letting random local processes mutate network state.

## Output Design

All runtime inspection responses should support structured output first.

Human-readable CLI rendering is important, but the underlying daemon responses should be machine-readable and stable enough for:
- automation
- diagnostics
- operator dashboards
- future control-plane integrations

## Relationship To Operator Workflows

The documented operator workflows in:
- [`docs/operator-workflows.md`](./operator-workflows.md)
- [`docs/authority-operations.md`](./authority-operations.md)
- [`docs/backup-and-restore.md`](./backup-and-restore.md)

should eventually map to concrete daemon/API commands wherever runtime truth or controlled runtime mutation is involved.

The intended CLI mapping for those commands is documented in [`docs/cli-surface.md`](./cli-surface.md).
The concrete request/response surface is documented in [`docs/daemon-api-schema.md`](./daemon-api-schema.md).

If a workflow currently depends on direct file inspection because the daemon API does not yet exist, that should be treated as an implementation gap, not the final architecture.

## Minimum Production Goal

Before this system is considered production-ready, we need:
- one canonical daemon-owned runtime session registry
- one stable local daemon API for runtime inspection and control
- one honest CLI that stops pretending cached files are live truth

That is the architectural line between a real node runtime and a pile of local utilities.
