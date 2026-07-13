# Quip State Model

This document defines the boundary between durable node state and live runtime state.

That boundary matters because a decentralized network node needs both:
- durable state that survives restart
- live runtime state that reflects what the daemon is actively doing right now

Production problems start when those two things get mixed together and operators can no longer tell whether a file is a remembered fact, a stale snapshot, or the source of truth.

## Two State Classes

Quip has two top-level state classes:

### 1. Durable State

Durable state survives restart and belongs on disk.

Current durable roots:
- `~/.quip/identity/node.json`
- `~/.quip/net/state.json`

Durable state is for:
- node identity
- network membership and authority-derived control-plane state that is safe to persist
- remembered peer, route, and topology information that remains meaningful across restart
- settings or facts needed to resume normal node behavior

### 2. Runtime State

Runtime state belongs to `quipd` and is not primary durable truth.

Runtime state is for:
- live sessions
- active transports
- listeners
- reconnect attempts
- path probes in flight
- ephemeral health transitions
- stale-handle detection
- temporary authority reevaluation state

If it only makes sense while the daemon is alive, it is runtime state.

## Durable State Rules

Something belongs in durable state only if all of the following are true:
- it is still meaningful after daemon restart
- it helps the node recover the same identity and control-plane position
- it does not pretend to be a live handle to a runtime object
- it can be validated or migrated as a stable stored artifact

Durable state must never contain fake ownership of live sessions.

## Runtime State Rules

Something belongs in runtime state if any of the following are true:
- it points at a live transport or session
- it depends on in-memory daemon ownership
- it represents a temporary transition
- it would become misleading if replayed blindly after restart

Runtime state can be exported for inspection, but an export is not the same thing as durable source of truth.

## Identity Is Not Network State

Identity lives separately from network state because it has a different risk profile and a different lifecycle.

`identity/node.json` is:
- long-lived
- security-sensitive
- not casually reset

`net/state.json` is:
- durable
- restart-relevant
- recoverable without creating a new logical node

Operators must be able to reset network state without accidentally rotating identity.

## Session State Boundary

Live session state must stay daemon-owned.

That means:
- no persisted session handle should be treated as authoritative after restart
- no operator command should assume a persisted `active_sessions` view is the live truth
- session close, upgrade, and reconcile must target daemon-owned runtime state

If session information is ever persisted, it should be clearly marked as remembered metadata, not a live ownership record.

## Path State Boundary

Path selection has both durable and runtime aspects.

Durable aspects may include:
- remembered peer reachability history
- remembered route preferences that remain meaningful after restart
- bounded historical observations useful for future selection

Runtime aspects include:
- currently chosen active path
- in-flight migration
- active health probe outcomes
- downgrade or upgrade transitions

The daemon owns the live path decision. Durable state may inform it, but should not impersonate it.

## Authority State Boundary

Authority affects both durable and runtime behavior.

Durable authority-related state may include:
- last accepted authority-derived records
- membership and capability facts that are valid to persist
- revocation-relevant facts that remain meaningful after restart

Runtime authority-related state may include:
- in-progress sync attempts
- reevaluation work against open sessions
- temporary enforcement transitions

Persist the accepted facts, not the transient enforcement machinery.

## Reset Semantics

The state model implies three different operator actions:

### Identity Preserve, Network Reset

Preserve:
- `identity/node.json`

Reset:
- `net/state.json`

Use this when the node should remain the same participant but durable network state must be rebuilt.

### Full Restore

Restore:
- `identity/node.json`
- `net/state.json`

Use this when recovering the same logical node after loss or corruption.

### Identity Rotation

Replace:
- `identity/node.json`

Reevaluate:
- whether `net/state.json` is still valid at all

Use this only when the node must become a different logical participant.

## Implementation Consequences

This model requires:
- a daemon-owned runtime session registry
- a stable daemon API for runtime inspection and mutation
- a clear schema boundary for what `net/state.json` is allowed to contain
- tests that prove restart behavior does not treat runtime-only data as durable truth

That schema boundary is defined in [`docs/state-schema.md`](./state-schema.md).

## Production Standard

If a field cannot survive restart honestly, it should not be presented as durable state.

If a field cannot be reconstructed without daemon ownership, it belongs to runtime state.

If an operator cannot tell which kind of state they are looking at, the design is not finished.
