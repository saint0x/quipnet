# Quip Path And Reconnect Model

This document defines the production model for path selection, migration, fallback, and reconnect behavior.

It builds on:
- [`docs/network-foundation.md`](./network-foundation.md)
- [`docs/runtime-lifecycle.md`](./runtime-lifecycle.md)
- [`docs/state-model.md`](./state-model.md)
- [`docs/authority-reevaluation.md`](./authority-reevaluation.md)

The central rule is that live path choice and reconnect behavior belong to `quipd`, not to persisted metadata.

## Path Classes

At minimum, Quip should reason about:
- direct path
- relay-assisted path
- alternative candidate paths that may become usable later

The implementation may support more path classes later, but operators need to understand at least this baseline.

## Path Ownership

The daemon owns:
- active path choice
- candidate path tracking
- migration between paths
- fallback decisions
- reconnect initiation and suppression

Durable state may inform those choices, but it must not impersonate the current live decision.

## Path States

At minimum, the runtime path model should expose:
- `candidate`
  - known but not active
- `active`
  - currently carrying the session
- `degraded`
  - usable but impaired
- `failed`
  - not currently usable
- `migrating`
  - in use as part of a transition
- `suppressed`
  - known but intentionally not chosen due to policy or runtime reasoning

## Path Selection Rules

Path choice should be based on:
- authority and policy allowance
- reachability
- observed health
- stability
- transport preference rules
- current session continuity risk

Path choice should not be based solely on stale durable hints.

## Relay Fallback

Relay is part of the real network model, not an embarrassment path.

Relay fallback should happen when:
- direct establishment is unavailable
- direct quality is insufficient
- policy or topology prevents direct continuity

Operators should be able to see when relay was chosen and why.

## Path Migration

Migration is the controlled runtime move from one path to another.

Migration may happen because:
- a better direct path becomes available
- the active path degrades
- authority or policy changes alter path eligibility
- relay is no longer needed or is no longer sufficient

Migration must preserve honest runtime ownership. It should not look like the durable state silently changed.

## Reconnect Ownership

Reconnect belongs to the daemon.

Reconnect behavior should include:
- explicit retry state
- bounded retry policy
- backoff behavior
- suppression after policy denial or authority rejection
- operator-visible reason for reconnect attempts or suppression

## Reconnect Outcomes

Reconnect may lead to:
- recovered active session
- degraded active session on fallback path
- reconnect suppression
- permanent failure requiring operator action

The daemon should expose which outcome occurred and why.

## Durable Versus Runtime Boundary

Durable state may contain:
- coarse path history
- remembered reachability hints
- bounded route preference memory

Runtime state owns:
- active path
- in-flight migration
- reconnect counters and timers for the current daemon run
- current path suppression decisions

If a path fact only makes sense while the daemon is alive, it is runtime state.

## Operator Visibility

Operators should be able to inspect:
- current active path
- current path class
- known candidate paths
- whether migration is in progress
- whether reconnect is active, delayed, suppressed, or failed
- why direct or relay was chosen

## Production Standard

Quip is not production-ready if:
- path selection is mostly implicit
- relay fallback cannot be explained to operators
- reconnect continues despite authority or policy denial
- restart makes runtime path state look like durable truth
