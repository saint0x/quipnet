# Quip Runtime Lifecycle

This document defines the production runtime lifecycle for daemon-owned sessions in Quip.

It builds on:
- [`docs/network-foundation.md`](./network-foundation.md)
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/daemon-api-schema.md`](./daemon-api-schema.md)
- [`docs/state-model.md`](./state-model.md)

The purpose of this document is to make session ownership, transitions, and restart behavior explicit.

## Runtime Ownership Rule

Every live session belongs to `quipd`.

That means:
- creation is daemon-owned
- transition is daemon-owned
- teardown is daemon-owned
- upgrade and migration are daemon-owned
- reconciliation is daemon-owned

The CLI may request actions, but it does not own the session lifecycle.

## Session Identity

A runtime session needs a daemon-owned session identifier that is:
- unique for the live daemon run
- stable enough for operator interaction during that run
- invalid after the daemon loses ownership or restarts

A persisted session reference must never be treated as proof that a live runtime session still exists.

## Session States

The minimum production session state model should include:

- `pending`
  - request accepted, runtime establishment not complete
- `connecting`
  - transport/path establishment in progress
- `active`
  - usable runtime session exists
- `degraded`
  - session is alive but path quality or capability is impaired
- `migrating`
  - runtime is moving the session to a different path or transport mode
- `reconciling`
  - runtime is checking or correcting session state against policy or durable expectations
- `closing`
  - teardown is in progress
- `closed`
  - session is gone and no longer runtime-owned
- `failed`
  - runtime establishment or continuity failed

The implementation may use sub-states internally, but operators need at least this visible model.

## State Transition Rules

Valid high-level transitions should include:

- `pending -> connecting`
- `connecting -> active`
- `connecting -> failed`
- `active -> degraded`
- `active -> migrating`
- `active -> reconciling`
- `active -> closing`
- `degraded -> active`
- `degraded -> migrating`
- `degraded -> reconciling`
- `degraded -> closing`
- `migrating -> active`
- `migrating -> degraded`
- `migrating -> failed`
- `reconciling -> active`
- `reconciling -> degraded`
- `reconciling -> closing`
- `closing -> closed`

Transitions should be explicit in runtime inspection output. Operators should not have to infer them from side effects.

## Session Creation

Session creation should:
1. validate the request
2. validate policy and authority constraints
3. create a daemon-owned runtime session entry
4. attempt path selection and connection establishment
5. expose a visible lifecycle state through the daemon API

If policy rejects the request, no fake runtime session should be left behind.

## Session Reconciliation

Reconciliation exists because durable state, authority state, and live runtime state can drift.

Reconciliation should check:
- whether the session still matches authority policy
- whether the session still matches local runtime expectations
- whether path and capability state are still valid
- whether the session should remain active, degrade, migrate, or close

Reconciliation must be daemon-owned because only the daemon owns live runtime truth.

## Session Upgrade

Upgrade is a controlled runtime change, not a metadata rewrite.

Upgrade may include:
- moving from relay-assisted to direct path
- moving to a stronger or preferred path class
- reestablishing under a better transport condition

Upgrade should:
- preserve runtime ownership under the same daemon
- expose the migration or upgrade state to operators
- fail clearly if the runtime no longer owns the referenced session

## Session Closure

Closure should be explicit about cause.

At minimum, runtime closure reasons should distinguish:
- operator requested close
- local runtime failure
- remote failure
- authority or policy rejection
- path exhaustion
- daemon shutdown

Operators need closure reason visibility for diagnosis and auditability.

## Restart Behavior

Restart is the hard boundary for runtime ownership.

After daemon restart:
- previous runtime session IDs are stale
- previous live session handles are invalid
- runtime state must be reconstructed honestly
- durable state may inform new runtime actions, but must not impersonate live session continuity

If continuity is restored after restart, that is a new daemon-owned runtime fact, not proof that the previous runtime object survived.

## Operator Visibility

Operators should be able to inspect:
- session ID
- peer reference
- current session state
- closure or failure reason when applicable
- active path summary
- whether the session is currently under migration or reconciliation

This is the minimum honest runtime lifecycle surface.

## Production Standard

Quip is not production-ready if:
- session lifecycle is still inferred from cached local files
- restart leaves stale runtime references looking valid
- upgrade or reconcile mutate metadata without clear runtime ownership
- operators cannot tell why a session closed or degraded
