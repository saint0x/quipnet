# Quip Runtime Events

This document defines the minimum event model that should exist around daemon-owned runtime behavior.

It builds on:
- [`docs/runtime-lifecycle.md`](./runtime-lifecycle.md)
- [`docs/authority-reevaluation.md`](./authority-reevaluation.md)
- [`docs/path-and-reconnect.md`](./path-and-reconnect.md)
- [`docs/daemon-api-schema.md`](./daemon-api-schema.md)

The point is to make runtime transitions observable and testable. Without an event model, the system tends to hide important behavior behind final state snapshots.

## Event Design Goals

The runtime event surface should let operators and tests observe:
- session creation and teardown
- path selection and migration
- reconnect attempts and suppression
- authority-driven reevaluation
- policy-driven closure

Events do not replace stable state inspection, but they make transitions visible.

## Common Event Envelope

Every event should include:
- `event_id`
- `event_type`
- `emitted_at`
- `truth_kind`
- `subject`
- `details`

Where:
- `truth_kind` is normally `runtime`
- `subject` identifies what changed, such as a session ID or peer ID

## Minimum Event Types

### Session Events

- `session.created`
- `session.state_changed`
- `session.closing`
- `session.closed`
- `session.failed`

Useful details:
- session ID
- peer ID
- prior state
- next state
- closure or failure reason

### Path Events

- `path.selected`
- `path.degraded`
- `path.migration_started`
- `path.migration_completed`
- `path.failed`
- `path.suppressed`

Useful details:
- session ID or peer ID
- path class
- prior path class when applicable
- selection or suppression reason

### Reconnect Events

- `reconnect.started`
- `reconnect.retry_scheduled`
- `reconnect.succeeded`
- `reconnect.suppressed`
- `reconnect.unsuppressed`
- `reconnect.cleared`
- `reconnect.failed`

Useful details:
- session or peer reference
- retry attempt number
- backoff summary
- suppression reason

### Authority Events

- `authority.sync_started`
- `authority.sync_completed`
- `authority.sync_failed`
- `authority.reevaluation_started`
- `authority.reevaluation_completed`
- `authority.policy_enforced`

Useful details:
- accepted revision summary
- affected session count
- policy action summary
- authority subject mismatch status
- local policy deny reason when reevaluation forces shutdown
- per-session `action` and `cause` for policy-enforced closure or reconnect suppression

## Event Semantics

Events should be:
- append-only observations of runtime change
- bounded and exportable for diagnostics
- clearly distinct from durable state

They must not be treated as the authoritative replacement for current runtime inspection. A current session list still comes from runtime state, not from replaying event history.

## Testing Value

This event model should be used by:
- daemon API integration tests
- runtime lifecycle tests
- authority reevaluation tests
- reconnect and path-migration tests
- Fozzy scenario assertions

If transitions are not visible as events or equivalent structured observations, deterministic system testing gets much weaker.

The machine-readable event schema target lives at [`schemas/events/runtime-event.schema.json`](../schemas/events/runtime-event.schema.json).
Concrete example event fixtures live under [`../fixtures/events/`](../fixtures/events).
