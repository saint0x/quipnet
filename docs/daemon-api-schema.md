# Quip Daemon API Schema

This document defines the concrete local control contract for `quipd`.

It builds on:
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/cli-surface.md`](./cli-surface.md)
- [`docs/state-model.md`](./state-model.md)

The goal is to make the daemon API implementable without leaving core request and response behavior ambiguous.

## Protocol Shape

The exact transport can be chosen by implementation, but the API contract should behave like a structured local RPC surface.

Every request should include:
- operation name
- request ID
- caller identity or local auth context
- operation-specific payload

Every response should include:
- request ID
- success or error result
- operation-specific payload

## Common Response Envelope

Every response should follow this logical shape:

- `ok: bool`
- `request_id: string`
- `result: object | null`
- `error: object | null`

Where `error` contains:
- `code`
- `message`
- optional `details`

## Error Codes

Minimum stable error codes:
- `invalid_request`
- `unauthorized`
- `not_found`
- `runtime_unavailable`
- `stale_runtime_reference`
- `policy_rejected`
- `authority_mismatch`
- `state_validation_failed`
- `unsupported_operation`
- `internal_error`

## Runtime Inspection Operations

### `runtime.status`

Purpose:
- summary view of live daemon-owned state

Result should include:
- daemon health
- node identity summary
- durable state availability summary
- authority sync summary
- runtime session count
- active path summary

### `runtime.sessions.list`

Purpose:
- enumerate live sessions

Result should include per session:
- session ID
- peer identity or peer reference
- current state
- active path type
- creation time or age summary
- last activity summary

This is live runtime truth, not persisted session memory.

### `runtime.listeners.list`

Purpose:
- enumerate live transport listeners

Result should include:
- listener ID
- transport type
- bind address summary
- state
- state reason when suppressed or failed
- whether the listener is currently eligible under authority and local policy

### `runtime.paths.list`

Purpose:
- inspect live path state

Result should include:
- peer or session reference
- active path
- candidate paths
- decision reason for the selected or candidate path
- current health summary
- migration state when applicable

### `runtime.health`

Purpose:
- inspect daemon runtime health and subsystem state

Result should include:
- daemon readiness
- authority sync health
- authority subject status
- authority deny reason when live authority posture is suppressing behavior
- runtime registry health
- path manager health
- reconnect subsystem health

### `runtime.events.list`

Purpose:
- inspect bounded live runtime transition history

Result should include per event:
- event ID
- event type
- emitted time
- event truth kind
- subject reference
- structured details

## Session Lifecycle Operations

### `session.connect`

Request should include:
- target peer or target address information
- optional requested path preference
- optional authority or policy context if needed

Result should include:
- session ID
- initial session state
- chosen initial path summary

### `session.close`

Request should include:
- session ID
- optional operator reason

Result should include:
- closed session ID
- final observed session state

### `session.upgrade`

Request should include:
- session ID
- requested upgrade target or policy hint

Result should include:
- session ID
- prior path summary
- resulting path summary or upgrade state

### `session.reconcile`

Request should include:
- optional session ID
- optional scope when reconciling all runtime sessions

Result should include:
- reconciled session count
- updated session summaries
- any mismatches detected

## Authority Operations

### `authority.show`

Purpose:
- inspect configured and accepted authority state

Result should include:
- configured authority origin
- configured authority subject if pinned
- accepted authority summary
- last sync summary
- live reevaluation summary
- authority subject mismatch status when present

### `authority.sync`

Purpose:
- force authority refresh

Result should include:
- sync started or completed status
- resulting authority summary
- affected membership or capability deltas when available
- removal deltas for grants or bootstrap hints when a new accepted snapshot withdraws them
- whether live runtime reevaluation ran as a consequence

### `authority.membership`

Purpose:
- inspect accepted membership facts

Result should include:
- membership records relevant to this node
- peer or group summaries as applicable

### `authority.capabilities`

Purpose:
- inspect accepted capability facts

Result should include:
- local node capability summary
- relevant peer or role capability summaries when applicable

### `authority.revocations`

Purpose:
- inspect accepted revocation facts

Result should include:
- issuer summary
- target summary
- effective time
- reason

## Identity Operations

### `identity.show`

Purpose:
- inspect the durable node identity associated with this daemon

Result should include:
- node identity summary
- identity path
- load status

### `identity.verify`

Purpose:
- confirm daemon/runtime association with the expected durable identity

Result should include:
- expected identity summary
- loaded identity summary
- match or mismatch result

## Durable State Operations

### `state.show`

Purpose:
- inspect durable remembered state, clearly labeled as durable

Result should include:
- durable state path
- presence or absence of the durable file
- schema version
- validation success or failure
- field-level violations when present
- durable state summary when the file is valid

### `state.validate`

Purpose:
- validate `~/.quip/net/state.json` against the durable schema contract

Result should include:
- durable state path
- presence or absence of the durable file
- schema version
- validation success or failure
- field-level violations when present

### `state.reset`

Purpose:
- reset durable network state while preserving identity

Request should include:
- operator confirmation token or equivalent guard
- reset scope

Result should include:
- identity preserved confirmation
- whether durable network state was actually removed
- next required live-daemon action summary

## Output Semantics

Every operation must clearly distinguish whether it is returning:
- live daemon-owned runtime state
- durable on-disk remembered state
- a comparison between durable and runtime state

The response contract should never force the CLI to guess which kind of truth it is rendering.

## Minimum Implementation Rule

Before Quip is production-ready, the implemented daemon surface should cover:
- `runtime.status`
- `runtime.sessions.list`
- `runtime.paths.list`
- `session.connect`
- `session.close`
- `session.upgrade`
- `session.reconcile`
- `authority.show`
- `authority.sync`
- `identity.show`
- `state.show`
- `state.validate`
- `state.reset`

Concrete payload examples for these operations are documented in [`docs/daemon-api-examples.md`](./daemon-api-examples.md).
Machine-readable response targets live under [`schemas/daemon/`](../schemas/daemon/).
