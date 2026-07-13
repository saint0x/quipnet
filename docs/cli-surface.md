# Quip CLI Surface

This document defines the intended production command surface for `quip` as the local operator client for `quipd`.

The goal is simple: runtime truth and runtime mutations should be expressed through a clear CLI that maps to the daemon API instead of reading random files and pretending that cached state is live state.

This document builds on:
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/operator-workflows.md`](./operator-workflows.md)
- [`docs/authority-operations.md`](./authority-operations.md)

## Product Roles

- `quip`
  - local operator CLI
  - reads or mutates runtime state through the daemon API
  - may inspect durable files only for explicitly file-oriented operations
- `quipd`
  - daemon that owns runtime state
  - answers runtime inspection requests
  - performs runtime lifecycle actions

## Top-Level Command Groups

The production CLI should converge on these top-level groups:

### `quip status`

Purpose:
- one concise operator view of node health

Should report:
- daemon health
- identity presence
- durable state presence
- authority sync status
- runtime session summary
- active path summary

Primary source:
- daemon API

### `quip runtime`

Purpose:
- inspect live runtime state in more detail

Candidate subcommands:
- `quip runtime sessions`
- `quip runtime listeners`
- `quip runtime paths`
- `quip runtime health`

Primary source:
- daemon API only

### `quip session`

Purpose:
- operator actions and inspection for runtime sessions

Candidate subcommands:
- `quip session list`
- `quip session connect`
- `quip session close`
- `quip session upgrade`
- `quip session reconcile`

Primary source:
- daemon API only

No subcommand here should rely on persisted session snapshots as primary truth.

### `quip authority`

Purpose:
- inspect authority inputs and authority-derived node state

Candidate subcommands:
- `quip authority show`
- `quip authority sync`
- `quip authority subject`
- `quip authority membership`
- `quip authority capabilities`
- `quip authority revocations`

Primary source:
- daemon API for live view
- durable state only where explicitly labeled as remembered state

### `quip identity`

Purpose:
- inspect local node identity and identity-related operator state

Candidate subcommands:
- `quip identity show`
- `quip identity path`
- `quip identity verify`

Primary source:
- durable identity store
- daemon API where runtime association matters

This group should never silently create a new production identity during normal inspection.

### `quip state`

Purpose:
- explicit durable-state-oriented operations

Candidate subcommands:
- `quip state show`
- `quip state validate`
- `quip state backup`
- `quip state export`
- `quip state restore`
- `quip state reset`

Primary source:
- durable state contract
- daemon-owned durable-state inspection and reset operations
- daemon-assisted export or snapshot flows when available

This group is where file-oriented behavior belongs. It should not be mixed with runtime session ownership.

## Output Modes

Every inspection command should support:
- human-readable default output
- structured machine-readable output

Structured output is required for:
- automation
- dashboards
- diagnostics
- regression tests

## Command Honesty Rules

The CLI must be honest about what kind of state it is showing.

That means:
- runtime commands must say they are showing live daemon-owned state
- durable-state commands must say they are showing remembered on-disk state
- mismatch situations must be labeled explicitly

The CLI should never blur these together just to seem convenient.

## Unsafe Legacy Behaviors To Remove

The production CLI should not preserve behaviors such as:
- reading cached local files and presenting them as live session truth
- allowing runtime mutation commands to operate without daemon ownership
- hiding the difference between authority configuration and authority live sync status
- mixing identity reset, network reset, and runtime reconcile into one ambiguous action

## Minimum Production Command Set

Before this surface is complete, we need at least:
- `quip status`
- `quip runtime sessions`
- `quip session connect`
- `quip session close`
- `quip session upgrade`
- `quip session reconcile`
- `quip authority show`
- `quip authority sync`
- `quip identity show`
- `quip state show`
- `quip state validate`
- `quip state backup`
- `quip state export`
- `quip state restore`
- `quip state reset`

That is the minimum honest operator surface for a daemon-owned node runtime.
