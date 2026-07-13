# Quip Durable State Schema

This document defines what is allowed to live in `~/.quip/net/state.json`.

It is a production contract, not a loose suggestion. If a field is not justified here as durable, it should not be persisted as part of the node's durable network state.

This document builds on:
- [`docs/state-model.md`](./state-model.md)
- [`docs/daemon-api.md`](./daemon-api.md)

## Scope

`~/.quip/net/state.json` is the durable network and control-plane state for a node.

It is not:
- a dump of daemon memory
- a persisted runtime session registry
- a cache of live transport handles
- a substitute for daemon API runtime inspection

## Top-Level Durable Categories

Durable network state may contain only these classes of information:

### 1. Schema Metadata

Purpose:
- versioning
- migration control
- validation boundaries

Allowed examples:
- schema version
- format revision
- migration marker fields that help explicit upgrade logic

### 2. Node Network Configuration Snapshot

Purpose:
- durable configuration facts that affect how the node participates in the network

Allowed examples:
- selected network identifier
- durable authority bootstrap configuration snapshot
- durable authority subject pin if the product model requires it as stored state

Not allowed:
- transient environment overrides that should come directly from runtime configuration

### 3. Accepted Authority-Derived Facts

Purpose:
- durable membership and policy facts that remain meaningful after restart

Allowed examples:
- last accepted authority records
- accepted membership facts
- accepted capability facts
- revocation-relevant facts that survive restart

Not allowed:
- in-progress sync bookkeeping that only exists for one live daemon run
- temporary reevaluation queues

### 4. Durable Peer And Topology Memory

Purpose:
- remembered network knowledge that helps the node rejoin intelligently after restart

Allowed examples:
- known peers
- durable peer attributes
- bounded topology observations
- stable route preference hints that remain meaningful after restart

Not allowed:
- live connection ownership
- active socket or stream identifiers
- assumptions that a peer is currently connected just because it was connected before shutdown

### 5. Durable Path History

Purpose:
- bounded historical observations that help future path selection

Allowed examples:
- coarse path quality history
- remembered reachability classifications
- prior successful path families when meaningful across restart

Not allowed:
- current in-flight migration state
- active probes
- current live path lock ownership

### 6. Durable Operator-Relevant Recovery Facts

Purpose:
- facts that help explain the node's last known durable state after restart

Allowed examples:
- last clean durable checkpoint markers
- durable corruption-detection metadata
- bounded recovery markers used by explicit restore or migration logic

Not allowed:
- arbitrary debug dumps
- unbounded event logs pretending to be state

## Explicitly Forbidden Durable Fields

The following must not be persisted as authoritative durable state:
- live session handles
- daemon-owned runtime session IDs treated as current truth
- listener handles
- transport backend object identity
- in-flight reconnect attempts
- in-flight authority sync tasks
- temporary retry counters that only make sense during the active daemon run
- unresolved runtime-only path transitions
- process IDs, socket paths, or other process-local ownership markers as durable source of truth

If persisted at all for diagnostics, such data must be clearly separated from the durable state contract and never used as restart truth.

## Validation Rules

`state.json` should be validated against explicit rules:
- required schema version
- known field allowlist
- bounded sizes for remembered collections
- rejection of unknown runtime-only fields in durable sections
- migration-required behavior when older schema versions are encountered

The goal is to stop stale or accidental runtime data from silently becoming part of the node's durable truth.

## Migration Rules

Schema change must be explicit.

Any durable state migration should:
- read an older version
- validate it
- transform it into the newer durable model
- reject unsupported or ambiguous state
- write back only fields allowed by the new schema contract

The operator-facing migration path should stay explicit:
- stop `quipd`
- run `quip state migrate --confirm`
- validate the rewritten durable state before restart

Migration should never blindly preserve legacy fields just because they already exist on disk.

## Relationship To The Daemon API

If an operator asks:
- what sessions are open right now
- what path is active right now
- what reconnect work is in flight right now
- what authority reevaluation is happening right now

the answer must come from `quipd`, not from `state.json`.

`state.json` is for what the node durably remembers, not what the daemon currently owns.

## Minimum Implementation Standard

Before this system is production-ready:
- `state.json` needs an explicit schema version
- the persisted field set needs an allowlist
- runtime-only fields need to be rejected from the durable schema
- tests need to prove restart behavior does not depend on fake persisted runtime ownership

A concrete example durable shape is documented in [`docs/state-schema-example.md`](./state-schema-example.md).
The machine-readable schema target lives at [`schemas/state/state.schema.json`](../schemas/state/state.schema.json).
