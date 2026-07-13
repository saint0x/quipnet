# RFC Process

Quipnet RFCs define the production architecture before cross-network behavior is considered stable.

## Lifecycle

1. Draft in `docs/rfcs/`.
2. Link the relevant threat boundaries, wire semantics, storage implications, and rollout plan.
3. Require at least one architecture review and one security review for transport, identity, membership, relay, and record changes.
4. Land implementation only after the RFC states invariants, migration rules, and observability hooks.

## Required Sections

- Problem statement
- Decision
- Trust boundaries
- Wire or data model
- Failure modes
- Telemetry and diagnostics
- Rollout and rollback
- Open questions

