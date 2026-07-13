# Quip Production Milestones

This document turns the remaining production work into concrete milestone phases with exit criteria.

It builds on:
- [`docs/implementation-map.md`](./implementation-map.md)
- [`docs/production-readiness.md`](./production-readiness.md)
- [`docs/verification-plan.md`](./verification-plan.md)

## Milestone 1: Runtime Ownership

Goal:
- make `quipd` the only owner of live runtime state

Required outcomes:
- daemon-owned runtime session registry
- daemon-owned reconnect ownership
- daemon-owned active path ownership
- stale runtime handle invalidation after restart

Exit criteria:
- runtime session lifecycle commands no longer rely on cached local state
- persisted session-like fields are not treated as live truth

## Milestone 2: Durable State Contract

Goal:
- make `~/.quip/net/state.json` a validated durable schema instead of an informal dump

Required outcomes:
- schema version field
- explicit durable-field allowlist
- rejection of runtime-only fields
- migration path for older state

Exit criteria:
- startup validates durable state before use
- restart behavior does not depend on fake persisted runtime ownership

## Milestone 3: Daemon API

Goal:
- expose the real local control surface for runtime inspection and runtime mutation

Required outcomes:
- runtime inspection endpoints
- session lifecycle endpoints
- authority inspection and sync endpoints
- structured error classes

Exit criteria:
- runtime truth is available through one stable local daemon API
- operator actions with runtime impact route through that API

## Milestone 4: CLI Alignment

Goal:
- make `quip` match the documented command model

Required outcomes:
- `quip status`
- `quip runtime ...`
- `quip session ...`
- `quip authority ...`
- `quip identity ...`
- `quip state ...`

Exit criteria:
- runtime commands are daemon-backed
- durable commands are clearly separated from runtime commands
- command output labels runtime versus durable truth honestly

## Milestone 5: Authority Enforcement

Goal:
- make authority and membership behavior visible, explainable, and enforceable

Required outcomes:
- authority origin inspection
- authority subject inspection
- membership and capability visibility
- revocation-driven runtime reevaluation
- capability-change runtime reevaluation

Exit criteria:
- operators can diagnose authority mismatch without guesswork
- runtime behavior changes when authority policy changes

## Milestone 6: Path And Reconnect

Goal:
- make path choice and reconnect behavior explicit, inspectable, and restart-safe

Required outcomes:
- daemon-owned path selection
- live path versus durable path-history split
- reconnect policy state machine
- runtime explanation surface for path choice and fallback

Exit criteria:
- direct, relay, and migration behavior are visible at runtime
- reconnect behavior is deterministic under controlled scenarios

## Milestone 7: Operator Recovery Surface

Goal:
- back the documented recovery workflows with real commands

Required outcomes:
- identity inspection command support
- durable state validation command support
- safe state reset support
- authority sync and diagnostic support
- backup/export support where implemented

Exit criteria:
- operators do not need undocumented file surgery for normal recovery workflows

## Milestone 8: Verification And Release Gate

Goal:
- turn production readiness into an enforced release decision

Required outcomes:
- scenario matrix implementation from [`docs/verification-plan.md`](./verification-plan.md)
- recorded trace coverage
- replay verification
- release gate wiring
- operator-surface verification

Exit criteria:
- release readiness is decided by runnable checks, not manual confidence

## Completion Rule

Quip is only done for production when all milestones are complete and the release gate in [`docs/production-readiness.md`](./production-readiness.md) passes without exceptions.
