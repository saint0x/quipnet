# Quip Implementation Map

This document maps the production architecture and operator model onto the concrete implementation work that still has to exist in the codebase.

It is the bridge between:
- the production documents
- the runtime model
- the remaining checklist

The point is to make the missing implementation surface obvious.

## Core Production Documents

These documents define the target model:
- [`docs/network-foundation.md`](./network-foundation.md)
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/state-model.md`](./state-model.md)
- [`docs/state-schema.md`](./state-schema.md)
- [`docs/cli-surface.md`](./cli-surface.md)
- [`docs/operator-workflows.md`](./operator-workflows.md)
- [`docs/authority-operations.md`](./authority-operations.md)
- [`docs/backup-and-restore.md`](./backup-and-restore.md)
- [`docs/production-readiness.md`](./production-readiness.md)
- [`docs/verification-plan.md`](./verification-plan.md)

## Implementation Tracks

The remaining implementation work falls into six tracks.

### 1. Daemon Runtime Ownership

Goal:
- make `quipd` the actual owner of live runtime truth

Must exist in code:
- one daemon-owned runtime session registry
- one daemon-owned path/runtime health registry
- one daemon-owned reconnect controller
- restart-safe invalidation of stale runtime handles

Reference documents:
- [`docs/runtime-lifecycle.md`](./runtime-lifecycle.md)
- [`docs/path-and-reconnect.md`](./path-and-reconnect.md)

Done only when:
- CLI runtime actions cannot bypass the daemon
- cached files cannot impersonate live runtime ownership

### 2. Durable State Enforcement

Goal:
- make `~/.quip/net/state.json` follow the documented schema contract

Must exist in code:
- schema version field
- strict field validation
- explicit migration path
- rejection of runtime-only fields from durable state

Done only when:
- restart behavior does not depend on fake persisted runtime state
- invalid durable state fails clearly and safely

### 3. CLI Surface Alignment

Goal:
- make `quip` match the documented operator command model

Must exist in code:
- `quip status`
- `quip runtime ...`
- `quip session ...`
- `quip authority ...`
- `quip identity ...`
- `quip state ...`

Done only when:
- runtime commands talk to the daemon
- durable commands are clearly separated
- output labels runtime versus durable truth honestly

### 4. Authority Enforcement

Goal:
- make authority and membership behavior operationally visible and runtime-enforced

Must exist in code:
- authority origin and subject inspection
- authority sync status inspection
- accepted authority fact visibility
- revocation-driven runtime reevaluation
- capability-change runtime reevaluation

Reference documents:
- [`docs/authority-operations.md`](./authority-operations.md)
- [`docs/authority-reevaluation.md`](./authority-reevaluation.md)

Done only when:
- operators can diagnose authority problems without guessing
- runtime behavior actually changes when authority policy changes

### 5. Path And Reconnect Control

Goal:
- make direct, relay, migration, and reconnect behavior daemon-owned and inspectable

Must exist in code:
- live path selection logic
- path history versus active path separation
- reconnect policy state machine
- runtime explanations for chosen path and fallback behavior

Reference documents:
- [`docs/path-and-reconnect.md`](./path-and-reconnect.md)
- [`docs/runtime-lifecycle.md`](./runtime-lifecycle.md)

Done only when:
- path decisions are visible through runtime inspection
- reconnect behavior is deterministic under controlled scenarios

### 6. Verification And Release Gating

Goal:
- make production readiness enforceable instead of aspirational

Must exist in code and tooling:
- runnable scenario checks
- recorded traces
- replay verification
- release gate integration
- operator-surface verification

Done only when:
- the release decision depends on the documented gates, not manual confidence

## Dependency Order

The practical implementation order should be:

1. daemon runtime ownership
2. durable state enforcement
3. daemon API request/response surface
4. CLI surface alignment
5. authority enforcement and operator visibility
6. path/reconnect runtime behavior
7. verification and release gating

This order matters because the CLI and tests should target the real runtime model, not temporary scaffolding.

## Minimum Code Outcomes

Before Quip is production-ready, the codebase must contain:
- a stable local daemon control path
- a restart-safe runtime session model
- a validated durable state schema
- a CLI that reflects the daemon-owned runtime model
- authority-aware runtime enforcement
- replayable system verification

If any of those are missing, the docs may be clearer, but the product is still not done.
