# Quip Authority Reevaluation

This document defines how authority changes should affect live runtime behavior.

It builds on:
- [`docs/authority-operations.md`](./authority-operations.md)
- [`docs/daemon-api.md`](./daemon-api.md)
- [`docs/runtime-lifecycle.md`](./runtime-lifecycle.md)

The central rule is simple: accepted authority changes must be able to change runtime behavior, not just durable metadata.

## Why Reevaluation Exists

Authority is not useful if the daemon only checks it once and then ignores later change.

Runtime reevaluation is required when:
- membership changes
- capability changes
- revocation occurs
- authority subject or trust context changes

Without reevaluation, live runtime sessions can keep operating under stale trust assumptions.

## Reevaluation Triggers

The daemon should reevaluate relevant runtime state when any of the following happen:
- successful authority sync that changes accepted facts
- explicit operator-triggered authority refresh
- startup with accepted authority state that changes local policy interpretation
- local detection of trust mismatch requiring immediate policy review

## Reevaluation Scope

Reevaluation may affect:
- all sessions
- sessions associated with a specific peer
- sessions associated with a revoked or changed capability set
- listener or path eligibility

The daemon should scope reevaluation narrowly when possible, but correctness matters more than minimizing work.

## Reevaluation Outcomes

At minimum, reevaluation should be able to produce these runtime outcomes:

- no change
  - current runtime behavior remains valid
- degrade
  - runtime behavior is limited while maintaining continuity where policy permits
- migrate
  - session moves to an allowed path or allowed policy posture
- close
  - session is terminated because it is no longer allowed
- suppress reconnect
  - runtime is no longer allowed to reestablish the session automatically

## Revocation Semantics

Revocation must be treated as a first-class runtime event.

If revocation invalidates a live session, the daemon should:
1. detect the revocation through accepted authority state
2. mark the session for policy reevaluation
3. close or constrain the session according to policy
4. prevent silent reconnect under stale assumptions
5. expose the policy-driven reason to operators

## Capability Change Semantics

Capability change is not always a full revocation, but it may still require runtime action.

Capability change may require:
- allowing additional behavior
- suppressing behavior that was previously allowed
- forcing reauthorization of path or session features
- changing which peers or services are reachable

The daemon should not assume that capability drift is safely deferred until the next restart.

## Membership Loss Semantics

If the local node loses membership:
- runtime behavior should transition into a deny or shutdown posture according to policy
- reconnect should not continue as though membership still exists
- operator-facing diagnostics should clearly state membership loss as the reason

If a remote peer loses membership:
- affected sessions should be reevaluated
- unauthorized continuity should not persist

## Subject Mismatch Semantics

If the configured or accepted authority subject no longer matches expectation:
- treat it as a trust-boundary issue
- stop assuming durable state remains valid without review
- expose the mismatch clearly

This is not just another transport error.

## Operator Visibility

Operators should be able to inspect:
- whether the last authority sync changed accepted facts
- how many sessions were reevaluated
- whether any sessions were closed, degraded, or suppressed
- whether reconnect suppression is in effect for policy reasons

## Production Standard

Quip is not production-ready if:
- authority sync updates durable facts but leaves runtime behavior stale
- revocation can occur without runtime consequence
- reconnect continues automatically after policy denial
- operators cannot tell whether a session changed because of authority policy
