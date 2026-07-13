# Quip Authority Operations

This document defines the baseline production procedures for inspecting authority state and handling authority-related node mismatches.

Authority data is how Quip nodes agree on trusted membership, capabilities, and revocation state. If operators cannot inspect that layer clearly, the network becomes hard to reason about and unsafe to recover.

## What Operators Need To Verify

For any given node, an operator should be able to answer:
- what authority bootstrap source the node is configured to trust
- what authority subject the node expects, if one is pinned
- whether the node's local durable state was built from the expected authority material
- whether current membership and capability assumptions still match policy

## Authority Inspection

Use authority inspection when:
- bringing up a new environment
- diagnosing membership failures
- confirming that a node is attached to the intended network
- validating revocation or capability changes

Baseline procedure:
1. Confirm the configured authority bootstrap source for the node.
2. Confirm any configured authority subject pin.
3. Confirm that the node's environment matches the intended network and authority origin.
4. Compare the node's expected authority source with the operator's deployment records.
5. If the node appears to have been bootstrapped from the wrong authority source, stop and treat that as a trust-boundary problem, not a routine runtime issue.

## Authority Mismatch Diagnosis

An authority mismatch exists when one or more of these are true:
- the node is pointed at the wrong authority origin
- the authority subject does not match expectation
- durable state reflects a different authority history than the operator expects
- membership or capability behavior no longer matches current authority policy

Baseline diagnosis flow:
1. Check the configured authority origin.
2. Check the configured authority subject, if used.
3. Determine whether the issue is configuration drift, stale durable state, or a genuine policy change.
4. Decide whether the node should be re-synced, state-reset, or fully re-provisioned.
5. Preserve evidence before destructive recovery steps.

Do not delete durable state just because a node is denied membership. First determine whether the node is wrong, the authority is wrong, or the policy changed as intended.

## Revocation Handling

Revocation is not a cosmetic update.

When revocation affects a node, operators need to know whether:
- the node itself has been revoked
- a peer or capability the node depended on has been revoked
- a stale local view is allowing behavior that should already be denied

Baseline procedure:
1. Confirm the intended revocation event from authority-side records.
2. Confirm the node is able to refresh authority state from the expected source.
3. Confirm whether live runtime behavior still reflects pre-revocation assumptions.
4. If the runtime still behaves as though revoked material is valid, treat that as a runtime policy enforcement issue.
5. If the node cannot refresh authority state, treat it as a bootstrap or synchronization issue.

## Capability Change Handling

Capability changes should be handled with the same seriousness as membership changes.

Baseline procedure:
1. Confirm the expected capability change in authority-side records.
2. Determine whether the node should gain, lose, or alter behavior because of that change.
3. Confirm whether durable state and runtime behavior reflect the new policy.
4. If behavior has not changed, determine whether the issue is stale authority data, stale runtime state, or missing reevaluation logic.

## Recovery Options

Depending on the diagnosis, the correct recovery may be:
- fix authority origin configuration
- fix subject pin configuration
- trigger authority re-sync
- perform a safe state reset while preserving identity
- rotate identity if the node should no longer act as the same participant
- fully re-provision the node for a different network

Operators should choose the smallest recovery that restores the correct trust model.

## What Operators Should Never Do

- Never point a node at a different authority source without treating it as a trust change.
- Never reuse durable state from one authority domain in a different authority domain without an explicit migration model.
- Never assume a membership denial is just a transport issue.
- Never rotate identity to hide an unresolved authority mismatch.
