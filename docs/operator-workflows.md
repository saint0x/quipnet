# Quip Operator Workflows

This document defines the baseline operator workflows for running and recovering Quip nodes in production.

These workflows assume the durable node contract:
- `~/.quip/identity/node.json`
- `~/.quip/net/state.json`

They also assume `quipd` is the owner of live runtime behavior.

Authority-specific inspection and mismatch handling are documented separately in [`docs/authority-operations.md`](./authority-operations.md).

## Identity Inspection

Use identity inspection when you need to answer:
- which logical node is this machine supposed to be
- whether the expected identity file exists
- whether the deployed node matches the operator's expectation

Baseline procedure:
1. Confirm the expected durable identity path for the environment.
2. Verify that `identity/node.json` exists and has correct ownership and permissions.
3. Confirm the passphrase source configured for the node.
4. Compare the node's expected identity with deployment records or authority-side expectations.
5. If the file is missing, corrupted, or unexpected, stop and treat it as an identity incident rather than guessing.

Do not silently generate a new identity on a production node that is supposed to remain the same logical participant.

## Runtime Mismatch Diagnosis

Use runtime mismatch diagnosis when:
- durable files look correct but runtime behavior does not
- the daemon appears to disagree with operator expectations
- direct or relay behavior is not matching stored state or authority state

Baseline procedure:
1. Confirm the node is using the expected durable identity and state paths.
2. Confirm the authority bootstrap inputs are the expected ones for the environment.
3. Compare durable state expectations with the live daemon status.
4. Check whether the issue is runtime-only, durable-state-only, or authority-driven.
5. Restart `quipd` only after confirming the restart will not destroy evidence needed for diagnosis.

The important split is:
- `identity/node.json` tells you who the node is
- `net/state.json` tells you what durable control-plane state it remembers
- `quipd` tells you what is live right now

Do not treat one of those layers as a substitute for the others.

## Safe State Reset

Use a state reset only when the operator intends to preserve the same identity while discarding bad or stale durable network state.

Typical reasons:
- corrupted or unusable durable network state
- stale routing or membership-derived state that cannot be safely reconciled
- controlled recovery after a known operational failure

Baseline procedure:
1. Stop `quipd`.
2. Back up `~/.quip/identity/node.json`.
3. Back up `~/.quip/net/state.json`.
4. Preserve the old `net/state.json` for rollback or analysis.
5. Remove or replace only `~/.quip/net/state.json`.
6. Keep `~/.quip/identity/node.json` unchanged.
7. Restart `quipd`.
8. Re-bootstrap and verify the node rejoins as the same logical identity.

State reset is not identity rotation. If the identity file changes, the operator is doing a different operation.

## Identity Rotation

Identity rotation means intentionally replacing the node's identity.

This is a major operation and should only happen when:
- the old identity is compromised
- a new node identity is explicitly required
- membership and authority-side trust are being updated accordingly

Baseline procedure:
1. Stop `quipd`.
2. Back up the current identity and durable state.
3. Generate or provision the new identity material through the approved process.
4. Replace `~/.quip/identity/node.json`.
5. Decide whether the old `net/state.json` is still valid for the new identity.
6. If not valid, reset or rebuild durable network state instead of reusing it blindly.
7. Update authority and membership material as required for the new identity.
8. Restart `quipd`.
9. Verify that the node is now participating as the intended new identity and not carrying stale trust assumptions.

Identity rotation should be treated as a controlled re-identity event, not a casual maintenance action.

## Restore After Loss

Use restore when the same logical node must come back after data loss, host loss, or corruption.

Baseline procedure:
1. Stop `quipd`.
2. Restore `identity/node.json`.
3. Restore `net/state.json`.
4. Verify file ownership, permissions, and passphrase inputs.
5. Restart `quipd`.
6. Validate authority bootstrap and runtime health.

See [`docs/backup-and-restore.md`](./backup-and-restore.md) for the full restore contract.

## What Operators Should Never Do

- Never generate a fresh production identity just because the daemon failed to start.
- Never overwrite `identity/node.json` without understanding whether the node is supposed to remain the same participant.
- Never delete `net/state.json` without taking a backup first.
- Never treat live runtime state as if it were safely recoverable from random process-local artifacts.
- Never assume a deployment environment changes the node model. The path root may change, but the node contract does not.
