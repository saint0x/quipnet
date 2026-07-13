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
1. Run `quip identity path` to confirm the exact identity file path, file kind, size, permissions, passphrase env, and control discovery path for this node.
2. Verify that `identity/node.json` exists and has correct ownership and permissions.
3. Confirm the passphrase source configured for the node.
4. Run `quip identity verify` to compare the loaded daemon identity against durable state and authority expectations.
5. Compare the node's expected identity with deployment records or authority-side expectations.
6. If the file is missing, corrupted, or unexpected, stop and treat it as an identity incident rather than guessing.

Do not silently generate a new identity on a production node that is supposed to remain the same logical participant.

## Runtime Mismatch Diagnosis

Use runtime mismatch diagnosis when:
- durable files look correct but runtime behavior does not
- the daemon appears to disagree with operator expectations
- direct or relay behavior is not matching stored state or authority state

Baseline procedure:
1. Run `quip runtime target` to confirm the live daemon discovery target, runtime instance id, pid, network, and the exact durable paths the operator surface is pointed at.
2. Run `quip runtime diagnose --events-limit <n>` to classify the problem as `healthy`, `runtime_only`, `authority_driven`, `durable_state_only`, or `mixed`.
3. Inspect the reported issues and confirm whether they are durable-state, authority, or runtime failures before taking action.
4. Use the attached session, path, listener, and event inventory from `runtime diagnose` to confirm whether the issue is live, recently closed, or only remembered on disk.
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
1. Run `quip state backup` or `quip state export` to capture the current durable identity and network state bundle before changing anything.
2. Preserve the previous bundle for rollback or analysis.
3. Run `quip state reset --confirm` through the live daemon so only durable network state is removed.
4. Keep `~/.quip/identity/node.json` unchanged.
5. Restart `quipd` after reset completes.
6. Re-bootstrap and verify the node rejoins as the same logical identity.

State reset is not identity rotation. If the identity file changes, the operator is doing a different operation.

## Identity Rotation

Identity rotation means intentionally replacing the node's identity.

This is a major operation and should only happen when:
- the old identity is compromised
- a new node identity is explicitly required
- membership and authority-side trust are being updated accordingly

Baseline procedure:
1. Stop `quipd`.
2. Run `quip state backup` or `quip state export` to preserve the current identity and durable state before rotation.
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
2. Run `quip state restore --input <bundle.qbk> --confirm`.
3. Verify file ownership, permissions, and passphrase inputs.
4. Restart `quipd`.
5. Validate authority bootstrap and runtime health.

See [`docs/backup-and-restore.md`](./backup-and-restore.md) for the full restore contract.

## What Operators Should Never Do

- Never generate a fresh production identity just because the daemon failed to start.
- Never overwrite `identity/node.json` without understanding whether the node is supposed to remain the same participant.
- Never delete `net/state.json` without taking a backup first.
- Never treat live runtime state as if it were safely recoverable from random process-local artifacts.
- Never assume a deployment environment changes the node model. The path root may change, but the node contract does not.
