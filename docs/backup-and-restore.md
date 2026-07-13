# Quip Backup And Restore

This document defines how to back up and restore a Quip node without corrupting identity or treating runtime state like durable truth.

## Durable Assets

The minimum durable node assets are:
- `~/.quip/identity/node.json`
- `~/.quip/net/state.json`

Treat them differently:
- `identity/node.json` is the node's long-lived identity
- `net/state.json` is durable network and control-plane state

Losing `identity/node.json` is an identity event. Restoring the wrong identity file onto a machine is also an identity event.

## What Not To Back Up As Primary State

Do not treat the following as primary durable assets unless and until the runtime architecture explicitly says otherwise:
- transient daemon runtime state
- live session handles
- process-local sockets or PID files
- temporary caches
- ephemeral logs

Those belong under runtime, cache, or log concerns, not in the identity or net backup contract.

## Backup Policy

At minimum:
- back up `~/.quip/identity/node.json`
- back up `~/.quip/net/state.json`
- store the backups encrypted
- version backups so operators can roll back bad state changes
- keep identity backups under tighter access control than general node state backups

Recommended split:
- identity backup policy should prioritize secrecy and access control
- network state backup policy should prioritize recoverability and version history

## Safe Backup Procedure

The preferred production procedure is a daemon-owned encrypted export:
1. Keep `quipd` running so the daemon remains the single writer and snapshot authority.
2. Run `quip state backup` for the default backup location or `quip state export` for an explicit output path.
3. Record the backup timestamp, node hostname, environment, and authority bootstrap source used by the node.
4. Store the encrypted bundle under the operator's backup retention policy.

If the daemon-owned export surface is unavailable, fall back to a cold file copy:
1. Stop `quipd` or otherwise guarantee no concurrent durable-state writer is running.
2. Copy `~/.quip/identity/node.json`.
3. Copy `~/.quip/net/state.json`.
4. Record the backup timestamp, node hostname, environment, and authority bootstrap source used by the node.
5. Encrypt and store the copied artifacts.

Do not invent ad hoc hot-copy procedures. Live backup is only safe through an explicit daemon-owned snapshot or export path.

The current operator surface for that flow is:
- `quip state backup`
- `quip state export`

## Restore Procedure

The safe restore procedure is:
1. Stop `quipd`.
2. Confirm the target machine is supposed to become the same logical node.
3. Run `quip state restore --input <bundle.qbk> --confirm`.
4. Confirm file ownership and permissions are correct for the runtime user.
5. Restart `quipd`.
6. Inspect runtime status and authority state before trusting the node as healthy.

Do not restore only half the durable contract unless the recovery plan explicitly calls for it.

The current offline operator surface for that flow is:
- `quip state restore --input <bundle.qbk> --confirm`

## Identity Rotation Is Not Restore

Restoring an old identity backup and rotating to a new identity are different operations.

Use restore when:
- the same node is being recovered
- durable files were lost or corrupted
- the operator is intentionally reconstructing the same logical participant

Do not use restore when:
- the node should become a new identity
- membership should be re-established as a different participant
- the old identity may be compromised

## Corruption Handling

If durable state appears corrupted:
- preserve the corrupted files for forensic analysis
- restore from the most recent known-good encrypted backup
- verify the authority bootstrap inputs before restart
- inspect whether corruption affected only `net/state.json` or also `identity/node.json`

If identity material may be compromised, treat the event as a security incident, not a routine restore.

## Environment Mapping

The same durable contract maps across deployment targets:
- local user node: `~/.quip/...`
- systemd service: `/var/lib/quip/.quip/...`
- container runtime: mounted `/home/quip/.quip/...`
- kubernetes: mounted volume backing `/home/quip/.quip/...`

The path root may change by environment, but the concern split must stay the same.
