# Quip Release Checklist

Use this checklist before calling a Quip release production-ready.

This is a ship gate, not a planning document.

It should be used alongside:
- [`docs/production-readiness.md`](./production-readiness.md)
- [`docs/verification-plan.md`](./verification-plan.md)
- [`docs/milestones.md`](./milestones.md)

## Runtime Ownership

- [ ] `quipd` is the single owner of live runtime sessions.
- [ ] `quipd` is the single owner of active path state.
- [ ] Session close, upgrade, and reconcile all route through the daemon API.
- [ ] Restart does not restore fake live runtime ownership from persisted state.

## Durable State

- [ ] `~/.quip/identity/node.json` is the canonical durable identity root.
- [ ] `~/.quip/net/state.json` is the canonical durable network state root.
- [ ] `~/.quip/net/state.json` has an enforced schema version.
- [ ] Durable fields are explicitly allowlisted.
- [ ] Runtime-only fields are rejected from durable state.
- [ ] Migration behavior is explicit and tested.

## CLI Surface

- [ ] `quip status` reflects daemon-backed runtime truth.
- [ ] Runtime inspection commands are daemon-backed.
- [ ] Session lifecycle commands are daemon-backed.
- [ ] Authority inspection and sync commands are daemon-backed.
- [ ] Identity inspection commands are explicit and safe.
- [ ] State validation and reset commands are explicit and safe.
- [ ] State migration commands are explicit and safe.
- [ ] CLI output clearly distinguishes runtime truth from durable remembered state.

## Authority

- [ ] Authority origin is inspectable.
- [ ] Authority subject is inspectable when pinned.
- [ ] Authority sync status is inspectable.
- [ ] Membership and capability state are inspectable.
- [ ] Revocation changes affect runtime behavior correctly.
- [ ] Capability changes affect runtime behavior correctly.
- [ ] Authority mismatch is diagnosable without operator guesswork.

## Path And Reconnect

- [ ] Direct path behavior is inspectable.
- [ ] Relay fallback behavior is inspectable.
- [ ] Path migration behavior is inspectable.
- [ ] Reconnect behavior is daemon-owned.
- [ ] Reconnect behavior is deterministic under controlled scenarios.
- [ ] Runtime path reporting explains the active path and fallback state honestly.

## Operator Recovery

- [ ] Identity inspection workflow is backed by real commands.
- [ ] Durable state validation workflow is backed by real commands.
- [ ] Durable state migration workflow is backed by real commands.
- [ ] Safe state reset workflow is backed by real commands.
- [ ] Authority sync and authority diagnostics are backed by real commands.
- [ ] Backup and restore procedures are documented and match implementation.

## Deploy Surfaces

- [ ] systemd uses the same node contract as the code.
- [ ] Docker uses the same node contract as the code.
- [ ] Kubernetes uses the same node contract as the code.
- [ ] Nix uses the same node contract as the code.
- [ ] Durable assets are laid out under `~/.quip/{concern}/...` or the environment equivalent.
- [ ] Secrets are injected, not baked into published runtime artifacts.

## Verification

- [ ] Deterministic scenario coverage exists for the real runtime model.
- [ ] Restart behavior is verified.
- [ ] Authority reevaluation behavior is verified.
- [ ] Reconnect and path behavior are verified.
- [ ] Schema validation failure behavior is verified.
- [ ] Backup and restore behavior is verified.
- [ ] At least one real trace is recorded for the active runtime model.
- [ ] Recorded traces are verified.
- [ ] Recorded traces are replayed.
- [ ] Recorded traces pass CI-style validation.
- [ ] Operator command surface is exercised through system-level scenarios.

## Documentation

- [ ] README matches the shipped product story.
- [ ] Runtime architecture docs match implementation.
- [ ] State model and state schema docs match implementation.
- [ ] CLI surface docs match implementation.
- [ ] Operator workflow docs match implementation.
- [ ] Release gate docs match implementation.

## Final Decision

- [ ] All milestones in [`docs/milestones.md`](./milestones.md) are complete.
- [ ] No known production gate in [`docs/production-readiness.md`](./production-readiness.md) is being waived.
- [ ] The release is being called production-ready based on runnable evidence, not confidence or naming cleanup.
