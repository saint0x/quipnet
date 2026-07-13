# Runtime And Session Ownership

- [ ] Build a real daemon-owned runtime session manager instead of relying on transport instance locality.
- [ ] Separate persisted daemon state from live runtime state as distinct models with explicit projection boundaries.
- [ ] Introduce a stable daemon control API for runtime session inspection and lifecycle operations.
- [ ] Reintroduce operator session close, upgrade, and reconcile against the daemon API only.
- [ ] Make daemon runtime session status observable without depending on cached local state.
- [ ] Ensure runtime session identity, path, and protocol state survive daemon loop boundaries correctly.
- [ ] Define and enforce single-writer ownership semantics for live session state.
- [ ] Decide and implement behavior for daemon restart with previously persisted sessions.
- [ ] Decide and implement behavior for runtime session loss when the daemon crashes or is killed.
- [ ] Remove any remaining code paths that treat persisted `active_sessions` as primary truth.

# Daemon API

- [ ] Define shared daemon API request and response types in a stable crate boundary.
- [ ] Implement a read-only daemon API for runtime status, runtime sessions, path decisions, and health.
- [ ] Implement authenticated local control operations for connect, session close, session upgrade, and reconcile.
- [ ] Add daemon API versioning and explicit compatibility policy.
- [ ] Define daemon API error codes and machine-readable failure responses.
- [ ] Add daemon API tests for success, validation failure, stale state, and runtime-not-owned cases.
- [ ] Decide transport for the daemon API for production use and standardize it.
- [ ] Add access control for local daemon API callers.
- [ ] Add timeouts, resource limits, and abuse protection for local daemon API requests.

# Transport Runtime

- [ ] Replace metadata-only QUIC adapter behavior with a true runtime-owned connection abstraction.
- [ ] Add explicit runtime session lifecycle states beyond raw snapshots.
- [ ] Track runtime listeners, not just connection/session snapshots.
- [ ] Persist only the subset of session information that is safe and useful across restarts.
- [ ] Model transport teardown, migration, and replacement as explicit runtime events.
- [ ] Ensure direct and relay transports share the same lifecycle and ownership semantics.
- [ ] Add runtime checks for duplicate logical sessions and duplicate transport sessions.
- [ ] Define concurrent session behavior for the same peer and protocol.
- [ ] Add protection against stale runtime session handles after migration or close.

# Authority And Membership

- [ ] Make authority sync and live runtime session behavior one coherent state machine.
- [ ] Define exact behavior when membership changes while live sessions are open.
- [ ] Define exact behavior when capability grants are added while live sessions are open.
- [ ] Define exact behavior when capability grants are revoked while live sessions are open.
- [ ] Define exact behavior when membership is revoked while live sessions are open.
- [ ] Define exact behavior when authority snapshot subject changes unexpectedly.
- [ ] Reject or reconcile stale authority artifacts more rigorously than simple merge behavior.
- [ ] Add runtime policy reevaluation hooks on authority-driven state changes.
- [ ] Add tests for revocation-driven runtime session closure and reconnect prevention.

# Reconnect, Retry, And Recovery

- [ ] Add daemon-owned reconnect policy for dropped direct sessions.
- [ ] Add daemon-owned retry/backoff policy for failed relay establishment.
- [ ] Add recovery behavior for relay control-plane failure during active sessions.
- [ ] Add path downgrade and path recovery behavior after direct-path loss.
- [ ] Add reconnect suppression and quarantine behavior for repeated failures.
- [ ] Define recovery behavior for state/identity mismatch after operator intervention.
- [ ] Add recovery behavior for corrupted persisted state files.

# Path Management

- [ ] Turn path selection into a continuously maintained runtime path manager instead of periodic snapshot recompute alone.
- [ ] Add explicit path health transition logic.
- [ ] Add path hysteresis to avoid flapping between nearly equivalent routes.
- [ ] Add route stickiness policy by traffic class.
- [ ] Add better direct-versus-relay migration thresholds.
- [ ] Add path quality history retention and bounded storage policy.
- [ ] Add runtime probes for path degradation and recovery.
- [ ] Add operator-visible path decision explanations through the daemon API.

# Netcheck And Reachability

- [ ] Replace fixture-style reprobe behavior with more realistic network probing logic.
- [ ] Add runtime scheduling policy for netcheck probes.
- [ ] Add rate limiting and backoff for repeated reprobes.
- [ ] Add richer NAT and IPv6 classification behavior.
- [ ] Add explicit handling for conflicting or unstable reachability observations.
- [ ] Add persistence and expiry policy for network observations.
- [ ] Add tests for network change triggers across direct and relay session transitions.

# CLI And Operator UX

- [ ] Move runtime-dependent operator commands behind the daemon API instead of cached local files.
- [ ] Distinguish clearly between cached control-plane state and live runtime state in all operator output.
- [ ] Add a dedicated `quicnet daemon` subcommand surface for daemon API interaction.
- [ ] Add structured output modes for runtime status and session views.
- [ ] Add command-level help text that reflects daemon-owned versus standalone behavior honestly.
- [ ] Add operator workflows for identity inspection, authority subject inspection, and runtime mismatch diagnosis.
- [ ] Add explicit operator workflows for safe state reset and identity rotation.

# Persistence And Storage

- [ ] Define the final persisted state schema boundary for durable versus ephemeral fields.
- [ ] Add schema versioning for daemon state files.
- [ ] Add forward migration for old state schema versions.
- [ ] Add corruption detection for persisted state.
- [ ] Add atomic write and rollback behavior for all persistent daemon state updates.
- [ ] Add backup and restore guidance for `~/.quip/quicnet/`.
- [ ] Add retention policy for logs, traces, and diagnostic artifacts under `~/.quip/`.
- [ ] Standardize all runtime artifacts, logs, sockets, traces, and caches under `~/.quip/{concern}/`.

# Identity And Key Management

- [ ] Split node root identity, daemon-issued workload credentials, and session keys into explicit operational workflows.
- [ ] Add identity rotation procedures.
- [ ] Add passphrase rotation procedures.
- [ ] Add hardware-backed or external key store integration points.
- [ ] Add explicit policy for identity backup and disaster recovery.
- [ ] Add detection and response for unexpected identity replacement.
- [ ] Add tests for identity mismatch across authority sync, runtime start, and operator commands.

# Security

- [ ] Add authenticated local daemon API access control.
- [ ] Add secret-handling review for passphrase and key material flows.
- [ ] Add rate limiting and abuse protection for local and relay control surfaces.
- [ ] Add replay and tampering checks where still missing in runtime control flows.
- [ ] Add audit logging for sensitive local control operations.
- [ ] Add a concrete incident response workflow for identity compromise.
- [ ] Add a concrete incident response workflow for authority compromise.
- [ ] Add a concrete incident response workflow for relay abuse or relay credential misuse.

# Deployment And Operations

- [ ] Finish moving all operator-facing runtime artifacts to the final `~/.quip/{concern}/` layout.
- [ ] Add daemon API configuration to deploy assets.
- [ ] Add production-ready health and readiness checks against the daemon API.
- [ ] Add secret rotation procedures for every deployment target.
- [ ] Add upgrade procedures that preserve identity and state safely.
- [ ] Add rollback procedures that preserve identity and state safely.
- [ ] Add node replacement procedures.
- [ ] Add bootstrap and enrollment runbooks for first-node and additional-node bring-up.
- [ ] Add recovery runbooks for lost identity, lost state, and authority unavailability.

# Observability

- [ ] Add structured daemon API status output for runtime sessions, path state, and authority state.
- [ ] Add metrics for session open, close, migrate, reconcile, and failure reasons.
- [ ] Add metrics for direct-versus-relay utilization.
- [ ] Add metrics for authority sync, revocation sync, and policy-driven closure.
- [ ] Add tracing spans for runtime session lifecycle operations.
- [ ] Add operator-facing diagnostics for why a session is absent from runtime but present in cache.
- [ ] Add bounded diagnostic history for path and session transitions.

# Testing And Verification

- [ ] Add daemon API integration tests.
- [ ] Add runtime-session-manager integration tests.
- [ ] Add restart and crash-recovery tests for runtime and persisted session state interaction.
- [ ] Add authority revocation tests against live runtime sessions.
- [ ] Add reconnect and retry behavior tests.
- [ ] Add mixed direct and relay lifecycle tests under repeated path changes.
- [ ] Add deterministic host-backed scenario coverage that maps to actual production workflows.
- [ ] Add release verification that exercises daemon API, identity binding, authority sync, and runtime session lifecycle together.
- [ ] Add failure-injection coverage for corrupted state, unavailable authority, unavailable relay, and path flapping.
- [ ] Add multi-node integration scenarios with real daemon-owned runtime coordination.

# Release Readiness

- [ ] Define the production freeze criteria.
- [ ] Define the minimum daemon API stability bar for first production use.
- [ ] Define the minimum observability bar for first production use.
- [ ] Define the minimum recovery/runbook bar for first production use.
- [ ] Define the minimum deterministic scenario coverage bar for first production use.
- [ ] Run a final production-readiness audit against all items above and close the remaining gaps.
