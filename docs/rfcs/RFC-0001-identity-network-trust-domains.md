# RFC-0001: Identity, Network, and Trust Domains

## Decision

Quipnet identities are cryptographic and self-certifying. `PeerId` is derived from the canonical public identity key, and `NetworkId` scopes trust, policy, discovery, and record visibility.

## Invariants

- IP addresses are routing hints, never identity.
- Nodes may join multiple networks, but state remains isolated by `NetworkId`.
- Session keys rotate frequently; durable identity rotates only through an auditable signed transition.

## Trust Boundaries

- Offline roots delegate to online enrollment authorities.
- Local workloads never inherit the daemon root key directly.
- Relay operators forward opaque ciphertext and cannot terminate application payload encryption.

## Rollout

Milestone 2 implements durable identity, session credentials, enrollment, and revocation using these boundaries.

