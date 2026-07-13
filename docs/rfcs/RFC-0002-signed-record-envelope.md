# RFC-0002: Signed Record Envelope and Canonical Encoding

## Decision

All mutable network state is transported as signed records with explicit sequence numbers, expiry, namespace scoping, and payload hashes.

## Envelope

- `network_id`
- `namespace`
- `record_type`
- `schema_version`
- `author_peer_id`
- `sequence`
- `issued_at`
- `expires_at`
- `previous_hash`
- `payload_hash`
- `payload`
- `signature`

## Rules

- Highest valid sequence wins for replaceable state.
- Append-only chains are used where auditability matters.
- Distribution scope is explicit and privacy-preserving by default.

