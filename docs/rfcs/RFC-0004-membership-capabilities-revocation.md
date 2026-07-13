# RFC-0004: Enrollment, Membership, Capabilities, and Revocation

## Decision

Quipnet uses short-lived enrollment credentials, signed memberships, capability grants, and layered revocation instead of ambient trust.

## Invariants

- network membership is explicit and signed;
- capabilities are authoritative, roles are ergonomic;
- revocation combines short TTLs, urgent push, signed records, and denylist caching.

## Operational Requirement

No single always-online service may be required to authorize every steady-state peer connection.

