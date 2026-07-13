# RFC-0006: Relay Protocol and Relay Trust Model

## Decision

Relays are authenticated, opaque forwarders that guarantee reachability, accelerate bootstrap, and provide controlled fallback when direct paths are unavailable or undesirable.

## Relay Guarantees

- source authentication
- destination authorization
- no plaintext application access
- bandwidth and session quotas
- anti-amplification controls
- regional placement and signed relay maps

## Deployment

Relays are split into bootstrap, performance, and peer-relay tiers with different capacity and policy expectations.

