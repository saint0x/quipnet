# RFC-0005: Endpoint Discovery, NAT Traversal, and Path State Machine

## Decision

Endpoint discovery combines bootstrap hints, signed endpoint records, local discovery, observer-assisted netcheck, and coordinated upgrade from relay to direct paths.

## State Machine

1. bootstrap via known hints or relay
2. collect endpoint candidates
3. characterize NAT and reachability
4. validate direct routing candidates
5. migrate when improvement exceeds hysteresis thresholds

## Observability

Every failure must record whether the block was NAT, firewall, policy, timeout, or incompatible protocol behavior.

