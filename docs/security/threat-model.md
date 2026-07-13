# Threat Model

## Adversaries

- unauthenticated internet scanners and spoofers
- authorized but malicious peers
- compromised relays
- compromised enrollment credentials
- network-routing observers
- supply-chain attackers

## Required Properties

- authenticated encrypted peer traffic
- cryptographic binding between durable identity and active session
- capability-based least privilege
- revocation propagation without a global online choke point
- no plaintext payload exposure at relays
- deterministic validation of attacker-controlled records and frames

## Non-Goals

- Quipnet does not provide application-level authorization semantics for storage, inference, or consensus payloads.

