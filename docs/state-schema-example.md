# Quip Durable State Example

This document gives a concrete example shape for `~/.quip/net/state.json`.

It exists to make the durable schema contract easier to implement and easier to review. The exact field names may evolve, but the separation between durable facts and runtime-owned state must not.

This document builds on:
- [`docs/state-schema.md`](./state-schema.md)
- [`docs/state-model.md`](./state-model.md)

## Example Shape

```json
{
  "schema_version": 1,
  "network": "personalcloud-prod",
  "local_peer_id": "peer-local-001",
  "roles": ["Edge", "Observer"],
  "membership": {
    "network_id": "personalcloud-prod",
    "subject_peer_id": "peer-local-001",
    "issuer_peer_id": "peer-authority-001",
    "issued_at": 1720000000,
    "expires_at": 1820000000,
    "roles": ["member"],
    "signature": []
  },
  "capability_grants": [
    {
      "network_id": "personalcloud-prod",
      "subject_peer_id": "peer-local-001",
      "issuer_peer_id": "peer-authority-001",
      "capabilities": ["connect", "sync"],
      "protocol_scopes": ["/quip/control/1"],
      "resource_limits": {
        "bandwidth_bps": 1500000000,
        "concurrent_streams": 64,
        "max_object_bytes": 10485760
      },
      "constraints": ["region=us-east-1"],
      "not_before": 1720000000,
      "expires_at": 1820000000,
      "sequence": 7,
      "signature": []
    }
  ],
  "revocations": [],
  "denied_peers": [],
  "bootstrap": [
    {
      "peer": "peer-relay-001",
      "addresses": ["udp://203.0.113.10:443"],
      "protocols": ["/quip/relay/1"],
      "metadata": {
        "source": "authority"
      }
    }
  ],
  "relay_map": null,
  "peers": [],
  "netcheck": {
    "nat_type": "Unknown",
    "udp_reachable": false,
    "ipv6_reachable": false,
    "hairpin_supported": false,
    "public_udp_addr": null,
    "port_mapped": false,
    "probe_observations": []
  },
  "queue_policies": [],
  "path_candidates": []
}
```

## What This Example Intentionally Omits

This example intentionally does not contain:
- live session IDs
- active transport handles
- current reconnect timers
- current active path locks
- in-flight authority sync work
- daemon process metadata

If a field only makes sense while `quipd` is alive, it should not be added to this file.

## Review Rules

Any proposal to add a new durable field should answer:
- does this survive restart honestly
- does this describe a durable remembered fact
- can this be validated and migrated safely
- would this become misleading if copied into a new daemon run as though it were live truth

If the last answer is yes, the field belongs in runtime state, not `state.json`.

The corresponding fixture files live under [`../fixtures/state/`](../fixtures/state).
