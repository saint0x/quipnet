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
  "network": {
    "id": "personalcloud-prod",
    "authority": {
      "origin": "https://authority.quip.example",
      "subject": "authority-root"
    }
  },
  "authority_state": {
    "last_accepted_revision": "rev-0042",
    "last_sync_at": "2026-07-13T15:04:05Z",
    "membership": {
      "local_node_status": "active",
      "accepted_groups": ["core", "relay-eligible"]
    },
    "capabilities": {
      "local": ["connect", "relay", "sync"]
    },
    "revocations": {
      "known_revisions": ["rev-0038", "rev-0040"]
    }
  },
  "peers": {
    "peer-001": {
      "last_seen_identity": "peer-001",
      "relationship": "known",
      "topology": {
        "last_reachable_at": "2026-07-13T14:00:00Z",
        "reachability_class": "direct_or_relay"
      }
    }
  },
  "path_history": {
    "peer-001": {
      "preferred_path_class": "direct",
      "last_successful_path_class": "relay",
      "observations": [
        {
          "at": "2026-07-13T14:00:00Z",
          "path_class": "relay",
          "outcome": "success"
        }
      ]
    }
  },
  "recovery": {
    "last_clean_checkpoint_at": "2026-07-13T15:00:00Z",
    "integrity_state": "clean"
  }
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
