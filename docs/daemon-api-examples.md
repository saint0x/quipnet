# Quip Daemon API Examples

This document provides concrete example request and response shapes for the daemon API.

It builds on:
- [`docs/daemon-api-schema.md`](./daemon-api-schema.md)
- [`docs/cli-surface.md`](./cli-surface.md)

The point is to make the control surface implementable and testable without ambiguity about the basic payload model.

The corresponding machine-readable fixtures live under [`../fixtures/daemon/`](../fixtures/daemon).

## Common Request Envelope

```json
{
  "request_id": "req-0001",
  "operation": "runtime.status",
  "auth": {
    "kind": "local_socket_peer"
  },
  "payload": {}
}
```

## Common Success Envelope

```json
{
  "ok": true,
  "request_id": "req-0001",
  "result": {},
  "error": null
}
```

## Common Error Envelope

```json
{
  "ok": false,
  "request_id": "req-0001",
  "result": null,
  "error": {
    "code": "stale_runtime_reference",
    "message": "session id is no longer owned by this daemon run",
    "details": {
      "session_id": "sess-0009"
    }
  }
}
```

## `runtime.status`

Request:

```json
{
  "request_id": "req-1000",
  "operation": "runtime.status",
  "auth": {
    "kind": "local_socket_peer"
  },
  "payload": {}
}
```

Response:

```json
{
  "ok": true,
  "request_id": "req-1000",
  "result": {
    "truth_kind": "runtime",
    "daemon_health": "ready",
    "identity": {
      "status": "loaded",
      "path": "~/.quip/identity/node.json",
      "node_id": "node-001"
    },
    "durable_state": {
      "status": "loaded",
      "path": "~/.quip/net/state.json",
      "schema_version": 1
    },
    "authority": {
      "sync_status": "in_sync",
      "last_accepted_revision": "rev-0042"
    },
    "runtime_summary": {
      "session_count": 2,
      "active_path_count": 2,
      "reconnect_state": "idle"
    }
  },
  "error": null
}
```

## `runtime.sessions.list`

Response:

```json
{
  "ok": true,
  "request_id": "req-1001",
  "result": {
    "truth_kind": "runtime",
    "sessions": [
      {
        "session_id": "sess-0001",
        "peer_id": "peer-001",
        "state": "active",
        "active_path_class": "direct",
        "age_seconds": 124,
        "last_activity_seconds": 2
      },
      {
        "session_id": "sess-0002",
        "peer_id": "peer-002",
        "state": "degraded",
        "active_path_class": "relay",
        "age_seconds": 380,
        "last_activity_seconds": 5
      }
    ]
  },
  "error": null
}
```

## `session.connect`

Request:

```json
{
  "request_id": "req-2000",
  "operation": "session.connect",
  "auth": {
    "kind": "local_socket_peer"
  },
  "payload": {
    "peer_id": "peer-003",
    "path_preference": "direct_preferred"
  }
}
```

Response:

```json
{
  "ok": true,
  "request_id": "req-2000",
  "result": {
    "truth_kind": "runtime",
    "session": {
      "session_id": "sess-0100",
      "state": "connecting",
      "initial_path_class": "direct"
    }
  },
  "error": null
}
```

## `session.close`

Request:

```json
{
  "request_id": "req-2001",
  "operation": "session.close",
  "auth": {
    "kind": "local_socket_peer"
  },
  "payload": {
    "session_id": "sess-0100",
    "reason": "operator_requested"
  }
}
```

## `authority.show`

Response:

```json
{
  "ok": true,
  "request_id": "req-3000",
  "result": {
    "truth_kind": "runtime_and_durable",
    "configured_authority": {
      "origin": "https://authority.quip.example",
      "subject": "authority-root"
    },
    "accepted_authority": {
      "last_accepted_revision": "rev-0042",
      "last_sync_status": "in_sync"
    }
  },
  "error": null
}
```

## `state.show`

Response:

```json
{
  "ok": true,
  "request_id": "req-3999",
  "result": {
    "truth_kind": "durable",
    "state_path": "/Users/example/.quip/net/state.json",
    "present": true,
    "schema_version": 1,
    "valid": true,
    "violations": [],
    "summary": {
      "network": "personalcloud-prod",
      "local_peer_id": "peer-local-001",
      "roles": ["edge", "observer"],
      "bootstrap_hints": 2,
      "relays": 1,
      "peers": 2,
      "capability_grants": 1,
      "revocations": 0,
      "denied_peers": 0,
      "path_candidates": 3
    }
  },
  "error": null
}
```

## `state.validate`

Response:

```json
{
  "ok": true,
  "request_id": "req-4000",
  "result": {
    "truth_kind": "durable",
    "state_path": "/Users/example/.quip/net/state.json",
    "present": true,
    "schema_version": 1,
    "valid": true,
    "violations": []
  },
  "error": null
}
```

## `state.export`

Request:

```json
{
  "request_id": "req-40005",
  "operation": "state.export",
  "auth": {
    "kind": "local_process"
  },
  "payload": {
    "output_path": "/Users/example/.quip/backup/personalcloud-prod-1720000123.qbk",
    "passphrase": "backup-passphrase",
    "hostname": "host-a",
    "environment": "local",
    "overwrite": false
  }
}
```

Response:

```json
{
  "ok": true,
  "request_id": "req-40005",
  "result": {
    "truth_kind": "durable",
    "bundle_path": "/Users/example/.quip/backup/personalcloud-prod-1720000123.qbk",
    "created_at_unix_secs": 1720000123,
    "hostname": "host-a",
    "environment": "local",
    "network": "personalcloud-prod",
    "identity_sha256_hex": "1111111111111111111111111111111111111111111111111111111111111111",
    "state_sha256_hex": "2222222222222222222222222222222222222222222222222222222222222222",
    "durable_state_present": true,
    "durable_state_valid": true
  },
  "error": null
}
```

## `state.reset`

Request:

```json
{
  "request_id": "req-4001",
  "operation": "state.reset",
  "auth": {
    "kind": "local_socket_peer"
  },
  "payload": {
    "scope": "network_state_only",
    "confirmation": "preserve-identity-reset-network-state"
  }
}
```

Response:

```json
{
  "ok": true,
  "request_id": "req-4001",
  "result": {
    "truth_kind": "durable",
    "identity_preserved": true,
    "network_state_reset": true,
    "next_action": "daemon_restart_required"
  },
  "error": null
}
```
