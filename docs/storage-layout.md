# Quip Storage Layout

All durable local node data belongs under `~/.quip/`. No component should create or depend on a nested product directory such as `~/.quip/product/` or any similar product-nested variant.

## Canonical Concern Directories

- `~/.quip/identity/`
  - long-lived local node identity material
  - canonical node identity path: `~/.quip/identity/node.json`
- `~/.quip/net/`
  - durable network, routing, netcheck, and control-plane state
  - canonical daemon state path: `~/.quip/net/state.json`
- `~/.quip/log/`
  - optional local log material when operators choose file-backed logging
- `~/.quip/cache/`
  - rebuildable caches only; never primary durable state
- `~/.quip/run/`
  - optional process-local runtime artifacts when they must live under the app root
  - never treat this directory as durable state

## Rules

- Identity and control-plane state must live in separate concern directories.
- Runtime-only session state must not be persisted as if it were durable control-plane state.
- Every deployment target should mirror the same concern split even when the home directory changes.
- Service installations should map `~/.quip/...` to the service account home, for example `/var/lib/quip/.quip/...`.
- Container images should mount the whole `~/.quip/` root or explicit concern subdirectories, not a legacy nested product directory.
- Backups and restore procedures must treat `identity/` and `net/` as separate assets with different risk profiles.
