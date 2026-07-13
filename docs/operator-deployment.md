# Quip Operator Deployment

Quip production nodes must boot with a durable runtime identity, durable daemon state, and an explicit authority bootstrap source.

Canonical storage layout lives in [`docs/storage-layout.md`](./storage-layout.md).
The node and daemon model behind this deployment contract lives in [`docs/network-foundation.md`](./network-foundation.md).

The deployment assets in this repository now share the same contract:
- `QUIP_NETWORK`
- `QUIP_STATE_PATH`
- `QUIP_IDENTITY_PATH`
- `QUIP_IDENTITY_PASSPHRASE`
- `QUIP_AUTHORITY_ORIGIN`
- optional `QUIP_AUTHORITY_SUBJECT`

## Required Runtime Contract

Production nodes should always:
- persist `~/.quip/`
- inject `QUIP_IDENTITY_PASSPHRASE` from a secret manager or encrypted environment file
- set `--sync` and `--revocation-sync`
- bootstrap from an authority origin unless deliberately operating from an offline snapshot

The minimum durable concern split is:
- `~/.quip/identity/node.json`
- `~/.quip/net/state.json`

Losing `~/.quip/identity/node.json` or changing the passphrase unexpectedly creates an operational identity event. Losing `~/.quip/net/state.json` drops routing, netcheck, and session orchestration state. Treat both as durable node assets.

## systemd

[`deploy/systemd/quipd.service`](../deploy/systemd/quipd.service) loads optional overrides from `/etc/quip/quipd.env`.

That file is the intended place for:
- `QUIP_IDENTITY_PASSPHRASE`
- `QUIP_AUTHORITY_ORIGIN`
- optional `QUIP_AUTHORITY_SUBJECT`

The service persists state under `~quip/.quip/`, which maps to `/var/lib/quip/.quip/` in the provided unit, with durable assets split by concern instead of product-nested directories.

## Docker

[`deploy/docker/Dockerfile`](../deploy/docker/Dockerfile) and [`deploy/docker/docker-compose.dev.yaml`](../deploy/docker/docker-compose.dev.yaml) mount `~quip/.quip/` and pass the same bootstrap variables into the container. For production, replace the development passphrase placeholder and inject the secret from your container platform rather than committing it into Compose files. Do not reintroduce `~/.quip/quip/` inside the container image or mounted volume layout.

## Kubernetes

[`deploy/kubernetes/deployment.yaml`](../deploy/kubernetes/deployment.yaml) now depends on:
- [`deploy/kubernetes/configmap.yaml`](../deploy/kubernetes/configmap.yaml) for bootstrap configuration
- [`deploy/kubernetes/secret.yaml`](../deploy/kubernetes/secret.yaml) for `QUIP_IDENTITY_PASSPHRASE`
- [`deploy/kubernetes/pvc.yaml`](../deploy/kubernetes/pvc.yaml) for durable `~/.quip/`

Replace the placeholder secret before deployment. Do not use `emptyDir` for real nodes unless the node is intentionally ephemeral.

Backups and restore policy for the durable node assets live in [`docs/backup-and-restore.md`](./backup-and-restore.md).
Operator run procedures live in [`docs/operator-workflows.md`](./operator-workflows.md).
Authority inspection and mismatch procedures live in [`docs/authority-operations.md`](./authority-operations.md).

## Nix

[`deploy/nix/module.nix`](../deploy/nix/module.nix) exposes options for:
- `services.quip.identityPath`
- `services.quip.identityPassphraseEnvironmentVariable`
- `services.quip.environmentFile`
- `services.quip.authorityOrigin`
- `services.quip.authoritySubject`
- `services.quip.sync`
- `services.quip.revocationSync`

Use `services.quip.environmentFile` to source the passphrase securely.
