# Quipnet Operator Deployment

Quipnet production nodes must boot with a durable runtime identity, durable daemon state, and an explicit authority bootstrap source. The deployment assets in this repository now share the same contract:

- `QUICNET_NETWORK`
- `QUICNET_STATE_PATH`
- `QUICNET_IDENTITY_PATH`
- `QUICNET_IDENTITY_PASSPHRASE`
- `QUICNET_AUTHORITY_ORIGIN`
- optional `QUICNET_AUTHORITY_SUBJECT`

## Required Runtime Contract

Production nodes should always:

- persist `/var/lib/quicnet`
- inject `QUICNET_IDENTITY_PASSPHRASE` from a secret manager or encrypted environment file
- set `--sync` and `--revocation-sync`
- bootstrap from an authority origin unless deliberately operating from an offline snapshot

Losing `identity.json` or changing the passphrase unexpectedly creates an operational identity event. Losing `state.json` drops routing, netcheck, and session orchestration state. Treat both as durable node assets.

## systemd

[`deploy/systemd/quicnetd.service`](../deploy/systemd/quicnetd.service) loads optional overrides from `/etc/quipnet/quipnetd.env`. That file is the intended place for:

- `QUICNET_IDENTITY_PASSPHRASE`
- `QUICNET_AUTHORITY_ORIGIN`
- optional `QUICNET_AUTHORITY_SUBJECT`

The service persists state under `/var/lib/quicnet`.

## Docker

[`deploy/docker/Dockerfile`](../deploy/docker/Dockerfile) and [`deploy/docker/docker-compose.dev.yaml`](../deploy/docker/docker-compose.dev.yaml) now mount `/var/lib/quicnet` and pass the same bootstrap variables into the container. For production, replace the development passphrase placeholder and inject the secret from your container platform rather than committing it into Compose files.

## Kubernetes

[`deploy/kubernetes/deployment.yaml`](../deploy/kubernetes/deployment.yaml) now depends on:

- [`deploy/kubernetes/configmap.yaml`](../deploy/kubernetes/configmap.yaml) for bootstrap configuration
- [`deploy/kubernetes/secret.yaml`](../deploy/kubernetes/secret.yaml) for `QUICNET_IDENTITY_PASSPHRASE`
- [`deploy/kubernetes/pvc.yaml`](../deploy/kubernetes/pvc.yaml) for durable `/var/lib/quicnet`

Replace the placeholder secret before deployment. Do not use `emptyDir` for real nodes unless the node is intentionally ephemeral.

## Nix

[`deploy/nix/module.nix`](../deploy/nix/module.nix) exposes options for:

- `services.quicnet.identityPath`
- `services.quicnet.identityPassphraseEnvironmentVariable`
- `services.quicnet.environmentFile`
- `services.quicnet.authorityOrigin`
- `services.quicnet.authoritySubject`
- `services.quicnet.sync`
- `services.quicnet.revocationSync`

Use `services.quicnet.environmentFile` to source the passphrase securely.
