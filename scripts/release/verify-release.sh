#!/usr/bin/env bash
set -euo pipefail

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to verify release artifacts" >&2
  exit 1
fi

artifacts=(
  "dist/quicnet-source.tar.gz"
  "release/artifacts/quicnet-source.sha256"
)

for artifact in "${artifacts[@]}"; do
  test -f "${artifact}"
  test -f "${artifact}.sig"
  test -f "${artifact}.pem"
  cosign verify-blob \
    --certificate "${artifact}.pem" \
    --signature "${artifact}.sig" \
    "${artifact}" >/dev/null
done

