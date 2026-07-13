#!/usr/bin/env bash
set -euo pipefail

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to sign release artifacts" >&2
  exit 1
fi

artifacts=(
  "dist/quip-source.tar.gz"
  "release/artifacts/quip-source.sha256"
)

for artifact in "${artifacts[@]}"; do
  test -f "${artifact}"
  cosign sign-blob --yes \
    --output-signature "${artifact}.sig" \
    --output-certificate "${artifact}.pem" \
    "${artifact}"
done
