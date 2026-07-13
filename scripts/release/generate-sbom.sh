#!/usr/bin/env bash
set -euo pipefail

mkdir -p release/sbom

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required to generate an SBOM" >&2
  exit 1
fi

syft dir:. -o spdx-json > release/sbom/quicnet-source.spdx.json

