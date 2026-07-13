#!/usr/bin/env bash
set -euo pipefail

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"
release_version="${RELEASE_VERSION:-dev}"

mkdir -p dist release/artifacts release/sbom

archive_path="dist/quicnet-source.tar.gz"

if command -v gtar >/dev/null 2>&1; then
  gtar \
    --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --exclude=.git \
    --exclude=.fozzy \
    --exclude=dist \
    --exclude=release/artifacts \
    --exclude=release/sbom \
    -czf "${archive_path}" .
else
  tmp_list="$(mktemp)"
  trap 'rm -f "${tmp_list}"' EXIT
  find . \
    -mindepth 1 \
    -path './.git' -prune -o \
    -path './.fozzy' -prune -o \
    -path './dist' -prune -o \
    -path './release/artifacts' -prune -o \
    -path './release/sbom' -prune -o \
    -print | LC_ALL=C sort > "${tmp_list}"
  COPYFILE_DISABLE=1 tar -czf "${archive_path}" -T "${tmp_list}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${archive_path}" > release/artifacts/quicnet-source.sha256
else
  shasum -a 256 "${archive_path}" > release/artifacts/quicnet-source.sha256
fi

printf '%s\n' "${release_version}" > release/artifacts/release-version.txt
