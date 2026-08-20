#!/bin/bash

# Explicit maintainer-only promotion of the reviewed immutable snapshot.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
quality_binary="${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}"
source_archive=${1:?Usage: update_govulndb.sh /absolute/path/vulndb.zip}
expected=6956c9eda20845fc540d08c38e22129b32effad51375ad3d6374fe1bed6d38cc
target_dir="${repo_root}/third_party/offline-packs/go-vulndb"
target="${target_dir}/vulndb-2026-08-19.zip"

[[ "${source_archive}" == /* ]] || { echo "Source archive must be absolute" >&2; exit 64; }
actual="$("${quality_binary}" -mode digest -input "${source_archive}")"
[[ "${actual}" == "${expected}" ]] || { echo "Source archive differs from reviewed digest" >&2; exit 2; }
mkdir -p "${target_dir}"
/usr/bin/install -m 0444 "${source_archive}" "${target}"
actual="$("${quality_binary}" -mode digest -input "${target}")"
[[ "${actual}" == "${expected}" ]] || { echo "Promoted archive failed read-back" >&2; exit 2; }

echo "Promoted locked Go vulnerability database snapshot: ${target}"
