#!/bin/bash

# Source this file so the three verified database references remain available
# to the network-disabled quality stages.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/ci_env.sh
source "${repo_root}/scripts/lib/ci_env.sh"

quality_binary="${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}"
archive_sha=6956c9eda20845fc540d08c38e22129b32effad51375ad3d6374fe1bed6d38cc
manifest_sha=a95e1ef286e8f04c1b14f899bc14b99ce2b357231e1abb2aae786ec168a5b75d
database_id=2026-08-19T170606Z-a95e1ef2
archive_dir="${COH_TOOLCHAIN_ROOT}/downloads/vulndb"
database_parent="${COH_TOOLCHAIN_ROOT}/vulndb"
database_root="${database_parent}/${database_id}"
manifest_dir="${database_parent}/manifests"
archive="${archive_dir}/vulndb-2026-08-19.zip"
manifest="${manifest_dir}/govulndb-manifest.json"
vendored_archive="${repo_root}/third_party/offline-packs/go-vulndb/vulndb-2026-08-19.zip"

mkdir -p "${archive_dir}" "${database_parent}" "${manifest_dir}"
if [[ ! -f "${archive}" ]]; then
  vendored_digest="$("${quality_binary}" -mode digest -input "${vendored_archive}")"
  [[ "${vendored_digest}" == "${archive_sha}" ]] || { echo "Vendored database archive digest mismatch" >&2; return 2 2>/dev/null || exit 2; }
  /usr/bin/install -m 0444 "${vendored_archive}" "${archive}"
fi
actual_archive="$("${quality_binary}" -mode digest -input "${archive}")"
[[ "${actual_archive}" == "${archive_sha}" ]] || { echo "Vulnerability database archive digest mismatch" >&2; return 2 2>/dev/null || exit 2; }

if [[ ! -d "${database_root}" ]]; then
  extraction="$(/usr/bin/mktemp -d "${database_parent}/.extract.XXXXXX")"
  "${quality_binary}" -mode extract-vulndb -root "${repo_root}" -input "${archive}" -output "${extraction}"
  /bin/mv "${extraction}" "${database_root}"
fi
if [[ ! -f "${manifest}" ]]; then
  "${quality_binary}" -mode generate-vulndb-manifest -root "${repo_root}" \
    -vulndb "file://${database_root}" -output "${manifest}"
fi
actual_manifest="$("${quality_binary}" -mode digest -input "${manifest}")"
[[ "${actual_manifest}" == "${manifest_sha}" ]] || { echo "Vulnerability database manifest digest mismatch" >&2; return 2 2>/dev/null || exit 2; }

export COH_GOVULNDB="file://${database_root}"
export COH_GOVULNDB_MANIFEST="${manifest}"
export COH_GOVULNDB_MANIFEST_SHA256="${manifest_sha}"

echo "Locked vulnerability database prepared at ${database_root}"
