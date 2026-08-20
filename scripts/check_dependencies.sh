#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_dir="${COH_CI_ARTIFACT_DIR:?COH_CI_ARTIFACT_DIR is required}"
mkdir -p "${artifact_dir}"

actual="$(mktemp "${GOTMPDIR}/coh-dependencies.XXXXXX")"
tidy_diff="$(mktemp "${GOTMPDIR}/coh-tidy.XXXXXX")"
vuln_tmp="$(mktemp "${artifact_dir}/.govulncheck.XXXXXX")"
cleanup() { rm -f "${actual}" "${tidy_diff}" "${vuln_tmp}"; }
trap cleanup EXIT

if ! "${COH_GO_BIN}" mod verify; then
  echo "Go module cache integrity verification failed" >&2
  exit 2
fi
set +e
"${COH_GO_BIN}" mod tidy -diff > "${tidy_diff}"
tidy_status=$?
set -e
if (( tidy_status != 1 )) || ! diff -u "${repo_root}/ci/go-mod-tidy.expected.diff" <(/usr/bin/sed -e '${/^$/d;}' "${tidy_diff}"); then
  echo "go.mod/go.sum tidiness differs beyond the locked CYB-32 toolchain directive" >&2
  exit 2
fi
if ! "${COH_GO_BIN}" list -mod=readonly -m -f '{{.Path}} {{if .Version}}{{.Version}}{{else}}(main){{end}}' all > "${actual}"; then
  echo "Go module graph integrity verification failed" >&2
  exit 2
fi
"${repo_root}/scripts/check_dependency_allowlist.sh" "${repo_root}/ci/dependencies.allow" "${actual}"

: "${COH_GOVULNDB:?COH_GOVULNDB is required}"
: "${COH_GOVULNDB_MANIFEST:?COH_GOVULNDB_MANIFEST is required}"
: "${COH_GOVULNDB_MANIFEST_SHA256:?COH_GOVULNDB_MANIFEST_SHA256 is required}"
"${COH_QUALITYGATE_BIN}" -mode verify-vulndb -root "${repo_root}" \
  -vulndb "${COH_GOVULNDB}" -manifest "${COH_GOVULNDB_MANIFEST}" \
  -manifest-sha256 "${COH_GOVULNDB_MANIFEST_SHA256}" -artifact-dir "${artifact_dir}" \
  -output "${artifact_dir}/govulndb-verification.json"
"${GOBIN}/govulncheck" -format sarif -db "${COH_GOVULNDB}" ./... > "${vuln_tmp}"
"${COH_QUALITYGATE_BIN}" -mode verify-govuln-sarif -root "${repo_root}" \
  -vulndb "${COH_GOVULNDB}" -input "${vuln_tmp}"
mv "${vuln_tmp}" "${artifact_dir}/govulncheck.sarif"

echo "dependency summary: approved=$(wc -l < "${actual}" | tr -d ' ') vulnerabilities=0"
