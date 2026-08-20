#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allow=${1:-${repo_root}/ci/licenses.allow}
if (( $# > 1 )) || [[ "${allow}" != /* || ! -f "${allow}" || -L "${allow}" ]]; then
  echo "License allowlist input is invalid" >&2
  exit 64
fi
module_list="$(mktemp "${GOTMPDIR}/coh-license-modules.XXXXXX")"
rule_list="$(mktemp "${GOTMPDIR}/coh-license-rules.XXXXXX")"
cleanup() { rm -f "${module_list}" "${rule_list}"; }
trap cleanup EXIT

if ! awk '
  NF && $1 !~ /^#/ {
    if (NF != 5 || seen[$1 SUBSEP $2]++) exit 1
    print
  }
' "${allow}" > "${rule_list}"; then
  echo "License allowlist is malformed or contains duplicate identities" >&2
  exit 64
fi

if ! "${COH_GO_BIN}" list -mod=readonly -m -f '{{.Path}} {{.Dir}}' all > "${module_list}"; then
  echo "Go module license inventory failed" >&2
  exit 1
fi

module_count=0
while read -r module directory; do
  [[ -n "${directory}" ]] || directory="${repo_root}"
  license_file=""
  for candidate in LICENSE LICENSE.txt LICENSE.md COPYING; do
    if [[ -f "${directory}/${candidate}" ]]; then license_file="${directory}/${candidate}"; break; fi
  done
  if [[ -z "${license_file}" ]]; then
    echo "No license file for ${module}" >&2
    exit 2
  fi
  digest="$("${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" -mode digest -input "${license_file}")"
  if ! awk -v id="${module}" -v hash="${digest}" '
    $1 == "module" && $2 == id && $3 == "Apache-2.0" && $4 == hash && $5 == "repository" { found=1 }
    END { exit !found }
  ' "${rule_list}"; then
    echo "Unapproved module license or digest for ${module}" >&2
    exit 2
  fi
  module_count=$((module_count + 1))
done < "${module_list}"

allowed_modules="$(awk '$1 == "module" { count++ } END { print count+0 }' "${rule_list}")"
if (( module_count == 0 || module_count != allowed_modules )); then
  echo "Module license inventory does not exactly match its allowlist" >&2
  exit 2
fi

artifact_count=0
while read -r kind identity license digest source; do
  [[ "${kind}" == "artifact" || "${kind}" == "notice" ]] || continue
  case "${kind}:${identity}:${license}:${source}" in
    artifact:third_party/offline-packs/go-vulndb/vulndb-2026-08-19.zip:CC-BY-4.0:https://vuln.go.dev/vulndb.zip) ;;
    notice:third_party/offline-packs/go-vulndb/NOTICE.md:CC-BY-4.0:https://creativecommons.org/licenses/by/4.0/) ;;
    *) echo "Unapproved shipped license input: ${kind} ${identity}" >&2; exit 2 ;;
  esac
  actual="$("${COH_QUALITYGATE_BIN}" -mode digest -input "${repo_root}/${identity}")"
  if [[ "${actual}" != "${digest}" ]]; then
    echo "Shipped license input digest mismatch: ${identity}" >&2
    exit 2
  fi
  artifact_count=$((artifact_count + 1))
done < "${rule_list}"

if (( artifact_count != 2 )); then
  echo "Shipped license inventory must contain the archive and attribution notice" >&2
  exit 2
fi

echo "license summary: modules=${module_count} shipped_inputs=${artifact_count} denied=0"
