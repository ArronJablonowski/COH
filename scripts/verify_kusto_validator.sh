#!/bin/bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
toolchain_root="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
rid="${1:-osx-arm64}"
first_report="$("${repository_root}/scripts/build_kusto_validator.sh" "${rid}")"
second_report="$("${repository_root}/scripts/build_kusto_validator.sh" "${rid}")"
first_digest="$(printf '%s\n' "${first_report}" | /usr/bin/awk -F= '$1 == "artifact_digest" {print $2}')"
second_digest="$(printf '%s\n' "${second_report}" | /usr/bin/awk -F= '$1 == "artifact_digest" {print $2}')"
artifact="$(printf '%s\n' "${first_report}" | /usr/bin/awk -F= '$1 == "artifact" {sub(/^artifact=/, ""); print}')"
if [[ -z "${first_digest}" || "${first_digest}" != "${second_digest}" ]]; then
  echo "Kusto validator build is not reproducible" >&2
  exit 67
fi

request="$(tr -d '\n' < "${repository_root}/contracts/kusto-validator/v1/fixtures/helper-request.json")"
transport="$(/usr/bin/printf '%s' "${request}" | /usr/bin/python3 -c 'import json,sys; print(json.dumps({"request_chunk_00":sys.stdin.read()}, separators=(",", ":")))')"
response="$(/usr/bin/printf '%s' "${transport}" | "${artifact}")"
/usr/bin/printf '%s' "${response}" | /usr/bin/python3 -c '
import json,sys
value=json.load(sys.stdin)
assert value["schema_version"] == "coh.kusto-helper-response/v1"
assert value["outcome"] == "denied"
assert value["reason_codes"] == ["helper_semantics_unavailable"]
assert value["canonical_kql"] == ""
'

printf '%s\n' "verified ${first_digest} (${rid}); locked signatures, reproducibility, and fail-closed protocol passed"
