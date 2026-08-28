#!/bin/bash

set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/connector/sigmacompiler"
contract="${root}/contracts/pysigma-helper/v1"
design="${root}/docs/design/signed-pysigma-helper.md"

for path in \
  "${package}/types.go" \
  "${package}/canonical.go" \
  "${package}/contract.go" \
  "${package}/contract_test.go" \
  "${package}/public_contract_test.go" \
  "${contract}/README.md" \
  "${contract}/compatibility-matrix.md" \
  "${contract}/compile-request.schema.json" \
  "${contract}/compile-response.schema.json" \
  "${contract}/capability-snapshot.schema.json" \
  "${contract}/helper-attestation.schema.json" \
  "${contract}/provenance-receipt.schema.json" \
  "${contract}/denial-corpus.schema.json" \
  "${contract}/redacted-trace.schema.json" \
  "${contract}/fixtures/compile-request.json" \
  "${contract}/fixtures/compile-response.compiled.json" \
  "${contract}/fixtures/compile-response.needs-mapping.json" \
  "${contract}/fixtures/capability-snapshot.json" \
  "${contract}/fixtures/helper-attestation.json" \
  "${contract}/fixtures/provenance-receipt.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${contract}/fixtures/redacted-error-trace.json"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: pySigma contract artifact is missing or linked: ${path}" >&2
    exit 2
  }
done

for schema in "${contract}"/*.schema.json; do
  /usr/bin/jq -e '
    .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    and .additionalProperties == false
    and (.required | type == "array" and length > 0)
  ' "${schema}" >/dev/null
done

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-helper-request/v1"
  and .contract_version == "1.0.0"
  and .operation == "sigma.compile"
  and .sigma_profile == "sigma-basic-2.1.0-coh-v1"
  and .target.target == "elastic"
  and .mapping.fields == ([.mapping.fields[]] | sort_by(.source))
  and ([.mapping.fields[].source] | unique | length) == (.mapping.fields | length)
  and ([.mapping.fields[].target] | unique | length) == (.mapping.fields | length)
' "${contract}/fixtures/compile-request.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-helper-response/v1"
  and .contract_version == "1.0.0"
  and .outcome == "compiled_untrusted"
  and .reason_codes == []
  and (.native_query | length > 0)
' "${contract}/fixtures/compile-response.compiled.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-helper-response/v1"
  and .outcome == "needs_mapping"
  and .native_query == ""
  and .native_query_digest == ""
  and (.reason_codes | length > 0)
' "${contract}/fixtures/compile-response.needs-mapping.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-capability/v1"
  and ([.backend_capabilities[].target] == ["elastic","security-onion","sentinel","splunk"])
  and (.backend_capabilities[] | select(.target == "security-onion") |
    .qualification == "unavailable" and .reason_code == "native_contract_mismatch")
' "${contract}/fixtures/capability-snapshot.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-helper-attestation/v1"
  and .python_version == "3.13.15"
  and .pysigma_version == "1.5.0"
  and .pyinstaller_version == "6.22.2"
  and .network_denied
  and .credential_classes == ["none"]
  and .ambient_plugins_denied
  and .external_sources_denied
  and .skip_unsupported_denied
  and .reproducible
' "${contract}/fixtures/helper-attestation.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-denials/v1"
  and (.cases | length >= 12)
  and ([.cases[] | .class + "\u0000" + .mutation] == ([.cases[] | .class + "\u0000" + .mutation] | sort | unique))
' "${contract}/fixtures/denial-corpus.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-redacted-trace/v1"
  and (.native_text_exposed | not)
  and (.sigma_text_exposed | not)
  and (.field_name_exposed | not)
  and (.credential_exposed | not)
  and (.path_exposed | not)
' "${contract}/fixtures/redacted-error-trace.json" >/dev/null

/usr/bin/grep -Fq 'compiled_untrusted' "${contract}/README.md"
/usr/bin/grep -Fq 'Security Onion requested' "${contract}/compatibility-matrix.md"
/usr/bin/grep -Fq '| Security decision | Exact explicitly imported backends' "${design}"

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|policy|provider|transport))"' \
  "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: pySigma contract imports a forbidden authority or execution capability" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/connector/sigmacompiler
"${COH_GO_ROOT}/bin/go" test -count=10 ./internal/connector/sigmacompiler
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/connector/sigmacompiler
"${COH_GO_ROOT}/bin/go" vet ./internal/connector/sigmacompiler
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${design}" "${contract}/README.md" "${contract}/compatibility-matrix.md"
/usr/bin/git diff --check

echo "pySigma-contract summary: issue=CYB-105 contract=v1 profile=sigma-2.1-basic mapping=explicit-one-to-one targets=three-candidate+security-onion-unavailable output=compiled-untrusted identity=exact attestation=closed provenance=digest-bound traces=redacted denials=machine-checkable failures=0"
