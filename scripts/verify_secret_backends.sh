#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/secret/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/secret-reference.schema.json" \
  "${contract}/resolution-request.schema.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/secretref" \
  "${root}/internal/broker/secretresolver" \
  "${root}/docs/design/secret-references-backends.md"; do
  [[ -e "${path}" ]] || {
    echo "error: secret-backend input is missing: ${path}" >&2
    exit 2
  }
done

references=("${contract}"/fixtures/valid/*.reference.json)
requests=("${contract}"/fixtures/valid/*.request.json)
[[ ${#references[@]} -eq 2 && ${#requests[@]} -eq 2 ]] || {
  echo "error: expected two reference and two resolution-request fixtures" >&2
  exit 2
}

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required == ["schema_version", "contract_version", "backend", "entry_id", "version"])
  and (.properties | has("secret") | not)
  and (.properties | has("secret_value") | not)
  and (.properties | has("password") | not)
  and (.properties | has("token") | not)
  and (.properties | has("credential") | not)
  and (.properties | has("path") | not)
  and (.properties | has("url") | not)
  and (.properties | has("command") | not)
' "${contract}/secret-reference.schema.json" >/dev/null

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 8
  and (.properties.context.required == ["organization_id", "tenant_id", "case_id", "actor_id"])
  and (.properties | has("secret_value") | not)
  and (.properties | has("password") | not)
  and (.properties | has("token") | not)
' "${contract}/resolution-request.schema.json" >/dev/null

/usr/bin/jq -s -e '
  length == 2
  and ([.[].backend] | unique | sort) == ["protected-file", "sealed-memory"]
  and all(.[]; .schema_version == "coh.secret-reference/v1" and .contract_version == "1.0.0" and .version > 0)
  and all(.[]; (keys | sort) == ["backend", "contract_version", "entry_id", "schema_version", "version"])
' "${references[@]}" >/dev/null

/usr/bin/jq -s -e '
  length == 2
  and all(.[]; .schema_version == "coh.secret-reference/v1" and .contract_version == "1.0.0")
  and all(.[]; (.context | keys | sort) == ["actor_id", "case_id", "organization_id", "tenant_id"])
' "${requests[@]}" >/dev/null

/usr/bin/jq -e '
  .schema == "coh.secret-reference-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 18
  and ([.cases[].name] | unique | length) == 18
  and all(.cases[];
    (.document == "reference" or .document == "request")
    and (.expected_code == "denied" or .expected_code == "invalid_input")
    and (.reason | length) > 0)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/secretref" "${root}/internal/broker/secretresolver"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/secretref" "${root}/internal/broker/secretresolver"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/secretref" "${root}/internal/broker/secretresolver"
"${root}/scripts/check_go_architecture.sh"

echo "secret-backend summary: references=2 requests=2 denials=18 backends=2 authority=bound file-root=protected material-tamper=denied zeroization=verified replay=atomic audit=fail-closed failures=0"
