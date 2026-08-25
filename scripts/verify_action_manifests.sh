#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
contract="${root}/contracts/action/v1"

for path in \
  "${contract}/README.md" \
  "${contract}/action-manifest.schema.json" \
  "${contract}/signed-action-envelope.schema.json" \
  "${contract}/compatibility-matrix.md" \
  "${contract}/fixtures/valid/detection-publish.manifest.json" \
  "${contract}/fixtures/valid/detection-publish.signed.json" \
  "${contract}/fixtures/denial-corpus.json" \
  "${root}/internal/domain/actionmanifest" \
  "${root}/docs/design/canonical-signed-action-manifests.md"; do
  [[ -e "${path}" ]] || {
    echo "error: signed-action input is missing: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 30
  and (.properties.action_tier.enum == ["T0", "T1", "T2", "T3", "T4"])
  and (.properties.target_digests["$ref"] == "#/$defs/nonempty_digest_set")
  and (.["$defs"].nonempty_digest_set.minItems == 1)
  and (.["$defs"].nonempty_digest_set.maxItems == 256)
  and (.properties.maximum_use_count.minimum == 1)
  and (.properties.maximum_use_count.maximum == 1000)
  and (.properties | has("arguments") | not)
  and (.properties | has("credential") | not)
  and (.properties | has("secret") | not)
' "${contract}/action-manifest.schema.json" >/dev/null

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and .type == "object"
  and .additionalProperties == false
  and (.required | length) == 9
  and .properties.signature_algorithm.const == "ed25519"
  and (.properties.signature.pattern | length) > 0
  and (.properties | has("private_key") | not)
' "${contract}/signed-action-envelope.schema.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.action-manifest/v1"
  and .contract_version == "1.0.0"
  and .action_tier == "T2"
  and .target_digests == (.target_digests | sort | unique)
  and .exclusion_digests == (.exclusion_digests | sort | unique)
  and .maximum_use_count == 1
  and .rollback_digest != null
  and .credential_reference_digest != null
' "${contract}/fixtures/valid/detection-publish.manifest.json" >/dev/null

/usr/bin/jq -e '
  .schema_version == "coh.signed-action/v1"
  and .contract_version == "1.0.0"
  and .signature_algorithm == "ed25519"
  and (.signature | length) == 86
  and (.manifest_digest | startswith("sha256:"))
  and .signer_actor_id == .manifest.requestor_actor_id
' "${contract}/fixtures/valid/detection-publish.signed.json" >/dev/null

/usr/bin/jq -e '
  .schema == "coh.action-manifest-denials/v1"
  and .contract_version == "1.0.0"
  and (.cases | length) == 24
  and ([.cases[].name] | unique | length) == 24
  and ([.cases[].name] | contains(["unknown-field", "unsorted-targets", "target-excluded", "raw-arguments", "expiry-before-start", "t4-without-roe", "inline-secret-reference"]))
  and all(.cases[]; (.operation == "set" or .operation == "remove") and (.reason | length) > 0)
' "${contract}/fixtures/denial-corpus.json" >/dev/null

/usr/bin/grep -Fq 'Changed canonicalization or signature domain' "${contract}/compatibility-matrix.md"
/usr/bin/grep -Fq 'Unknown signer key revision or inactive signer' "${contract}/compatibility-matrix.md"

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 "${root}/internal/domain/actionmanifest"
"${COH_GO_ROOT}/bin/go" test -count=1 -race "${root}/internal/domain/actionmanifest"
"${COH_GO_ROOT}/bin/go" vet "${root}/internal/domain/actionmanifest"
"${root}/scripts/check_go_architecture.sh"

echo 'signed-action summary: schemas=2 fixtures=2 denials=24 canonical=COH-CJ-1 signature=ed25519 domain-separated scope=full mutation=invalidates authority=current cancellation=closed recovery=fresh-context failures=0'
