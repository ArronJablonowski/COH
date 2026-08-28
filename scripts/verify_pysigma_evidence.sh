#!/bin/bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
mode="${1:-gate}"
report="${root}/docs/evidence/CYB-105-pysigma-helper-report.md"
provenance="${root}/docs/evidence/CYB-105-pysigma-bundle-provenance.json"
snapshot="${root}/docs/evidence/CYB-105-pysigma-vulnerability-snapshot.json"
checksums="${root}/docs/evidence/CYB-105-artifacts.sha256"

[[ "${mode}" == gate || "${mode}" == inventory ]] || { echo "Usage: $0 [gate|inventory]" >&2; exit 64; }
for path in "${report}" "${provenance}" "${snapshot}" "${checksums}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || { echo "Missing CYB-105 evidence: ${path}" >&2; exit 64; }
done

/usr/bin/jq -e '
  .schema_version == "coh.pysigma-bundle-provenance/v1"
  and .issue == "CYB-105" and .stable_key == "COH-E15-01"
  and .requirements == ["FR-055","FR-056","SEC-019"]
  and .qualification_state == "candidate_blocked_license_review"
  and (.release_eligible | not)
  and .source.vcs_revision == "c597fe4ca9feeea31d4cad600c7186a963b9280e"
  and (.source.vcs_modified | not)
  and .bundle.rid == "osx-arm64" and .bundle.wheel_count == 22
  and .bundle.offline_hash_only_restore and .bundle.reproducible
  and .security.action_tier == "T0" and .security.credential_classes == ["none"]
  and .security.network_mode == "none" and (.security.diskcache_present | not)
  and (.security.remote_mitre_modules_present | not)
  and .security.selected_runtime_vulnerability_count == 0
  and .signature.ci_fixture_path_verified and (.signature.ci_fixture_release_authority | not)
  and (.signature.production_signature_present | not) and .signature.production_signature_required_before_release
  and .validation_handoff.input_state == "compiled_untrusted"
  and .validation_handoff.output_state == "native_validated"
  and .validation_handoff.schema_rebind_required and (.validation_handoff.unsupported_query_released | not)
  and .clean_ci.stage_count == 18 and .clean_ci.outcome == "passed"
  and .clean_ci.quality_gate_promotable
  and .blocking_issues == ["CYB-187"]
  and .non_blocking_release_followups == ["CYB-173"]
' "${provenance}" >/dev/null

/usr/bin/grep -Fq 'CYB-105 is not complete and this packet is not release approval.' "${report}"
/usr/bin/grep -Fq 'No database migration is introduced.' "${report}"
/usr/bin/grep -Fq 'Changed reuse conflicts.' "${report}"
/usr/bin/grep -Fq 'Rollback revokes or removes the new manifest admission' "${report}"

(cd "${root}" && /usr/bin/shasum -a 256 -c "${checksums}" >/dev/null)
export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"
"${root}/scripts/verify_pysigma_contract.sh"
"${root}/scripts/check_pysigma_supply_chain.sh" "${mode}"

if [[ -n "${COH_CYB105_CI_REPORT:-}" ]]; then
  [[ -f "${COH_CYB105_CI_REPORT}" && ! -L "${COH_CYB105_CI_REPORT}" ]] || { echo "CI report is invalid" >&2; exit 64; }
  actual="$(/usr/bin/shasum -a 256 "${COH_CYB105_CI_REPORT}" | /usr/bin/awk '{print $1}')"
  [[ "${actual}" == "dd78b876c8458fb944327dbd8c7c189a5e0405328087b590ff4d9983d5436d75" ]] || { echo "CI report digest mismatch" >&2; exit 2; }
  /usr/bin/jq -e '.outcome == "passed" and .quality_gate_promotable and .provenance.vcs_revision == "c597fe4ca9feeea31d4cad600c7186a963b9280e" and (.provenance.vcs_modified | not) and ([.stages[].outcome] | all(. == "passed")) and (.stages | length == 18)' "${COH_CYB105_CI_REPORT}" >/dev/null
elif [[ "${mode}" == gate ]]; then
  echo "COH_CYB105_CI_REPORT is required for final evidence verification" >&2
  exit 64
fi

echo "pysigma-evidence summary: issue=CYB-105 state=candidate mode=${mode} ci=18/18 blocker=CYB-187 release=false"
