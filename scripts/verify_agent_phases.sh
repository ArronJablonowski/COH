#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
package="${root}/internal/workflow/agentphase"
contract="${root}/contracts/workflow/v1/agent-phase.schema.json"
input_fixture="${root}/contracts/workflow/v1/fixtures/agent-phase-input.json"
review_fixture="${root}/contracts/workflow/v1/fixtures/agent-phase-review-output.json"

paths=(
  "${package}/README.md"
  "${package}/types.go"
  "${package}/validate.go"
  "${package}/coordinator.go"
  "${package}/model.go"
  "${contract}"
  "${input_fixture}"
  "${review_fixture}"
  "${root}/contracts/workflow/v1/README.md"
)
for path in "${paths[@]}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: typed agent-phase input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .["$schema"] == "https://json-schema.org/draft/2020-12/schema"
  and (."$defs".input.properties.contract_version.const == "coh.agent-phase/v1")
  and (."$defs".input.properties.phase.enum == ["plan","act","observe","review"])
  and (."$defs".output.properties.phase.enum == ["plan","act","observe","review"])
  and (."$defs".retry_policy.properties.maximum_phase_attempts.maximum == 8)
  and (."$defs".retry_policy.properties.maximum_review_cycles.maximum == 8)
  and (."$defs".digest_set.uniqueItems == true)
  and (."$defs".nonempty_digest_set.minItems == 1)
  and (."$defs".claim.required | index("counterevidence_refs")) != null
  and (."$defs".claim.required | index("unknown_digests")) != null
  and (."$defs".claim.required | index("recommended_next_step_digests")) != null
  and (."$defs".finding.required | index("confidence_basis_points")) != null
  and (."$defs".input.allOf | length == 3)
  and (."$defs".output.allOf | length == 4)
  and (."$defs".input.additionalProperties == false)
  and (."$defs".output.additionalProperties == false)
  and (."$defs".claim.additionalProperties == false)
  and (."$defs".finding.additionalProperties == false)
' "${contract}" >/dev/null

/usr/bin/jq -e '
  .contract_version == "coh.agent-phase/v1"
  and .phase == "plan"
  and .cycle == 1
  and .prior_output_digest == ""
  and .retry_policy.maximum_phase_attempts == 2
  and .retry_policy.maximum_review_cycles == 2
  and (.input_set_digest | test("^sha256:[0-9a-f]{64}$"))
' "${input_fixture}" >/dev/null

/usr/bin/jq -e '
  .contract_version == "coh.agent-phase/v1"
  and .phase == "review"
  and .review_disposition == "accepted"
  and (.claims | length) == 1
  and (.findings | length) == 1
  and .claims[0].confidence_basis_points == 8500
  and .findings[0].severity == "high"
  and (.findings[0].evidence_refs | length) == 1
  and (.findings[0].recommended_next_step_digests | length) == 1
' "${review_fixture}" >/dev/null

if /usr/bin/grep -R -n -E '"(net/http|os/exec|github[.]com/ArronJablonowski/COH/internal/(broker|provider|transport|persistence))"' "${package}" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: agent phases import a forbidden action-capable dependency" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/workflow/agentphase ./internal/workflow/agentloop
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/workflow/agentphase ./internal/workflow/agentloop
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/workflow/agentphase ./internal/workflow/agentloop
"${COH_GO_ROOT}/bin/go" vet ./internal/workflow/agentphase ./internal/workflow/agentloop
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${package}/README.md" "${root}/contracts/workflow/v1/README.md"
/usr/bin/git diff --check

echo "agent-phase summary: contract=coh.agent-phase/v1 graph=plan-act-observe-review phases=4 typed_claims=true typed_findings=true retries=phase8+cycles8 action_replay=false trace_binding=deterministic failures=0"
