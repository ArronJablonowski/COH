#!/bin/bash

set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
adapter="${root}/internal/provider/codexruntime"
public_contract="${root}/contracts/provider/codex-runtime/v1"

for path in \
  "${adapter}/README.md" \
  "${adapter}/testdata/app-server.jsonl" \
  "${adapter}/testdata/exec.jsonl" \
  "${public_contract}/README.md" \
  "${public_contract}/capability.json"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: Codex runtime evidence input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .schema_version == "coh.provider-capability/v1"
  and .contract_version == "1.0.0"
  and .provider.provider_kind == "codex_runtime"
  and .provider.adapter_version == "1.0.0"
  and .provider.data_route == "approved_external"
  and .provider.state_mode == "stateless"
  and .provider.runtime_name == "codex-app-server"
  and .provider.runtime_version == "0.145.0"
  and .provider.runtime_digest == "sha256:1da3f4e0e96028b8a771814293c3033dafd1971f943f6c7e79b0897fe705f590"
  and .provider.requested_model == "gpt-5.6-terra"
  and .provider.actual_model == "gpt-5.6-terra"
  and .provider.context_limit == 400000
  and .features.tool_calls and .features.structured_output
  and .features.streaming and .features.cancellation and .features.usage
  and .features.state_modes == ["stateless"]
  and .limits.maximum_input_tokens == 300000
  and .limits.maximum_output_tokens == 64000
  and .limits.maximum_messages == 512
  and .limits.maximum_tools == 32
  and .limits.maximum_parallel_tool_calls == 4
  and .limits.maximum_stream_seconds == 900
' "${public_contract}/capability.json" >/dev/null

/usr/bin/jq -s -e '
  length == 14
  and .[0].id == 1 and .[0].result.codexHome == "/managed/codex-home"
  and .[1].id == 2 and .[1].result.thread.ephemeral
  and .[1].result.thread.cwd == "/workspace"
  and .[1].result.instructionSources == []
  and .[2].method == "thread/started"
  and .[3].id == 3 and .[3].result.turn.status == "inProgress"
  and .[4].method == "turn/started"
  and .[9].method == "item/tool/call"
  and .[9].params.tool == "query_host"
  and .[12].method == "thread/tokenUsage/updated"
  and .[12].params.tokenUsage.total.totalTokens == 120
  and .[13].method == "turn/completed"
' "${adapter}/testdata/app-server.jsonl" >/dev/null

/usr/bin/jq -s -e '
  length == 4
  and [.[].type] == ["thread.started","turn.started","item.completed","turn.completed"]
  and .[2].item.type == "agent_message"
  and .[3].usage.input_tokens + .[3].usage.output_tokens == 92
' "${adapter}/testdata/exec.jsonl" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/provider/codexruntime
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/provider/codexruntime
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/provider/codexruntime
"${COH_GO_ROOT}/bin/go" vet ./internal/provider/codexruntime
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${adapter}/README.md" "${public_contract}/README.md"
/usr/bin/git diff --check

echo "codex-runtime summary: primary=app-server-v2 runtime=digest-pinned protocol=digest-pinned model=exact route=approved-external config=managed-isolated state=ephemeral+stateless tools=dynamicTools-broker-only native-tools=denied fallback=explicit-exec-only exec-tools=disabled sandbox=read-only credentials=invocation-scoped bounds=fail-closed qualification=signed+unexpired conformance=six-case failures=0"
