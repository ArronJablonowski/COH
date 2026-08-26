#!/bin/bash

set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
adapter="${root}/internal/provider/vllm"
public_contract="${root}/contracts/provider/vllm/v1"

for path in \
  "${adapter}/README.md" \
  "${adapter}/testdata/health.empty" \
  "${adapter}/testdata/version.json" \
  "${adapter}/testdata/models.json" \
  "${adapter}/testdata/tokenizer-info.json" \
  "${adapter}/testdata/completed-chat.json" \
  "${adapter}/testdata/structured-chat.json" \
  "${adapter}/testdata/completed-stream.sse" \
  "${public_contract}/README.md" \
  "${public_contract}/capability.json"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: vLLM evidence input is missing or linked: ${path}" >&2
    exit 2
  }
done

[[ ! -s "${adapter}/testdata/health.empty" ]] || {
  echo "error: vLLM health fixture must be an empty 200 response body" >&2
  exit 2
}

/usr/bin/jq -e '
  .schema_version == "coh.provider-capability/v1"
  and .contract_version == "1.0.0"
  and .provider.provider_kind == "vllm"
  and .provider.adapter_version == "1.0.0"
  and .provider.data_route == "local"
  and .provider.state_mode == "stateless"
  and .provider.runtime_name == "vLLM"
  and .provider.runtime_version == "0.11.0"
  and .provider.model_revision == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and .provider.context_limit == 32768
  and .features.message_roles == ["assistant","system","tool","user"]
  and .features.content_kinds == ["input_json","output_json","reasoning_ref","text","tool_call","tool_result"]
  and .features.tool_calls and .features.structured_output and .features.streaming and .features.cancellation and .features.usage
  and .limits.maximum_input_tokens == 24576
  and .limits.maximum_output_tokens == 8192
  and .limits.maximum_parallel_tool_calls == 4
  and .limits.maximum_stream_seconds == 600
' "${public_contract}/capability.json" >/dev/null

/usr/bin/jq -e '.version == "0.11.0" and (keys == ["version"])' "${adapter}/testdata/version.json" >/dev/null
/usr/bin/jq -e '
  .object == "list" and (.data | length == 1)
  and .data[0].id == "qwen3-8b-coh" and .data[0].owned_by == "vllm"
  and .data[0].root == "/models/Qwen3-8B" and .data[0].parent == null
  and .data[0].max_model_len == 32768 and (.data[0].permission | length == 1)
  and .data[0].permission[0].allow_sampling and .data[0].permission[0].allow_view
  and (.data[0].permission[0].allow_create_engine | not)
  and (.data[0].permission[0].allow_fine_tuning | not)
' "${adapter}/testdata/models.json" >/dev/null
/usr/bin/jq -e '
  .tokenizer_class == "Qwen2TokenizerFast"
  and .tokenizer_version == "4.55.0"
  and .model_max_length == 32768
  and (.chat_template | length > 0)
' "${adapter}/testdata/tokenizer-info.json" >/dev/null
/usr/bin/jq -e '
  .object == "chat.completion" and .model == "qwen3-8b-coh"
  and .system_fingerprint == "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  and (.choices | length == 1) and .choices[0].message.role == "assistant"
  and .choices[0].message.tool_calls[0].function.name == "query_host"
  and .choices[0].finish_reason == "tool_calls"
  and .usage.prompt_tokens + .usage.completion_tokens == .usage.total_tokens
  and .prompt_logprobs == null and .prompt_token_ids == null and .prompt_text == null
  and .kv_transfer_params == null and .ec_transfer_params == null and .metrics == null
' "${adapter}/testdata/completed-chat.json" >/dev/null

/usr/bin/awk '/^data: \{/ {sub(/^data: /, ""); print}' "${adapter}/testdata/completed-stream.sse" | /usr/bin/jq -s -e '
  length == 8
  and ([.[] | .id] | unique | length == 1)
  and ([.[] | .model] | unique == ["qwen3-8b-coh"])
  and (.[0:7] | all(.system_fingerprint == null))
  and .[6].choices[0].finish_reason == "tool_calls"
  and (.[7].choices | length == 0)
  and .[7].system_fingerprint == "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  and .[7].usage.prompt_tokens + .[7].usage.completion_tokens == .[7].usage.total_tokens
' >/dev/null
[[ $(/usr/bin/grep -c '^data: \[DONE\]$' "${adapter}/testdata/completed-stream.sse") -eq 1 ]] || {
  echo "error: SSE fixture must contain exactly one DONE marker" >&2
  exit 2
}

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/provider/vllm
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/provider/vllm
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/provider/vllm
"${COH_GO_ROOT}/bin/go" vet ./internal/provider/vllm
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${adapter}/README.md" "${public_contract}/README.md"
/usr/bin/git diff --check

echo "vLLM summary: route=attested-managed-loopback operations=health+version+models+tokenizer_info+chat credentials=none model=weights-digest-bound runtime=image-bound tokenizer=bound template=bound parsers=bound gpu=bound state=stateless tools=strict-broker-only streaming=SSE+usage+DONE qualification=signed+unexpired conformance=six-case failures=0"
