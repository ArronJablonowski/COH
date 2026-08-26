#!/bin/bash

set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
adapter="${root}/internal/provider/llamacpp"
public_contract="${root}/contracts/provider/llama-cpp/v1"

for path in \
  "${adapter}/README.md" \
  "${adapter}/testdata/health.json" \
  "${adapter}/testdata/properties.json" \
  "${adapter}/testdata/models.json" \
  "${adapter}/testdata/completed-chat.json" \
  "${adapter}/testdata/structured-chat.json" \
  "${adapter}/testdata/completed-stream.sse" \
  "${public_contract}/README.md" \
  "${public_contract}/capability.json"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: llama.cpp evidence input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .schema_version == "coh.provider-capability/v1"
  and .contract_version == "1.0.0"
  and .provider.provider_kind == "llama_cpp"
  and .provider.adapter_version == "1.0.0"
  and .provider.data_route == "local"
  and .provider.state_mode == "stateless"
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

/usr/bin/jq -e '.status == "ok"' "${adapter}/testdata/health.json" >/dev/null
/usr/bin/jq -e '
  .default_generation_settings.n_ctx == 32768
  and .total_slots == 1
  and (.model_path | endswith(".gguf"))
  and (.chat_template | length > 0)
  and .chat_template_caps.supports_tools
  and .chat_template_caps.supports_tool_calls
  and .chat_template_caps.supports_parallel_tool_calls
  and .chat_template_caps.supports_system_role
  and .chat_template_caps.supports_preserve_reasoning
  and .modalities.vision == false
  and .build_info == "b7000-5d5cb4c3"
  and .is_sleeping == false
' "${adapter}/testdata/properties.json" >/dev/null
/usr/bin/jq -e '
  .object == "list"
  and (.data | length == 1)
  and .data[0].id == "qwen3-8b-coh"
  and .data[0].owned_by == "llamacpp"
  and .data[0].meta.n_ctx_train >= 32768
  and .data[0].meta.size > 0
' "${adapter}/testdata/models.json" >/dev/null
/usr/bin/jq -e '
  .object == "chat.completion"
  and .model == "qwen3-8b-coh"
  and .system_fingerprint == "b7000-5d5cb4c3"
  and (.choices | length == 1)
  and .choices[0].message.role == "assistant"
  and .choices[0].message.tool_calls[0].function.name == "query_host"
  and .choices[0].finish_reason == "tool_calls"
  and .usage.prompt_tokens + .usage.completion_tokens == .usage.total_tokens
' "${adapter}/testdata/completed-chat.json" >/dev/null

/usr/bin/awk '/^data: \{/ {sub(/^data: /, ""); print}' "${adapter}/testdata/completed-stream.sse" | /usr/bin/jq -s -e '
  length == 8
  and ([.[] | .id] | unique | length == 1)
  and ([.[] | .model] | unique == ["qwen3-8b-coh"])
  and ([.[] | .system_fingerprint] | unique == ["b7000-5d5cb4c3"])
  and .[-2].choices[0].finish_reason == "tool_calls"
  and (.[-1].choices | length == 0)
  and .[-1].usage.prompt_tokens + .[-1].usage.completion_tokens == .[-1].usage.total_tokens
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
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/provider/llamacpp
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/provider/llamacpp
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/provider/llamacpp
"${COH_GO_ROOT}/bin/go" vet ./internal/provider/llamacpp
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${adapter}/README.md" "${public_contract}/README.md"
/usr/bin/git diff --check

echo "llama.cpp summary: route=attested-managed-loopback operations=health+props+models+chat credentials=none model=GGUF-digest-bound build=bound template=bound context=bound tools=broker-only streaming=SSE+usage+DONE qualification=signed+unexpired conformance=six-case failures=0"
