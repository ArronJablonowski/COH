#!/bin/bash

set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
adapter="${root}/internal/provider/ollama"
public_contract="${root}/contracts/provider/ollama/v1"

for path in \
  "${adapter}/README.md" \
  "${adapter}/testdata/version.json" \
  "${adapter}/testdata/tags.json" \
  "${adapter}/testdata/show.json" \
  "${adapter}/testdata/completed-chat.json" \
  "${adapter}/testdata/structured-chat.json" \
  "${adapter}/testdata/completed-stream.ndjson" \
  "${public_contract}/README.md" \
  "${public_contract}/capability.json"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: native Ollama evidence input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .schema_version == "coh.provider-capability/v1"
  and .contract_version == "1.0.0"
  and .provider.provider_kind == "ollama"
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

/usr/bin/jq -e '.version == "0.12.6"' "${adapter}/testdata/version.json" >/dev/null
/usr/bin/jq -e '
  .models | length == 1
  and .[0].name == "qwen3:8b"
  and .[0].model == "qwen3:8b"
  and .[0].digest == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and .[0].details.format == "gguf"
' "${adapter}/testdata/tags.json" >/dev/null
/usr/bin/jq -e '
  (.template | length > 0)
  and .capabilities == ["completion","thinking","tools"]
  and .model_info["qwen3.context_length"] == 32768
  and .details.family == "qwen3"
' "${adapter}/testdata/show.json" >/dev/null
/usr/bin/jq -e '
  .model == "qwen3:8b"
  and .message.role == "assistant"
  and .message.tool_calls[0].function.name == "query_host"
  and .done == true
  and .done_reason == "stop"
  and .prompt_eval_count + .eval_count == 120
' "${adapter}/testdata/completed-chat.json" >/dev/null
/usr/bin/jq -s -e '
  length == 5
  and ([.[] | .model] | unique == ["qwen3:8b"])
  and ([.[0:4][] | .done] | all(. == false))
  and .[-1].done == true
  and .[-1].done_reason == "stop"
  and .[-1].prompt_eval_count + .[-1].eval_count == 120
' "${adapter}/testdata/completed-stream.ndjson" >/dev/null

if /usr/bin/grep -R -n -E 'OLLAMA_API_KEY|Authorization: Bearer|ollama[.]com|Passthrough|GenericOptions' \
  "${adapter}"/*.go "${adapter}"/testdata "${public_contract}"/*.json | \
  /usr/bin/grep -v -E '_test[.]go:' >/dev/null; then
  echo "error: unsupported cloud, credential, or generic vendor surface found" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/provider/ollama
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/provider/ollama
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/provider/ollama
"${COH_GO_ROOT}/bin/go" vet ./internal/provider/ollama
"${root}/scripts/check_static_analysis.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${adapter}/README.md" "${public_contract}/README.md"
/usr/bin/git diff --check

echo "ollama summary: route=attested-cloud-disabled-loopback operations=version+tags+show+chat credentials=none model=digest-bound template=bound context=bound keep_alive=0 tools=function-only streaming=ndjson+terminal qualification=signed+unexpired conformance=six-case failures=0"
