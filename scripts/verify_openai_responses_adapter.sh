#!/bin/bash

set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
adapter="${root}/internal/provider/openairesponses"
public_contract="${root}/contracts/provider/openai-responses/v1"

for path in \
  "${adapter}/README.md" \
  "${adapter}/testdata/completed-response.json" \
  "${adapter}/testdata/structured-response.json" \
  "${adapter}/testdata/incomplete-response.json" \
  "${adapter}/testdata/completed-stream.sse" \
  "${public_contract}/README.md" \
  "${public_contract}/capability.json"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "error: OpenAI Responses evidence input is missing or linked: ${path}" >&2
    exit 2
  }
done

/usr/bin/jq -e '
  .schema_version == "coh.provider-capability/v1"
  and .contract_version == "1.0.0"
  and .provider.provider_kind == "openai_responses"
  and .provider.adapter_version == "1.0.0"
  and .provider.data_route == "approved_external"
  and .provider.state_mode == "stateless"
  and .features == {
    "cancellation":true,
    "content_kinds":["input_json","output_json","reasoning_ref","text","tool_call","tool_result"],
    "message_roles":["assistant","developer","system","tool","user"],
    "state_modes":["stateless"],
    "streaming":true,
    "structured_output":true,
    "tool_calls":true,
    "usage":true
  }
  and .limits.maximum_input_tokens == 24576
  and .limits.maximum_output_tokens == 8192
  and .limits.maximum_parallel_tool_calls == 4
  and .limits.maximum_stream_seconds == 600
' "${public_contract}/capability.json" >/dev/null

/usr/bin/jq -e '
  .object == "response"
  and .status == "completed"
  and .store == false
  and .background == false
  and .truncation == "disabled"
  and .parallel_tool_calls == false
  and [.output[].type] == ["reasoning", "message", "function_call"]
  and .output[2].name == "query_host"
  and .usage.total_tokens == (.usage.input_tokens + .usage.output_tokens)
' "${adapter}/testdata/completed-response.json" >/dev/null

/usr/bin/jq -e '
  .status == "completed"
  and .output[0].type == "message"
  and (.output[0].content[0].text | fromjson | .verdict == "allow")
' "${adapter}/testdata/structured-response.json" >/dev/null

/usr/bin/jq -e '
  .status == "incomplete"
  and .incomplete_details.reason == "max_output_tokens"
  and .output[0].status == "incomplete"
' "${adapter}/testdata/incomplete-response.json" >/dev/null

stream_events=$(/usr/bin/mktemp "${TMPDIR:-/tmp}/coh-openai-stream.XXXXXX")
cleanup() { /bin/rm -f -- "${stream_events}"; }
trap cleanup EXIT HUP INT TERM
/usr/bin/awk '/^data: / { sub(/^data: /, ""); if ($0 != "[DONE]") print }' \
  "${adapter}/testdata/completed-stream.sse" > "${stream_events}"
/usr/bin/jq -s -e '
  length == 18
  and ([to_entries[] | .value.sequence_number == .key] | all)
  and .[0].type == "response.created"
  and .[-1].type == "response.completed"
  and ([.[].type] | contains([
    "response.output_text.delta",
    "response.function_call_arguments.delta",
    "response.reasoning_summary_text.delta",
    "response.output_item.done"
  ]))
' "${stream_events}" >/dev/null

if /usr/bin/grep -R -n -E '(^|[^A-Za-z])(conversation|built_in_tool|hosted_tool|mcp_tool|passthrough)([^A-Za-z]|$)' \
  "${adapter}"/*.go "${adapter}"/testdata "${public_contract}"/*.json | \
  /usr/bin/grep -v -E '_test[.]go:|vendor passthrough' >/dev/null; then
  echo "error: unsupported generic or hosted vendor surface found" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/provider/openairesponses
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/provider/openairesponses
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/provider/openairesponses
"${COH_GO_ROOT}/bin/go" vet ./internal/provider/openairesponses
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${adapter}/README.md" "${public_contract}/README.md"
/usr/bin/git diff --check

echo "openai-responses summary: route=exact tls=1.2+ redirects=denied storage=false background=false truncation=disabled tools=function-only qualification=signed+unexpired schemas=strict reasoning=opaque+digest streaming=correlated+terminal conformance=six-case failures=0"
