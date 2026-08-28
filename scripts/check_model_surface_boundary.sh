#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "${root}"

status=0
while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  echo "error: production code imports a concrete provider adapter and can bypass model-surface admission: ${path}" >&2
  status=2
done < <(/usr/bin/find internal cmd -type f -name '*.go' ! -name '*_test.go' -print0 |
  /usr/bin/xargs -0 /usr/bin/grep -lE 'github[.]com/ArronJablonowski/COH/internal/provider/(ollama|llamacpp|vllm|openairesponses|codexruntime)' 2>/dev/null || true)

while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  case "${path}" in
    internal/domain/providercontract/*|internal/provider/*|internal/domain/modelsurface/admission.go) continue ;;
  esac
  echo "error: production code handles a raw validated provider request outside the admitted boundary: ${path}" >&2
  status=2
done < <(/usr/bin/find internal cmd -type f -name '*.go' ! -name '*_test.go' -print0 |
  /usr/bin/xargs -0 /usr/bin/grep -l 'providercontract.ValidatedRequest' 2>/dev/null || true)

if (( status != 0 )); then
  exit "${status}"
fi
echo "model-surface boundary: concrete-adapter-imports=0 raw-request-bypasses=0"
