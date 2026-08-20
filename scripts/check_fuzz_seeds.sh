#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/ci/fuzz-targets.txt"
inventory="$(mktemp "${GOTMPDIR}/coh-fuzz-targets.XXXXXX")"
trace="$(mktemp "${GOTMPDIR}/coh-fuzz-execution.XXXXXX")"
cleanup() { rm -f "${inventory}" "${trace}"; }
trap cleanup EXIT

"${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" \
  -mode verify-fuzz-manifest -root "${repo_root}" -input "${manifest}" > "${inventory}"

count=0
while read -r package target extra; do
  if [[ -n "${extra:-}" || -z "${package}" || -z "${target}" ]]; then
    echo "Validated fuzz inventory was not canonical" >&2
    exit 1
  fi
  : > "${trace}"
  set +e
  "${COH_GO_BIN}" test -count=1 -run "^${target}$" -json "${package}" | /usr/bin/head -c 67108865 > "${trace}"
  test_status=${PIPESTATUS[0]}
  set -e
  trace_size="$(/usr/bin/wc -c < "${trace}" | /usr/bin/tr -d ' ')"
  if (( trace_size > 67108864 )); then
    echo "Fuzz execution trace exceeded 64 MiB" >&2
    exit 2
  fi
  if (( test_status != 0 )); then
    echo "Fuzz seed execution failed for ${package} ${target}" >&2
    exit 2
  fi
  verification="$("${COH_QUALITYGATE_BIN}" -mode verify-fuzz-execution -input "${trace}" -fuzz-target "${target}")"
  trace_digest="$("${COH_QUALITYGATE_BIN}" -mode digest -input "${trace}")"
  printf 'fuzz-target package=%s target=%s trace_sha256=%s %s\n' "${package}" "${target}" "${trace_digest}" "${verification}"
  count=$((count + 1))
done < "${inventory}"

if (( count == 0 )); then
  echo "Validated fuzz inventory returned no targets" >&2
  exit 2
fi

echo "fuzz-seed summary: targets=${count} seed_callbacks=executed"
