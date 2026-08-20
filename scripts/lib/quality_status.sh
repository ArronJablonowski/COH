#!/bin/bash

# Map a finding from tools whose documented finding exit is 1 to the quality
# contract's denial exit. Invocation, signal, and typed exits are preserved.
coh_normalize_stage_status() {
  local classification=$1
  local status=$2
  if [[ "${classification}" == denial && "${status}" -eq 1 ]]; then
    printf '2\n'
    return 0
  fi
  printf '%s\n' "${status}"
}
