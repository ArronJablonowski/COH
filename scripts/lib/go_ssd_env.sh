#!/bin/bash

# Shared Go environment for COH. Source this file from repository scripts.
# Every mutable Go/toolchain path stays on the external SSD by default.

set -euo pipefail

COH_TOOLCHAIN_ROOT="${COH_TOOLCHAIN_ROOT:-/Volumes/Untitled/Codex/toolchains}"
COH_GO_ROOT="${COH_GO_ROOT:-${COH_TOOLCHAIN_ROOT}/go1.26.7}"
COH_GO_VERSION="1.26.7"

export GOCACHE="${COH_TOOLCHAIN_ROOT}/cache/go${COH_GO_VERSION}/build"
export GOMODCACHE="${COH_TOOLCHAIN_ROOT}/cache/go${COH_GO_VERSION}/modules"
export GOPATH="${COH_TOOLCHAIN_ROOT}/gopath/go${COH_GO_VERSION}"
export GOTMPDIR="${COH_TOOLCHAIN_ROOT}/tmp/go${COH_GO_VERSION}"
export GOTOOLCHAIN="local"
export GOENV="off"
export GOTELEMETRY="off"
export GOFLAGS="-mod=readonly"
export PATH="${COH_GO_ROOT}/bin:${PATH}"

mkdir -p "${GOCACHE}" "${GOMODCACHE}" "${GOPATH}" "${GOTMPDIR}"

if [[ ! -x "${COH_GO_ROOT}/bin/go" ]]; then
  echo "Go ${COH_GO_VERSION} is unavailable at ${COH_GO_ROOT}/bin/go" >&2
  return 1 2>/dev/null || exit 1
fi

actual_version="$(${COH_GO_ROOT}/bin/go version)"
if [[ "${actual_version}" != go\ version\ go${COH_GO_VERSION}\ * ]]; then
  echo "Expected Go ${COH_GO_VERSION}; found ${actual_version}" >&2
  return 1 2>/dev/null || exit 1
fi

telemetry_mode="$(${COH_GO_ROOT}/bin/go telemetry)"
if [[ "${telemetry_mode}" != "off" ]]; then
  echo "Go telemetry must be off to prevent writes to the internal system drive" >&2
  echo "Run: ${COH_GO_ROOT}/bin/go telemetry off" >&2
  return 1 2>/dev/null || exit 1
fi

unset actual_version telemetry_mode
