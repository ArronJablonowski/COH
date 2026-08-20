#!/bin/bash

# Shared Go environment for COH. Source this file from repository scripts.
# Every mutable Go/toolchain path stays under an explicitly trusted storage
# root. Native macOS defaults to the external SSD used by the workstation,
# while machines with sufficient internal storage may opt in by setting
# COH_NATIVE_STORAGE_ROOT to an existing real directory.

set -euo pipefail

coh_go_lib_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)"
# shellcheck source=storage_contract.sh
source "${coh_go_lib_root}/storage_contract.sh"

COH_GO_VERSION="${COH_GO_VERSION:-${COH_CI_GO_VERSION:-1.26.7}}"
if [[ "${CI:-}" == "true" ]]; then
  [[ -n "${RUNNER_TEMP:-}" && -n "${COH_TOOLCHAIN_ROOT:-}" ]] || {
    echo "Hosted Go environment requires RUNNER_TEMP and COH_TOOLCHAIN_ROOT" >&2
    return 64 2>/dev/null || exit 64
  }
  coh_go_trusted_root="$(coh_real_existing_directory "${RUNNER_TEMP}")" || {
    echo "Cannot resolve RUNNER_TEMP" >&2
    return 64 2>/dev/null || exit 64
  }
  COH_TOOLCHAIN_ROOT="$(coh_prepare_contained_directory "${coh_go_trusted_root}" "${COH_TOOLCHAIN_ROOT}")" || {
    echo "Hosted toolchain root must resolve under RUNNER_TEMP" >&2
    return 64 2>/dev/null || exit 64
  }
else
  if [[ -n "${COH_NATIVE_STORAGE_ROOT:-}" ]]; then
    coh_go_trusted_root="$(coh_real_existing_directory "${COH_NATIVE_STORAGE_ROOT}")" || {
      echo "COH_NATIVE_STORAGE_ROOT must be an existing real directory" >&2
      return 64 2>/dev/null || exit 64
    }
    coh_go_default_toolchain_root="${coh_go_trusted_root}/COH-toolchains"
  else
    coh_go_volume=/Volumes/Untitled
    coh_require_native_macos_volume "${coh_go_volume}" || {
      echo "External SSD volume must be mounted and distinct from the root filesystem" >&2
      return 64 2>/dev/null || exit 64
    }
    coh_go_trusted_root="$(coh_real_existing_directory "${coh_go_volume}")" || {
      echo "External SSD volume is unavailable" >&2
      return 64 2>/dev/null || exit 64
    }
    coh_go_default_toolchain_root="${coh_go_trusted_root}/Codex/toolchains"
  fi
  COH_TOOLCHAIN_ROOT="$(coh_prepare_contained_directory "${coh_go_trusted_root}" "${COH_TOOLCHAIN_ROOT:-${coh_go_default_toolchain_root}}")" || {
    echo "Cannot resolve native toolchain root" >&2
    return 64 2>/dev/null || exit 64
  }
fi
COH_GO_ROOT="${COH_GO_ROOT:-${COH_TOOLCHAIN_ROOT}/go${COH_GO_VERSION}}"
export COH_TOOLCHAIN_ROOT COH_GO_ROOT COH_GO_VERSION

export GOCACHE="${COH_TOOLCHAIN_ROOT}/cache/go${COH_GO_VERSION}/build"
export GOMODCACHE="${COH_TOOLCHAIN_ROOT}/cache/go${COH_GO_VERSION}/modules"
export GOPATH="${COH_TOOLCHAIN_ROOT}/gopath/go${COH_GO_VERSION}"
export GOTMPDIR="${COH_TOOLCHAIN_ROOT}/tmp/go${COH_GO_VERSION}"
export XDG_CONFIG_HOME="${COH_TOOLCHAIN_ROOT}/ci-xdg/config"
export XDG_CACHE_HOME="${COH_TOOLCHAIN_ROOT}/ci-xdg/cache"
export TMPDIR="${GOTMPDIR}"
export GOTOOLCHAIN="local"
export GOENV="off"
export GOFLAGS="-mod=readonly"
export PATH="${COH_GO_ROOT}/bin:/usr/bin:/bin"

for coh_go_variable in GOCACHE GOMODCACHE GOPATH GOTMPDIR XDG_CONFIG_HOME XDG_CACHE_HOME; do
  coh_go_value=${!coh_go_variable}
  coh_go_resolved="$(coh_prepare_contained_directory "${COH_TOOLCHAIN_ROOT}" "${coh_go_value}")" || {
    echo "${coh_go_variable} must resolve under the trusted toolchain root" >&2
    return 64 2>/dev/null || exit 64
  }
  printf -v "${coh_go_variable}" '%s' "${coh_go_resolved}"
  export "${coh_go_variable?}"
done
export TMPDIR="${GOTMPDIR}"

if [[ ! -x "${COH_GO_ROOT}/bin/go" ]]; then
  echo "Go ${COH_GO_VERSION} is unavailable at ${COH_GO_ROOT}/bin/go" >&2
  return 1 2>/dev/null || exit 1
fi

if ! coh_ensure_go_telemetry_off "${coh_go_trusted_root}" "${XDG_CONFIG_HOME}"; then
  echo "Go telemetry must be safely configured off before Go work" >&2
  return 1 2>/dev/null || exit 1
fi

actual_version="$(${COH_GO_ROOT}/bin/go version)"
if [[ "${actual_version}" != go\ version\ go${COH_GO_VERSION}\ * ]]; then
  echo "Expected Go ${COH_GO_VERSION}; found ${actual_version}" >&2
  return 1 2>/dev/null || exit 1
fi

unset actual_version coh_go_value coh_go_resolved coh_go_variable coh_go_trusted_root coh_go_volume coh_go_default_toolchain_root coh_go_lib_root
