#!/bin/bash

# Shared native CI environment. Source after setting COH_CI_LANE.

set -euo pipefail

coh_ci_lib_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)"
# shellcheck source=storage_contract.sh
source "${coh_ci_lib_root}/storage_contract.sh"

fail_ci_env() {
  echo "$1" >&2
  return 64 2>/dev/null || exit 64
}

COH_CI_LANE="${COH_CI_LANE:-baseline}"
case "${COH_CI_LANE}" in
  baseline) COH_CI_GO_VERSION="1.26.7" ;;
  go1.27) COH_CI_GO_VERSION="1.27.0" ;;
  *) fail_ci_env "Unsupported CI lane: ${COH_CI_LANE}" ;;
esac

if [[ "${CI:-}" == "true" ]]; then
	[[ -n "${RUNNER_TEMP:-}" && -n "${COH_TOOLCHAIN_ROOT:-}" ]] || fail_ci_env "Hosted CI requires RUNNER_TEMP and COH_TOOLCHAIN_ROOT"
	coh_ci_runner_root="$(coh_real_existing_directory "${RUNNER_TEMP}")" || fail_ci_env "Cannot resolve RUNNER_TEMP"
	COH_TOOLCHAIN_ROOT="$(coh_prepare_contained_directory "${coh_ci_runner_root}" "${COH_TOOLCHAIN_ROOT}")" || fail_ci_env "Hosted toolchain root must resolve under RUNNER_TEMP"
  COH_GO_ROOT="${COH_GO_ROOT:-$($(command -v go) env GOROOT)}"
  coh_ci_mutable_root="${coh_ci_runner_root}"
else
	if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
		coh_ci_volume=/Volumes/Untitled
		coh_require_native_macos_volume "${coh_ci_volume}" || fail_ci_env "External SSD volume must be mounted and distinct from the root filesystem"
		coh_ci_external_root="$(coh_real_existing_directory "${coh_ci_volume}")" || fail_ci_env "External SSD volume is unavailable"
		COH_TOOLCHAIN_ROOT="$(coh_prepare_contained_directory "${coh_ci_external_root}" "${COH_TOOLCHAIN_ROOT:-${coh_ci_external_root}/Codex/toolchains}")" || fail_ci_env "Cannot resolve native toolchain root"
		coh_ci_mutable_root="${coh_ci_external_root}"
	else
		[[ -n "${COH_TOOLCHAIN_ROOT:-}" ]] || fail_ci_env "Native Linux requires an explicit external COH_TOOLCHAIN_ROOT"
		COH_TOOLCHAIN_ROOT="$(coh_real_existing_directory "${COH_TOOLCHAIN_ROOT}")" || fail_ci_env "Native Linux toolchain root must already exist and be a real directory"
    coh_ci_mutable_root="${COH_TOOLCHAIN_ROOT}"
  fi
  COH_GO_ROOT="${COH_GO_ROOT:-${COH_TOOLCHAIN_ROOT}/go${COH_CI_GO_VERSION}}"
fi

export COH_CI_LANE COH_CI_GO_VERSION COH_TOOLCHAIN_ROOT COH_GO_ROOT
export GOCACHE="${COH_TOOLCHAIN_ROOT}/cache/go${COH_CI_GO_VERSION}/build"
export GOMODCACHE="${COH_TOOLCHAIN_ROOT}/cache/go${COH_CI_GO_VERSION}/modules"
export GOPATH="${COH_TOOLCHAIN_ROOT}/gopath/go${COH_CI_GO_VERSION}"
export GOTMPDIR="${COH_TOOLCHAIN_ROOT}/tmp/go${COH_CI_GO_VERSION}"
export GOBIN="${COH_TOOLCHAIN_ROOT}/ci-tools/go${COH_CI_GO_VERSION}/bin"
export XDG_CONFIG_HOME="${COH_TOOLCHAIN_ROOT}/ci-xdg/config"
export XDG_CACHE_HOME="${COH_TOOLCHAIN_ROOT}/ci-xdg/cache"
export STATICCHECK_CACHE="${COH_TOOLCHAIN_ROOT}/staticcheck-cache/${COH_CI_LANE}"
export COH_CI_LOCK_DIR="${COH_TOOLCHAIN_ROOT}/locks"
export COH_CI_DOWNLOAD_DIR="${COH_TOOLCHAIN_ROOT}/downloads"
export COH_GO_BIN="${COH_GO_ROOT}/bin/go"
export COH_CI_ARTIFACT_DIR="${COH_CI_ARTIFACT_DIR:-${COH_TOOLCHAIN_ROOT}/ci-artifacts/${COH_CI_LANE}}"
export TMPDIR="${GOTMPDIR}"
export GOTOOLCHAIN=local GOENV=off GOTELEMETRY=off GOFLAGS=-mod=readonly
export PATH="${COH_GO_ROOT}/bin:/usr/bin:/bin"
export GOPROXY=off GOSUMDB=off
export GOPRIVATE='' GONOPROXY='' GONOSUMDB=''

for coh_ci_variable in GOCACHE GOMODCACHE GOPATH GOTMPDIR GOBIN XDG_CONFIG_HOME XDG_CACHE_HOME STATICCHECK_CACHE COH_CI_LOCK_DIR COH_CI_DOWNLOAD_DIR COH_CI_ARTIFACT_DIR; do
	coh_ci_value=${!coh_ci_variable}
	coh_ci_resolved="$(coh_prepare_contained_directory "${coh_ci_mutable_root}" "${coh_ci_value}")" || fail_ci_env "${coh_ci_variable} must resolve under approved mutable storage"
	printf -v "${coh_ci_variable}" '%s' "${coh_ci_resolved}"
	export "${coh_ci_variable?}"
done
export TMPDIR="${GOTMPDIR}"

if [[ ! -x "${COH_GO_BIN}" ]]; then
  fail_ci_env "Pinned Go executable is unavailable: ${COH_GO_BIN}"
fi
actual_version="$("${COH_GO_BIN}" env GOVERSION)"
if [[ "${actual_version}" != "go${COH_CI_GO_VERSION}" ]]; then
  fail_ci_env "CI lane ${COH_CI_LANE} requires go${COH_CI_GO_VERSION}; found ${actual_version}"
fi
unset actual_version coh_ci_resolved coh_ci_value coh_ci_variable coh_ci_mutable_root coh_ci_external_root coh_ci_runner_root coh_ci_volume coh_ci_lib_root
