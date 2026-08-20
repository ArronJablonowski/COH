#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=lib/storage_contract.sh
source "${repo_root}/scripts/lib/storage_contract.sh"

temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-storage-contract.XXXXXX")"
cleanup() { /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM

expect_denied() {
  if "$@" >/dev/null 2>&1; then
    echo "storage contract unexpectedly allowed an unsafe path" >&2
    return 2
  fi
}

expect_denied coh_validate_mount_facts false false true 1 2 || exit 21
expect_denied coh_validate_mount_facts true true true 1 2 || exit 21
expect_denied coh_validate_mount_facts true false false 1 2 || exit 21
expect_denied coh_validate_mount_facts true false true 1 1 || exit 21
coh_validate_mount_facts true false true 1 2 || exit 21

trusted="${temporary}/trusted volume"
outside="${temporary}/outside"
/bin/mkdir -p "${trusted}" "${outside}"
/bin/ln -s "${outside}" "${trusted}/cache"
expect_denied coh_prepare_contained_directory "${trusted}" "${trusted}/cache/new" || exit 22
[[ ! -e "${outside}/new" ]] || { echo "symlink denial wrote outside the trusted root" >&2; exit 22; }

hosted="${temporary}/runner temp"
/bin/mkdir -p "${hosted}"
/bin/ln -s "${outside}" "${hosted}/ci-tools"
expect_denied coh_prepare_contained_directory "${hosted}" "${hosted}/ci-tools/bin" || exit 22
[[ ! -e "${outside}/bin" ]] || { echo "hosted symlink denial wrote outside RUNNER_TEMP" >&2; exit 22; }

for name in ci-xdg staticcheck-cache; do
  protected="${temporary}/protected-${name}"
  /bin/mkdir -p "${protected}"
  /bin/ln -s "${outside}" "${protected}/${name}"
  expect_denied coh_prepare_contained_directory "${protected}" "${protected}/${name}/cache" || exit 22
  [[ ! -e "${outside}/cache" ]] || { echo "${name} symlink denial wrote outside approved storage" >&2; exit 22; }
done

resolved="$(coh_prepare_contained_directory "${trusted}" "${trusted}/safe path/cache")" || exit 22
[[ "${resolved}" == "${trusted}/safe path/cache" ]] || { echo "path-with-spaces resolution drifted" >&2; exit 22; }

telemetry_trusted="${temporary}/telemetry-trusted"
telemetry_outside="${temporary}/telemetry-outside"
/bin/mkdir -p "${telemetry_trusted}/config/go/telemetry" "${telemetry_outside}"
printf 'outside-sentinel' > "${telemetry_outside}/mode"
/bin/ln -s "${telemetry_outside}/mode" "${telemetry_trusted}/config/go/telemetry/mode"
expect_denied coh_prepare_go_telemetry_mode "${telemetry_trusted}" "${telemetry_trusted}/config" || exit 22
[[ "$(/bin/cat "${telemetry_outside}/mode")" == outside-sentinel ]] || exit 22
/bin/rm "${telemetry_trusted}/config/go/telemetry/mode"
/bin/rm -rf "${telemetry_trusted}/config/go"
/bin/ln -s "${telemetry_outside}" "${telemetry_trusted}/config/go"
expect_denied coh_prepare_go_telemetry_mode "${telemetry_trusted}" "${telemetry_trusted}/config" || exit 22
/bin/rm "${telemetry_trusted}/config/go"
telemetry_mode="$(coh_prepare_go_telemetry_mode "${telemetry_trusted}" "${telemetry_trusted}/config")" || exit 22
[[ "${telemetry_mode}" == "${telemetry_trusted}/config/go/telemetry/mode" && -f "${telemetry_mode}" && ! -L "${telemetry_mode}" ]] || exit 22
[[ "$(/bin/cat "${telemetry_mode}")" == off ]] || exit 22
[[ "$(coh_prepare_go_telemetry_mode "${telemetry_trusted}" "${telemetry_trusted}/config")" == "${telemetry_mode}" ]] || exit 22
/bin/chmod 0666 "${telemetry_mode}"
expect_denied coh_prepare_go_telemetry_mode "${telemetry_trusted}" "${telemetry_trusted}/config" || exit 22
/bin/chmod 0600 "${telemetry_mode}"

hosted_go_root="${temporary}/go-hosted"
/bin/mkdir -p "${hosted_go_root}"
set +e
CI=true RUNNER_TEMP="${hosted_go_root}" COH_TOOLCHAIN_ROOT="${hosted_go_root}/toolchains" \
  COH_GO_ROOT="${COH_GO_ROOT:?COH_GO_ROOT is required}" COH_GO_VERSION="${COH_CI_GO_VERSION:-1.26.7}" \
  /bin/bash -c 'source "$1"; [[ "$TMPDIR" == "$GOTMPDIR" && "$GOTMPDIR" == "$COH_TOOLCHAIN_ROOT"/* ]]' \
  _ "${repo_root}/scripts/lib/go_ssd_env.sh"
hosted_go_status=$?
set -e
if (( hosted_go_status != 0 )); then
  (( hosted_go_status != 64 )) || exit 31
  [[ -x "${COH_GO_ROOT}/bin/go" ]] || exit 32
  hosted_go_version="$("${COH_GO_ROOT}/bin/go" version)" || exit 32
  [[ "${hosted_go_version}" == go\ version\ go${COH_CI_GO_VERSION:-1.26.7}\ * ]] || exit 33
  hosted_telemetry_mode="$("${COH_GO_ROOT}/bin/go" telemetry)" || exit 34
  [[ "${hosted_telemetry_mode}" == "off" ]] || exit 34
  exit 35
fi

native_storage_root="${temporary}/native storage"
/bin/mkdir -p "${native_storage_root}/COH-toolchains"
/usr/bin/env -u CI -u RUNNER_TEMP \
  COH_NATIVE_STORAGE_ROOT="${native_storage_root}" \
  COH_TOOLCHAIN_ROOT="${native_storage_root}/COH-toolchains" \
  COH_GO_ROOT="${COH_GO_ROOT:?COH_GO_ROOT is required}" COH_GO_VERSION="${COH_CI_GO_VERSION:-1.26.7}" \
  /bin/bash -c 'source "$1"; [[ "$TMPDIR" == "$GOTMPDIR" && "$GOTMPDIR" == "$COH_TOOLCHAIN_ROOT"/* ]]' \
  _ "${repo_root}/scripts/lib/go_ssd_env.sh" || exit 24

missing_native_root="${temporary}/missing-native-root"
if /usr/bin/env -u CI -u RUNNER_TEMP \
  COH_NATIVE_STORAGE_ROOT="${missing_native_root}" \
  COH_TOOLCHAIN_ROOT="${missing_native_root}/COH-toolchains" \
  COH_GO_ROOT="${COH_GO_ROOT}" COH_GO_VERSION="${COH_CI_GO_VERSION:-1.26.7}" \
  /bin/bash -c 'source "$1"' _ "${repo_root}/scripts/lib/go_ssd_env.sh" >/dev/null 2>&1; then
  echo "Go environment accepted a missing native storage root" >&2
  exit 25
fi
[[ ! -e "${missing_native_root}" ]] || {
  echo "Rejected native storage root was created" >&2
  exit 25
}

attack_runner="${temporary}/attack-runner"
attack_outside="${temporary}/attack-outside"
/bin/mkdir -p "${attack_runner}/toolchains" "${attack_outside}"
/bin/ln -s "${attack_outside}" "${attack_runner}/toolchains/cache"
if CI=true RUNNER_TEMP="${attack_runner}" COH_TOOLCHAIN_ROOT="${attack_runner}/toolchains" \
  COH_GO_ROOT="${COH_GO_ROOT}" COH_GO_VERSION="${COH_CI_GO_VERSION:-1.26.7}" \
  /bin/bash -c 'source "$1"' _ "${repo_root}/scripts/lib/go_ssd_env.sh" >/dev/null 2>&1; then
  echo "Go SSD environment accepted a symlinked mutable descendant" >&2
  exit 26
fi
[[ ! -e "${attack_outside}/go${COH_CI_GO_VERSION:-1.26.7}" ]] || {
  echo "Go SSD environment wrote through a rejected symlink" >&2
  exit 26
}

echo "CI storage contract tests: passed"
