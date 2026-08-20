#!/bin/bash

set -euo pipefail

temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-release-lifecycle.XXXXXX")"
cleanup() { /bin/chmod -R u+w "${temporary}" 2>/dev/null || true; /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM
installer="$(cd "$(dirname "${BASH_SOURCE[0]}")" && /bin/pwd -P)/install_release.sh"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
installgate="${temporary}/installgate"
"${COH_GO_BIN:?COH_GO_BIN is required}" build -trimpath -o "${installgate}" "${repo_root}/cmd/installgate"
export COH_INSTALLGATE_BIN="${installgate}"

make_source() {
  local root=$1 marker=$2
  /bin/mkdir -p "${root}/bin" "${root}/share/coh"
  printf 'archcheck-%s\n' "${marker}" > "${root}/bin/archcheck"
  printf 'qualitygate-%s\n' "${marker}" > "${root}/bin/qualitygate"
	/bin/cp "${installgate}" "${root}/bin/installgate"
  printf 'license\n' > "${root}/share/coh/LICENSE"
  /bin/cp "${installer}" "${root}/share/coh/install_release.sh"
	/bin/chmod 0555 "${root}/bin/archcheck" "${root}/bin/installgate" "${root}/bin/qualitygate" "${root}/share/coh/install_release.sh"
  /bin/chmod 0444 "${root}/share/coh/LICENSE"
  : > "${root}/share/coh/release-files.sha256"
	for relative in bin/archcheck bin/installgate bin/qualitygate share/coh/LICENSE share/coh/install_release.sh; do
    digest="$(/usr/bin/shasum -a 256 "${root}/${relative}" | /usr/bin/awk '{print $1}')"
    printf '%s  %s\n' "${digest}" "${relative}" >> "${root}/share/coh/release-files.sha256"
  done
  /bin/chmod 0444 "${root}/share/coh/release-files.sha256"
}

expect_denied() {
  local status
  set +e
  "$@" > "${temporary}/denied.log" 2>&1
  status=$?
  set -e
  [[ "${status}" -eq 2 ]] || { echo "expected denial; status=${status}" >&2; exit 1; }
}

expect_status() {
  local expected=$1 status
  shift
  set +e
  "$@" > "${temporary}/status.log" 2>&1
  status=$?
  set -e
  [[ "${status}" -eq "${expected}" ]] || { echo "expected status ${expected}; status=${status}" >&2; exit 1; }
}

source_v1="${temporary}/source-v1"
source_v2="${temporary}/source-v2"
prefix="${temporary}/install"
make_source "${source_v1}" v1
make_source "${source_v2}" v2
/bin/mkdir "${prefix}"
/bin/chmod 0700 "${prefix}"
expect_status 1 env COH_INSTALL_TIMEOUT=1ns "${installer}" remove "" "${prefix}"

source_link="${temporary}/source-link"
/bin/ln -s "${source_v1}" "${source_link}"
expect_status 2 "${installer}" install "${source_link}" "${prefix}" v0.1.0
expect_denied env COH_LIFECYCLE_TEST_FAULT=install_after_marker "${installer}" install "${source_v1}" "${prefix}" v0.1.0
expect_denied env COH_LIFECYCLE_TEST_FAULT=recovery_cleanup "${installer}" install "${source_v1}" "${prefix}" v0.1.0

"${installer}" install "${source_v1}" "${prefix}" v0.1.0
"${installer}" verify "${source_v1}" "${prefix}"
expect_denied "${installer}" install "${source_v1}" "${prefix}" v0.1.0

expect_denied env COH_LIFECYCLE_TEST_FAULT=upgrade_after_release "${installer}" upgrade "${source_v2}" "${prefix}" v0.2.0
"${installer}" upgrade "${source_v2}" "${prefix}" v0.2.0
"${installer}" verify "${source_v2}" "${prefix}"
expect_denied "${installer}" upgrade "${source_v2}" "${prefix}" v0.2.0

/bin/chmod u+w "${prefix}/releases/v0.1.0/bin/qualitygate"
printf 'corrupt-prior\n' > "${prefix}/releases/v0.1.0/bin/qualitygate"
expect_denied "${installer}" rollback "" "${prefix}"
/usr/bin/install -m 0555 "${source_v1}/bin/qualitygate" "${prefix}/releases/v0.1.0/bin/qualitygate"
/bin/rm "${prefix}/releases/v0.1.0/bin/qualitygate"
/bin/ln -s "${source_v1}/bin/qualitygate" "${prefix}/releases/v0.1.0/bin/qualitygate"
expect_denied "${installer}" rollback "" "${prefix}"
/bin/rm "${prefix}/releases/v0.1.0/bin/qualitygate"
/usr/bin/install -m 0555 "${source_v1}/bin/qualitygate" "${prefix}/releases/v0.1.0/bin/qualitygate"
printf 'interrupted\n' > "${prefix}/.state.pending"
"${installer}" rollback "" "${prefix}"
"${installer}" verify "${source_v1}" "${prefix}"

/bin/chmod u+w "${prefix}/releases/v0.1.0/bin/qualitygate"
printf 'corrupt\n' > "${prefix}/releases/v0.1.0/bin/qualitygate"
expect_denied "${installer}" verify "${source_v1}" "${prefix}"
/usr/bin/install -m 0555 "${source_v1}/bin/qualitygate" "${prefix}/releases/v0.1.0/bin/qualitygate"

/usr/bin/touch "${prefix}/unexpected"
expect_denied "${installer}" remove "" "${prefix}"
/bin/rm "${prefix}/unexpected"
expect_denied env COH_LIFECYCLE_TEST_FAULT=remove_after_releases "${installer}" remove "" "${prefix}"
expect_denied env COH_LIFECYCLE_TEST_FAULT=recovery_cleanup "${installer}" remove "" "${prefix}"
"${installer}" remove "" "${prefix}"
[[ -z "$(/bin/ls -A "${prefix}")" ]] || { echo "removal left managed state" >&2; exit 1; }

post_state_prefix="${temporary}/post-state-install"
/bin/mkdir "${post_state_prefix}"
/bin/chmod 0700 "${post_state_prefix}"
expect_denied env COH_LIFECYCLE_TEST_FAULT=install_after_state "${installer}" install "${source_v1}" "${post_state_prefix}" v0.1.0
"${installer}" install "${source_v1}" "${post_state_prefix}" v0.1.0
expect_denied env COH_LIFECYCLE_TEST_FAULT=upgrade_after_state "${installer}" upgrade "${source_v2}" "${post_state_prefix}" v0.2.0
/bin/chmod u+w "${post_state_prefix}/releases/v0.2.0/bin/qualitygate"
printf 'post-state-corrupt\n' > "${post_state_prefix}/releases/v0.2.0/bin/qualitygate"
expect_denied "${installer}" upgrade "${source_v2}" "${post_state_prefix}" v0.2.0
/usr/bin/install -m 0555 "${source_v2}/bin/qualitygate" "${post_state_prefix}/releases/v0.2.0/bin/qualitygate"
"${installer}" upgrade "${source_v2}" "${post_state_prefix}" v0.2.0
expect_denied env COH_LIFECYCLE_TEST_FAULT=rollback_after_state "${installer}" rollback "" "${post_state_prefix}"
"${installer}" rollback "" "${post_state_prefix}"
"${installer}" remove "" "${post_state_prefix}"

echo "Release lifecycle contract tests: passed"
