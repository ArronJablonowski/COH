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
    exit 2
  fi
}

expect_denied coh_validate_mount_facts false false true 1 2
expect_denied coh_validate_mount_facts true true true 1 2
expect_denied coh_validate_mount_facts true false false 1 2
expect_denied coh_validate_mount_facts true false true 1 1
coh_validate_mount_facts true false true 1 2

trusted="${temporary}/trusted volume"
outside="${temporary}/outside"
/bin/mkdir -p "${trusted}" "${outside}"
/bin/ln -s "${outside}" "${trusted}/cache"
expect_denied coh_prepare_contained_directory "${trusted}" "${trusted}/cache/new"
[[ ! -e "${outside}/new" ]] || { echo "symlink denial wrote outside the trusted root" >&2; exit 2; }

hosted="${temporary}/runner temp"
/bin/mkdir -p "${hosted}"
/bin/ln -s "${outside}" "${hosted}/ci-tools"
expect_denied coh_prepare_contained_directory "${hosted}" "${hosted}/ci-tools/bin"
[[ ! -e "${outside}/bin" ]] || { echo "hosted symlink denial wrote outside RUNNER_TEMP" >&2; exit 2; }

for name in ci-xdg staticcheck-cache; do
  protected="${temporary}/protected-${name}"
  /bin/mkdir -p "${protected}"
  /bin/ln -s "${outside}" "${protected}/${name}"
  expect_denied coh_prepare_contained_directory "${protected}" "${protected}/${name}/cache"
  [[ ! -e "${outside}/cache" ]] || { echo "${name} symlink denial wrote outside approved storage" >&2; exit 2; }
done

resolved="$(coh_prepare_contained_directory "${trusted}" "${trusted}/safe path/cache")"
[[ "${resolved}" == "${trusted}/safe path/cache" ]] || { echo "path-with-spaces resolution drifted" >&2; exit 2; }

echo "CI storage contract tests: passed"
