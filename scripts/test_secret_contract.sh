#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-secret-contract.XXXXXX")"
cleanup() { /bin/chmod -R u+w "${temporary}" 2>/dev/null || true; /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM

synthetic_key='COH_TEST_''SECRET_0123456789ABCDEF0123456789ABCDEF'
synthetic_secret='COH_TEST_''SECRET_FEDCBA9876543210FEDCBA9876543210'

write_synthetic_secret() {
  printf 'access_key=%s\nsecret_key=%s\n' "${synthetic_key}" "${synthetic_secret}" > "$1"
}

expect_secret_denial() {
  local label=$1
  shift
  local output="${temporary}/${label}.out" status
  set +e
  "$@" > "${output}" 2>&1
  status=$?
  set -e
  if (( status != 2 )); then
    echo "${label} returned ${status}; expected denial" >&2
    exit 1
  fi
  if /usr/bin/grep -Fq "${synthetic_key}" "${output}" || /usr/bin/grep -Fq "${synthetic_secret}" "${output}"; then
    echo "${label} leaked synthetic secret plaintext" >&2
    exit 2
  fi
}

git_repo() {
  local root=$1
  /usr/bin/git init -q "${root}"
  /usr/bin/git -C "${root}" config user.email coh-ci@example.invalid
  /usr/bin/git -C "${root}" config user.name 'COH CI'
}

worktree="${temporary}/worktree"
/bin/mkdir -p "${worktree}"
write_synthetic_secret "${worktree}/fixture.txt"
expect_secret_denial worktree "${repo_root}/scripts/check_secrets.sh" worktree "${worktree}"
expect_secret_denial evidence "${repo_root}/scripts/check_secrets.sh" evidence "${worktree}"

history="${temporary}/history"
git_repo "${history}"
write_synthetic_secret "${history}/fixture.txt"
/usr/bin/git -C "${history}" add fixture.txt
/usr/bin/git -C "${history}" commit -q -m synthetic-secret
/bin/rm "${history}/fixture.txt"
/usr/bin/git -C "${history}" add -u
/usr/bin/git -C "${history}" commit -q -m remove-secret
expect_secret_denial history "${repo_root}/scripts/check_secrets.sh" history "${history}"

clean="${temporary}/clean"
git_repo "${clean}"
printf 'clean\n' > "${clean}/input.txt"
/usr/bin/git -C "${clean}" add input.txt
/usr/bin/git -C "${clean}" commit -q -m clean

shallow="${temporary}/shallow"
/usr/bin/git clone -q --depth=1 "file://${clean}" "${shallow}"
expect_secret_denial shallow "${repo_root}/scripts/check_secrets.sh" history "${shallow}"

partial="${temporary}/partial"
/bin/cp -R "${clean}" "${partial}"
/usr/bin/git -C "${partial}" config remote.origin.promisor true
expect_secret_denial partial "${repo_root}/scripts/check_secrets.sh" history "${partial}"

replacement="${temporary}/replacement"
/bin/cp -R "${clean}" "${replacement}"
head_commit="$(/usr/bin/git -C "${replacement}" rev-parse HEAD)"
tree="$(/usr/bin/git -C "${replacement}" rev-parse 'HEAD^{tree}')"
other_commit="$(printf 'replacement\n' | /usr/bin/git -C "${replacement}" commit-tree "${tree}")"
/usr/bin/git -C "${replacement}" replace "${head_commit}" "${other_commit}"
expect_secret_denial replacement "${repo_root}/scripts/check_secrets.sh" history "${replacement}"

missing="${temporary}/missing"
/bin/cp -R "${clean}" "${missing}"
blob="$(/usr/bin/git -C "${missing}" rev-parse HEAD:input.txt)"
/bin/rm -f "${missing}/.git/objects/${blob:0:2}/${blob:2}"
expect_secret_denial missing-object "${repo_root}/scripts/check_secrets.sh" history "${missing}"

monitor="${temporary}/monitor"
/bin/cp -R "${clean}" "${monitor}"
marker="${temporary}/fsmonitor-ran"
hook="${temporary}/fsmonitor.sh"
printf '#!/bin/sh\nprintf ran > "%s"\n' "${marker}" > "${hook}"
/bin/chmod 0700 "${hook}"
/usr/bin/git -C "${monitor}" config core.fsmonitor "${hook}"
"${repo_root}/scripts/check_secrets.sh" history "${monitor}" >/dev/null 2>&1
[[ ! -e "${marker}" ]] || { echo "secret history executed repository fsmonitor" >&2; exit 2; }

echo "Secret negative contract tests: passed"
