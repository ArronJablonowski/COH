#!/bin/bash

set -euo pipefail

mode=${1:-}
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scan_root=${2:-${repo_root}}
gitleaks="${GOBIN:?GOBIN is required}/gitleaks"
config="${repo_root}/ci/gitleaks.toml"
ignore="${repo_root}/ci/gitleaks.ignore"
[[ "${scan_root}" == /* && -d "${scan_root}" && ! -L "${scan_root}" ]] || { echo "Secret scan root must be an absolute real directory" >&2; exit 64; }

git_environment=(
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=2
  GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=false
  GIT_CONFIG_KEY_1=core.hooksPath GIT_CONFIG_VALUE_1=/dev/null
  GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 LANG=C LC_ALL=C PATH=/usr/bin:/bin
  "TMPDIR=${GOTMPDIR:?GOTMPDIR is required}"
)

safe_git() {
  env -i "${git_environment[@]}" /usr/bin/git \
    -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    --git-dir="${scan_root}/.git" --work-tree="${scan_root}" "$@"
}

safe_gitleaks() {
  env -i "${git_environment[@]}" "${gitleaks}" "$@"
}

verify_complete_history() {
  local state_file partial status bytes
  [[ -d "${scan_root}/.git" && ! -L "${scan_root}/.git" ]] || { echo "Secret history requires a real Git directory" >&2; exit 2; }
  [[ "$(safe_git rev-parse --is-shallow-repository)" == "false" ]] || { echo "Secret history scan rejects shallow repositories" >&2; exit 2; }
  set +e
  partial="$(safe_git config --local --get-regexp '^(extensions\.partialClone|remote\..*\.promisor)$' 2>/dev/null)"
  status=$?
  set -e
  (( status == 0 || status == 1 )) || { echo "Unable to inspect partial-clone configuration" >&2; exit 1; }
  [[ -z "${partial}" ]] || { echo "Secret history scan rejects partial or promisor repositories" >&2; exit 2; }
  [[ ! -s "${scan_root}/.git/info/grafts" ]] || { echo "Secret history scan rejects grafted history" >&2; exit 2; }
  [[ -z "$(safe_git for-each-ref --format='%(refname)' refs/replace)" ]] || { echo "Secret history scan rejects replacement refs" >&2; exit 2; }
  state_file="$(/usr/bin/mktemp "${GOTMPDIR:?GOTMPDIR is required}/coh-history.XXXXXX")"
  set +e
  safe_git rev-list --objects --all --missing=print > "${state_file}"
  status=$?
  set -e
  (( status == 0 )) || { /bin/rm -f "${state_file}"; echo "Secret history scan rejects incomplete Git objects" >&2; exit 2; }
  bytes="$(/usr/bin/wc -c < "${state_file}" | /usr/bin/tr -d ' ')"
  (( bytes <= 67108864 )) || { /bin/rm -f "${state_file}"; echo "Git history inventory exceeds the bounded limit" >&2; exit 2; }
  if /usr/bin/grep -q '^?' "${state_file}"; then
    /bin/rm -f "${state_file}"
    echo "Secret history scan rejects missing Git objects" >&2
    exit 2
  fi
  /bin/rm -f "${state_file}"
}

case "${mode}" in
  worktree)
    safe_gitleaks dir --config "${config}" --gitleaks-ignore-path "${ignore}" --ignore-gitleaks-allow --no-banner --redact --exit-code 2 "${scan_root}"
    ;;
  history)
    if safe_git rev-parse --verify HEAD >/dev/null 2>&1; then
      verify_complete_history
      safe_gitleaks git --log-opts=--all --config "${config}" --gitleaks-ignore-path "${ignore}" --ignore-gitleaks-allow --no-banner --redact --exit-code 2 "${scan_root}"
    elif [[ -z "$(safe_git rev-list --all 2>/dev/null)" ]]; then
      if [[ "${CI:-}" == "true" ]]; then
        echo "Hosted CI requires a committed full-history checkout" >&2
        exit 2
      fi
      echo "secret-history: not_applicable_unborn quality_gate_promotable=false"
    else
      echo "Unable to verify repository history state" >&2
      exit 1
    fi
    ;;
  evidence)
    artifact_dir="${2:-${COH_CI_ARTIFACT_DIR:?COH_CI_ARTIFACT_DIR is required}}"
    [[ "${artifact_dir}" == /* && -d "${artifact_dir}" && ! -L "${artifact_dir}" ]] || { echo "Evidence root must be an absolute real directory" >&2; exit 64; }
    safe_gitleaks dir --config "${config}" --gitleaks-ignore-path "${ignore}" --ignore-gitleaks-allow --no-banner --redact --exit-code 2 "${artifact_dir}"
    ;;
  *) echo "Usage: $0 worktree|history|evidence" >&2; exit 64 ;;
esac
