#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/ci_env.sh
source "${repo_root}/scripts/lib/ci_env.sh"
# shellcheck source=lib/tool_promotion.sh
source "${repo_root}/scripts/lib/tool_promotion.sh"

quality_binary="${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}"
lock=ci/tools.lock.json
promotion_lock="${COH_CI_LOCK_DIR}/bootstrap-${COH_CI_LANE}.lock"
coh_acquire_directory_lock "${promotion_lock}" 120 || { echo "Timed out waiting for CI tool bootstrap lock" >&2; exit 124; }
release_lock() { /bin/rmdir "${promotion_lock}" 2>/dev/null || true; }
trap release_lock EXIT HUP INT TERM

verify_installed() {
  "${quality_binary}" -mode verify-tools -root "${repo_root}" -lane "${COH_CI_LANE}" -tool-lock "${lock}" -tool-bin "${GOBIN}"
}

tool_parent="${COH_TOOLCHAIN_ROOT}/ci-tools/go${COH_CI_GO_VERSION}"
coh_recover_tool_promotion "${tool_parent}" || { echo "Cannot recover interrupted tool promotion" >&2; exit 1; }
if [[ "${COH_CI_OFFLINE:-false}" == "true" ]]; then
  verify_installed
  echo "Pinned CI tools verified offline in ${GOBIN}"
  exit 0
fi

bootstrap_root="$(/usr/bin/mktemp -d "${COH_TOOLCHAIN_ROOT}/tmp/bootstrap-${COH_CI_LANE}.XXXXXX")"
fresh_bin="${bootstrap_root}/bin"
fresh_modules="${bootstrap_root}/modules"
fresh_cache="${bootstrap_root}/build-cache"
fresh_gopath="${bootstrap_root}/gopath"
extract_root="${bootstrap_root}/extract"
mkdir -p "${fresh_bin}" "${fresh_modules}" "${fresh_cache}" "${fresh_gopath}" "${extract_root}"
cleanup() {
  /bin/chmod -R u+w "${bootstrap_root}" 2>/dev/null || true
  /bin/rm -rf -- "${bootstrap_root}" 2>/dev/null || true
}
trap 'cleanup; release_lock' EXIT HUP INT TERM

export GOBIN="${fresh_bin}" GOMODCACHE="${fresh_modules}" GOCACHE="${fresh_cache}" GOPATH="${fresh_gopath}"
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOPRIVATE='' GONOPROXY='' GONOSUMDB='' CGO_ENABLED=0

"${quality_binary}" -mode verify-tool-sources -root "${repo_root}" -lane "${COH_CI_LANE}" -tool-lock "${lock}"

"${COH_GO_BIN}" install -trimpath github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
"${COH_GO_BIN}" install -trimpath github.com/zricethezav/gitleaks/v8@v8.30.1
"${COH_GO_BIN}" install -trimpath golang.org/x/vuln/cmd/govulncheck@v1.7.0
if [[ "${COH_CI_LANE}" == "baseline" ]]; then
  "${COH_GO_BIN}" install -trimpath honnef.co/go/tools/cmd/staticcheck@v0.7.0
fi

goos="$("${COH_GO_BIN}" env GOOS)"
goarch="$("${COH_GO_BIN}" env GOARCH)"
case "${goos}/${goarch}" in
  darwin/arm64) asset=darwin.aarch64; archive_sha=339b930feb1ea764467013cc1f72d09cd6b869ebf1013296ba9055ab2ffbd26f ;;
  linux/amd64) asset=linux.x86_64; archive_sha=b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6 ;;
  linux/arm64) asset=linux.aarch64; archive_sha=68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc ;;
  *) echo "ShellCheck is not pinned for ${goos}/${goarch}" >&2; exit 2 ;;
esac

download_dir="${COH_CI_DOWNLOAD_DIR}/shellcheck-v0.11.0"
archive="${download_dir}/shellcheck-v0.11.0.${asset}.tar.gz"
mkdir -p "${download_dir}"
if [[ ! -f "${archive}" ]]; then
  temporary="$(/usr/bin/mktemp "${download_dir}/.download.XXXXXX")"
  /usr/bin/curl -q --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --max-filesize 33554432 \
    "https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.${asset}.tar.gz" \
    --output "${temporary}"
  /bin/mv "${temporary}" "${archive}"
fi
actual_archive="$("${quality_binary}" -mode digest -input "${archive}")"
[[ "${actual_archive}" == "${archive_sha}" ]] || { echo "ShellCheck archive digest mismatch" >&2; exit 2; }
env -u TAR_OPTIONS /usr/bin/tar -xzf "${archive}" -C "${extract_root}"
/usr/bin/install -m 0555 "${extract_root}/shellcheck-v0.11.0/shellcheck" "${fresh_bin}/shellcheck"

"${quality_binary}" -mode verify-tools -root "${repo_root}" -lane "${COH_CI_LANE}" -tool-lock "${lock}" -tool-bin "${fresh_bin}"

original_bin="${tool_parent}/bin"
coh_promote_tool_directory "${fresh_bin}" "${tool_parent}" || { echo "Atomic CI tool promotion failed" >&2; exit 1; }
export GOBIN="${original_bin}"
if ! verify_installed; then
  coh_recover_tool_promotion "${tool_parent}" || true
  echo "Promoted CI tools failed verification; previous tool set restored" >&2
  exit 2
fi
coh_finalize_tool_promotion "${tool_parent}" || { echo "Cannot finalize verified tool promotion" >&2; exit 1; }

echo "Pinned CI tools rebuilt and verified in ${GOBIN}"
