#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "${root}/internal/broker/nativeexecutor" \
  "${root}/cmd/coh-native-limit/main.go" \
  "${root}/docs/design/low-risk-native-executor.md"; do
  [[ -e "${path}" ]] || {
    echo "error: native-executor input is missing: ${path}" >&2
    exit 2
  }
done

if /usr/bin/grep -R -E '(/bin/sh|bash -c|docker\.sock|http\.Client)' \
  "${root}/internal/broker/nativeexecutor" "${root}/cmd/coh-native-limit" \
  --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: forbidden generic execution surface found" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-native-executor.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/broker/nativeexecutor | tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/broker/nativeexecutor | tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/broker/nativeexecutor ./cmd/coh-native-limit

GOOS=linux GOARCH=amd64 "${COH_GO_ROOT}/bin/go" test -c \
  -o "${artifact_dir}/nativeexecutor-linux.test" ./internal/broker/nativeexecutor
GOOS=linux GOARCH=amd64 "${COH_GO_ROOT}/bin/go" build -trimpath \
  -o "${artifact_dir}/coh-native-limit-linux" ./cmd/coh-native-limit
GOOS=windows GOARCH=amd64 "${COH_GO_ROOT}/bin/go" test -c \
  -o "${artifact_dir}/nativeexecutor-windows.test.exe" ./internal/broker/nativeexecutor

"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"

echo "native-executor summary: tiers=T0/T1 isolation=native_restricted authorization=fresh registry=signed argv=fixed stdin=typed environment=clean network=none artifact=staged+verified resources=bounded cancellation=process-group provenance=complete replay=exact docker=absent failures=0"
