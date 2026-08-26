#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "${root}/internal/broker/ociexecutor" \
  "${root}/docs/design/optional-oci-executor.md"; do
  [[ -e "${path}" ]] || {
    echo "error: OCI-executor input is missing: ${path}" >&2
    exit 2
  }
done

if /usr/bin/grep -R -E '(/bin/sh|bash -c|docker\.sock|http\.Client|--privileged|--volume|--mount|--device)' \
  "${root}/internal/broker/ociexecutor" --include='*.go' --exclude='*_test.go' >/dev/null; then
  echo "error: forbidden generic or host-expanding OCI surface found" >&2
  exit 2
fi

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "${root}")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "${root}/scripts/lib/go_ssd_env.sh"

artifact_dir=$(/usr/bin/mktemp -d "${GOTMPDIR}/coh-oci-executor.XXXXXX")
cleanup() { /bin/rm -rf -- "${artifact_dir}"; }
trap cleanup EXIT HUP INT TERM

cd "${root}"
"${COH_GO_ROOT}/bin/go" test -count=1 ./internal/broker/ociexecutor | tee "${artifact_dir}/unit.log"
"${COH_GO_ROOT}/bin/go" test -count=3 ./internal/broker/ociexecutor | tee "${artifact_dir}/repeat.log"
"${COH_GO_ROOT}/bin/go" test -count=1 -race ./internal/broker/ociexecutor | tee "${artifact_dir}/race.log"
"${COH_GO_ROOT}/bin/go" vet ./internal/broker/ociexecutor/...

GOOS=linux GOARCH=amd64 "${COH_GO_ROOT}/bin/go" test -c \
  -o "${artifact_dir}/ociexecutor-linux.test" ./internal/broker/ociexecutor
GOOS=windows GOARCH=amd64 "${COH_GO_ROOT}/bin/go" test -c \
  -o "${artifact_dir}/ociexecutor-windows.test.exe" ./internal/broker/ociexecutor

"${root}/scripts/check_go_architecture.sh" | tee "${artifact_dir}/architecture.log"
"${root}/scripts/check_file_sizes.sh"
/usr/bin/git diff --check

runtime_presence=absent
if command -v docker >/dev/null 2>&1; then
  runtime_presence=present-unqualified
fi

echo "oci-executor summary: tiers=T0-T3 isolation=oci_sandbox authorization=fresh registry=signed image=digest-only pull=never user=non-root rootfs=read-only capabilities=dropped mounts=tmpfs-bounded socket=not-mounted network=broker-attested health=fixed resources=bounded cancellation=kill+remove provenance=complete replay=exact fixture=integrated runtime=${runtime_presence} failures=0"
