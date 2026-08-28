#!/bin/bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
helper="${root}/helpers/pysigma"
package="${root}/internal/connector/sigmacompiler"
toolchain="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
python="${toolchain}/python/cpython-3.13.15-macos-aarch64-none/bin/python3"
uv="${toolchain}/uv/0.12.7/uv"

for path in "${helper}/pyproject.toml" "${helper}/uv.lock" "${helper}/requirements-osx-arm64.lock" \
  "${helper}/entrypoint.py" "${helper}/src/coh_pysigma_helper/__main__.py" \
  "${helper}/src/coh_pysigma_helper/protocol.py" "${helper}/src/coh_pysigma_helper/yaml_profile.py" \
  "${helper}/src/coh_pysigma_helper/compiler.py" "${root}/tests/pysigma-helper/test_helper.py" \
  "${package}/helper_process_integration_test.go"; do
  [[ -f "${path}" && ! -L "${path}" ]] || { echo "Missing or linked pySigma helper input: ${path}" >&2; exit 2; }
done
[[ -x "${python}" && "$("${python}" --version)" == "Python 3.13.15" ]] || { echo "CPython identity denied" >&2; exit 64; }
[[ -x "${uv}" && "$("${uv}" --version)" == uv\ 0.12.7* ]] || { echo "uv identity denied" >&2; exit 64; }

for binding in 'pysigma==1.5.0' 'pysigma-backend-elasticsearch==2.1.0' \
  'pysigma-backend-kusto==1.0.1' 'pysigma-backend-splunk==2.1.0' 'pyinstaller==6.22.2'; do
  /usr/bin/grep -Fq "${binding}" "${helper}/pyproject.toml"
  /usr/bin/grep -Fq "${binding}" "${helper}/requirements-osx-arm64.lock"
done
if /usr/bin/grep -R -n -E '(git\+|file://|https?://.*@|collect_errors=True|autodiscover|ProcessingPipelineResolver|load_ruleset|from_yaml)' \
  "${helper}/src" "${helper}/requirements-osx-arm64.lock" >/dev/null; then
  echo "Helper contains an ambient, floating, or skip-unsupported surface" >&2
  exit 2
fi

"${uv}" lock --offline --check --python "${python}" --directory "${helper}"
lock_sha="$(/usr/bin/shasum -a 256 "${helper}/requirements-osx-arm64.lock" | /usr/bin/awk '{print $1}')"
wheelhouse="${toolchain}/pysigma-helper/wheelhouses/osx-arm64/${lock_sha}"
test_root="$(/usr/bin/mktemp -d "${toolchain}/pysigma-helper/test.XXXXXX")"
invalid_output=""
cleanup() {
  /bin/rm -rf -- "${test_root}"
  [[ -z "${invalid_output}" ]] || /bin/rm -f -- "${invalid_output}"
}
trap cleanup EXIT HUP INT TERM
"${python}" -m venv "${test_root}/venv"
PIP_NO_INDEX=1 "${test_root}/venv/bin/python" -m pip install --no-index --find-links "${wheelhouse}" \
  --no-deps --require-hashes -r "${helper}/requirements-osx-arm64.lock" >/dev/null
PYTHONPATH="${helper}/src" "${test_root}/venv/bin/python" -m unittest discover \
  -s "${root}/tests/pysigma-helper" -p 'test_*.py'

first_report="$("${root}/scripts/build_pysigma_helper.sh")"
second_report="$("${root}/scripts/build_pysigma_helper.sh")"
first_digest="$(/usr/bin/printf '%s\n' "${first_report}" | /usr/bin/awk -F= '$1 == "artifact_digest" {print $2}')"
second_digest="$(/usr/bin/printf '%s\n' "${second_report}" | /usr/bin/awk -F= '$1 == "artifact_digest" {print $2}')"
artifact="$(/usr/bin/printf '%s\n' "${first_report}" | /usr/bin/awk -F= '$1 == "artifact" {sub(/^artifact=/, ""); print}')"
[[ -n "${first_digest}" && "${first_digest}" == "${second_digest}" && -x "${artifact}" ]] || {
  echo "pySigma helper reproducibility denied" >&2; exit 67;
}

response="$("${artifact}" < "${root}/contracts/pysigma-helper/v1/fixtures/compile-request.json")"
/usr/bin/printf '%s' "${response}" | /usr/bin/jq -e '
  .schema_version == "coh.pysigma-helper-response/v1"
  and .outcome == "compiled_untrusted"
  and .reason_codes == [] and .diagnostics == []
  and (.native_query | contains("logs-endpoint-events-process-default"))
' >/dev/null

invalid_output="$(/usr/bin/mktemp "${toolchain}/pysigma-helper/invalid.XXXXXX")"
set +e
"${artifact}" forbidden-argument </dev/null >"${invalid_output}" 2>/dev/null
invalid_status=$?
set -e
[[ "${invalid_status}" == 2 ]] || { echo "Argument surface was not denied" >&2; exit 68; }
/usr/bin/jq -e '.outcome == "denied" and .reason_codes == ["request_denied"]' "${invalid_output}" >/dev/null

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "${root}")}
export COH_CI_LANE=${COH_CI_LANE:-baseline}
# shellcheck source=lib/ci_env.sh
source "${root}/scripts/lib/ci_env.sh"
"${root}/scripts/check_pysigma_supply_chain.sh" inventory
COH_PYSIGMA_HELPER="${artifact}" "${COH_GO_ROOT}/bin/go" test -count=1 -run TestPinnedHelperProcessContract "${package}"
"${root}/scripts/verify_pysigma_contract.sh"
"${root}/scripts/check_go_architecture.sh"
"${root}/scripts/check_file_sizes.sh"
"${root}/scripts/check_markdown_links.sh" "${helper}/README.md" "${root}/docs/design/signed-pysigma-helper.md"
/usr/bin/git diff --check

printf 'pysigma-helper summary: issue=CYB-105 rid=osx-arm64 artifact=%s runtime=3.13.15 pyinstaller=6.22.2 restore=offline+hashed reproducible=true protocol=go-verified network=closed-in-process+native-sandbox credentials=none output=compiled-untrusted failures=0\n' "${first_digest}"
