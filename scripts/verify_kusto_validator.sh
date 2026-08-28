#!/bin/bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
toolchain_root="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
rid="${1:-osx-arm64}"
case "$(/usr/bin/uname -sm)" in
  "Darwin arm64") sdk_host="osx-arm64" ;;
  "Linux x86_64") sdk_host="linux-x64" ;;
  "Linux aarch64") sdk_host="linux-arm64" ;;
  *) echo "Unsupported .NET verification host" >&2; exit 64 ;;
esac
dotnet_root="${toolchain_root}/dotnet/10.0.400-${sdk_host}"
dotnet="${dotnet_root}/dotnet"
export DOTNET_ROOT="${dotnet_root}"
export DOTNET_CLI_HOME="${toolchain_root}/dotnet/home"
export NUGET_PACKAGES="${toolchain_root}/nuget/packages"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export PATH="${dotnet_root}:/usr/bin:/bin"
first_report="$("${repository_root}/scripts/build_kusto_validator.sh" "${rid}")"
second_report="$("${repository_root}/scripts/build_kusto_validator.sh" "${rid}")"
first_digest="$(printf '%s\n' "${first_report}" | /usr/bin/awk -F= '$1 == "artifact_digest" {print $2}')"
second_digest="$(printf '%s\n' "${second_report}" | /usr/bin/awk -F= '$1 == "artifact_digest" {print $2}')"
artifact="$(printf '%s\n' "${first_report}" | /usr/bin/awk -F= '$1 == "artifact" {sub(/^artifact=/, ""); print}')"
if [[ -z "${first_digest}" || "${first_digest}" != "${second_digest}" ]]; then
  echo "Kusto validator build is not reproducible" >&2
  exit 67
fi

test_root="$(mktemp -d "${toolchain_root}/kusto-validator/builds/test.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT
test_properties=(
  "-p:BaseIntermediateOutputPath=${test_root}/obj/"
  "-p:BaseOutputPath=${test_root}/bin/"
  "-p:MSBuildProjectExtensionsPath=${test_root}/obj/"
)
"${dotnet}" restore "${repository_root}/tests/kusto-language/KustoValidator.Tests.csproj" \
  --configfile "${repository_root}/helpers/kusto-language/NuGet.Config" --locked-mode "${test_properties[@]}" >/dev/null
"${dotnet}" run --project "${repository_root}/tests/kusto-language/KustoValidator.Tests.csproj" --no-restore \
  "${test_properties[@]}" -- "${repository_root}/contracts/kusto-validator/v1/fixtures/helper-request.json"

request="$(tr -d '\n' < "${repository_root}/contracts/kusto-validator/v1/fixtures/helper-request.json")"
transport="$(/usr/bin/printf '%s' "${request}" | /usr/bin/python3 -c 'import json,sys; print(json.dumps({"request_chunk_00":sys.stdin.read()}, separators=(",", ":")))')"
response="$(/usr/bin/printf '%s' "${transport}" | "${artifact}")"
/usr/bin/printf '%s' "${response}" | /usr/bin/python3 -c '
import json,sys
value=json.load(sys.stdin)
assert value["schema_version"] == "coh.kusto-helper-response/v1"
assert value["outcome"] == "accepted"
assert value["reason_codes"] == []
assert value["canonical_kql"] == "SecurityEvent | where EventID == 4624 | project TimeGenerated, Computer, EventID | take 500"
assert value["terminal_take"] == 500
assert value["semantic"]["tables"] == ["SecurityEvent"]
'

go_bin="${COH_GO_BIN:-${toolchain_root}/go1.26.7/bin/go}"
[[ -x "${go_bin}" ]] || { echo "Pinned Go 1.26.7 is unavailable at ${go_bin}" >&2; exit 68; }
export GOCACHE="${toolchain_root}/cache/go1.26.7/build"
export GOMODCACHE="${toolchain_root}/cache/go1.26.7/modules"
export GOPATH="${toolchain_root}/gopath/go1.26.7"
export GOTMPDIR="${toolchain_root}/tmp/go1.26.7"
export GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off
mkdir -p "${GOCACHE}" "${GOMODCACHE}" "${GOPATH}" "${GOTMPDIR}"
COH_KUSTO_HELPER="${artifact}" "${go_bin}" test -run '^TestPinnedHelperProcessContract$' \
  "${repository_root}/internal/connector/kustovalidator"

printf '%s\n' "verified ${first_digest} (${rid}); signatures, reproducibility, semantics, AST bound, and protocol passed"
