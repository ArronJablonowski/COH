#!/bin/bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
helper_root="${repository_root}/helpers/kusto-language"
toolchain_root="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
dotnet_root="${toolchain_root}/dotnet/10.0.400-osx-arm64"
dotnet="${dotnet_root}/dotnet"
rid="${1:-}"

if [[ ! -x "${dotnet}" ]]; then
  echo "Pinned .NET SDK 10.0.400 is unavailable at ${dotnet}" >&2
  exit 64
fi
if [[ -z "${rid}" ]]; then
  case "$(/usr/bin/uname -sm)" in
    "Darwin arm64") rid="osx-arm64" ;;
    "Linux x86_64") rid="linux-x64" ;;
    "Linux aarch64") rid="linux-arm64" ;;
    *) echo "Unsupported build host; pass osx-arm64, linux-x64, or linux-arm64" >&2; exit 64 ;;
  esac
fi
case "${rid}" in
  osx-arm64|linux-x64|linux-arm64) ;;
  *) echo "Unsupported runtime identifier: ${rid}" >&2; exit 64 ;;
esac

export DOTNET_ROOT="${dotnet_root}"
export DOTNET_CLI_HOME="${toolchain_root}/dotnet/home"
export NUGET_PACKAGES="${toolchain_root}/nuget/packages"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export PATH="${dotnet_root}:/usr/bin:/bin"

mkdir -p "${DOTNET_CLI_HOME}" "${NUGET_PACKAGES}" "${toolchain_root}/kusto-validator/builds"
temporary_root="$(mktemp -d "${toolchain_root}/kusto-validator/builds/build.XXXXXX")"
trap 'rm -rf -- "${temporary_root}"' EXIT
build_properties=(
  "-p:BaseIntermediateOutputPath=${temporary_root}/obj/"
  "-p:BaseOutputPath=${temporary_root}/bin/"
  "-p:MSBuildProjectExtensionsPath=${temporary_root}/obj/"
)

cd "${helper_root}"
"${dotnet}" restore KustoValidator.csproj --configfile NuGet.Config --locked-mode "${build_properties[@]}"

packages=(
  "${NUGET_PACKAGES}/microsoft.azure.kusto.language/12.4.1/microsoft.azure.kusto.language.12.4.1.nupkg"
  "${NUGET_PACKAGES}/microsoft.net.illink.tasks/10.0.11/microsoft.net.illink.tasks.10.0.11.nupkg"
  "${NUGET_PACKAGES}/microsoft.netcore.app.runtime.${rid}/10.0.11/microsoft.netcore.app.runtime.${rid}.10.0.11.nupkg"
  "${NUGET_PACKAGES}/microsoft.aspnetcore.app.runtime.${rid}/10.0.11/microsoft.aspnetcore.app.runtime.${rid}.10.0.11.nupkg"
)
host_package="${NUGET_PACKAGES}/microsoft.netcore.app.host.${rid}/10.0.11/microsoft.netcore.app.host.${rid}.10.0.11.nupkg"
if [[ -f "${host_package}" ]]; then
  packages+=("${host_package}")
fi
for package in "${packages[@]}"; do
  [[ -f "${package}" ]] || { echo "Locked package is unavailable: ${package}" >&2; exit 65; }
  "${dotnet}" nuget verify --all "${package}" >/dev/null
done

"${dotnet}" publish KustoValidator.csproj -c Release -r "${rid}" --no-restore -o "${temporary_root}/publish" "${build_properties[@]}" >/dev/null
artifact="${temporary_root}/publish/coh-kusto-validator"
[[ -f "${artifact}" ]] || { echo "Published helper is unavailable" >&2; exit 66; }
artifact_sha="$(/usr/bin/shasum -a 256 "${artifact}" | /usr/bin/awk '{print $1}')"
closure_sha="$(for package in "${packages[@]}"; do /usr/bin/shasum -a 256 "${package}"; done | /usr/bin/awk '{print $1}' | LC_ALL=C /usr/bin/sort | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
destination="${toolchain_root}/kusto-validator/artifacts/${rid}/${artifact_sha}"
mkdir -p "${destination}"
/usr/bin/install -m 0555 "${artifact}" "${destination}/coh-kusto-validator"

printf '%s\n' \
  "rid=${rid}" \
  "artifact=${destination}/coh-kusto-validator" \
  "artifact_digest=sha256:${artifact_sha}" \
  "package_closure_digest=sha256:${closure_sha}"
