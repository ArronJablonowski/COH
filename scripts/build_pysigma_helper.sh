#!/bin/bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
helper="${root}/helpers/pysigma"
toolchain="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
python="${toolchain}/python/cpython-3.13.15-macos-aarch64-none/bin/python3"
requirements="${helper}/requirements-osx-arm64.lock"

case "$(/usr/bin/uname -sm)" in
  "Darwin arm64") rid=osx-arm64 ;;
  *) echo "Build the helper on a qualified native RID host" >&2; exit 64 ;;
esac
[[ -x "${python}" && "$("${python}" --version)" == "Python 3.13.15" ]] || {
  echo "Pinned CPython 3.13.15 is unavailable" >&2; exit 64;
}
lock_sha="$(/usr/bin/shasum -a 256 "${requirements}" | /usr/bin/awk '{print $1}')"
wheelhouse="${toolchain}/pysigma-helper/wheelhouses/${rid}/${lock_sha}"
[[ -f "${wheelhouse}/SHA256SUMS" ]] || { echo "Fetch and verify the locked wheelhouse first" >&2; exit 65; }
(cd "${wheelhouse}" && /usr/bin/shasum -a 256 -c SHA256SUMS >/dev/null)

/bin/mkdir -p "${toolchain}/pysigma-helper/builds" "${toolchain}/pysigma-helper/artifacts/${rid}"
temporary="$(/usr/bin/mktemp -d "${toolchain}/pysigma-helper/builds/${rid}.XXXXXX")"
trap '/bin/rm -rf -- "${temporary}"' EXIT HUP INT TERM
"${python}" -m venv "${temporary}/venv"
PIP_NO_INDEX=1 "${temporary}/venv/bin/python" -m pip install \
  --no-deps --no-index --find-links "${wheelhouse}" --require-hashes -r "${requirements}" >/dev/null
[[ "$("${temporary}/venv/bin/python" -c 'import PyInstaller; print(PyInstaller.__version__)')" == "6.22.2" ]] || {
  echo "PyInstaller identity denied" >&2; exit 66;
}

export LC_ALL=C TZ=UTC PYTHONHASHSEED=0 SOURCE_DATE_EPOCH=1787890000
export PYINSTALLER_CONFIG_DIR="${temporary}/pyinstaller-config"
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
"${temporary}/venv/bin/python" -m PyInstaller --noconfirm --clean --onefile \
  --name coh-pysigma-helper --distpath "${temporary}/dist" --workpath "${temporary}/work" \
  --specpath "${temporary}/spec" --paths "${helper}/src" \
  --hidden-import sigma.backends.elasticsearch.elasticsearch_esql \
  --hidden-import sigma.backends.splunk.splunk --hidden-import sigma.backends.kusto.kusto \
  --exclude-module sigma.plugins --exclude-module sigma.processing.resolver \
  --exclude-module sigma.data.mitre_attack --exclude-module sigma.data.mitre_d3fend \
  --exclude-module diskcache \
  "${helper}/entrypoint.py" >/dev/null

artifact="${temporary}/dist/coh-pysigma-helper"
[[ -x "${artifact}" ]] || { echo "PyInstaller artifact is unavailable" >&2; exit 67; }
module_toc="${temporary}/work/coh-pysigma-helper/PYZ-00.toc"
for required in sigma.backends.elasticsearch.elasticsearch_esql sigma.backends.splunk.splunk sigma.backends.kusto.kusto; do
  /usr/bin/grep -Fq "'${required}'" "${module_toc}" || { echo "Required backend module is absent: ${required}" >&2; exit 68; }
done
forbidden_modules="$(/usr/bin/grep -Eo "'sigma[.]plugins[^']*'|'sigma[.]processing[.]resolver[^']*'|'sigma[.]data[.]mitre_[^']*'|'diskcache[^']*'" "${module_toc}" | LC_ALL=C /usr/bin/sort -u || true)"
if [[ -n "${forbidden_modules}" ]]; then
  echo "Artifact contains a forbidden ambient module: ${forbidden_modules}" >&2
  exit 68
fi
artifact_sha="$(/usr/bin/shasum -a 256 "${artifact}" | /usr/bin/awk '{print $1}')"
closure_sha="$(/usr/bin/shasum -a 256 "${wheelhouse}/SHA256SUMS" | /usr/bin/awk '{print $1}')"
runtime_sha="$(/usr/bin/shasum -a 256 "${python}" | /usr/bin/awk '{print $1}')"
destination="${toolchain}/pysigma-helper/artifacts/${rid}/${artifact_sha}"
/bin/mkdir -p "${destination}"
/usr/bin/install -m 0555 "${artifact}" "${destination}/coh-pysigma-helper"
printf '%s\n' \
  "rid=${rid}" "artifact=${destination}/coh-pysigma-helper" \
  "artifact_digest=sha256:${artifact_sha}" "package_closure_digest=sha256:${closure_sha}" \
  "runtime_digest=sha256:${runtime_sha}" "lock_digest=sha256:${lock_sha}"
