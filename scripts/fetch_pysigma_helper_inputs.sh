#!/bin/bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
helper="${root}/helpers/pysigma"
toolchain="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
python="${toolchain}/python/cpython-3.13.15-macos-aarch64-none/bin/python3"
requirements="${helper}/requirements-osx-arm64.lock"

case "$(/usr/bin/uname -sm)" in
  "Darwin arm64") rid=osx-arm64 ;;
  *) echo "Run the matching RID input fetch on its native build host" >&2; exit 64 ;;
esac
[[ -x "${python}" ]] || { echo "Pinned CPython 3.13.15 is unavailable" >&2; exit 64; }
[[ "$("${python}" --version)" == "Python 3.13.15" ]] || { echo "Python identity denied" >&2; exit 65; }

lock_sha="$(/usr/bin/shasum -a 256 "${requirements}" | /usr/bin/awk '{print $1}')"
destination="${toolchain}/pysigma-helper/wheelhouses/${rid}/${lock_sha}"
if [[ -f "${destination}/SHA256SUMS" ]]; then
  (cd "${destination}" && /usr/bin/shasum -a 256 -c SHA256SUMS >/dev/null)
  printf 'verified existing wheelhouse=%s\n' "${destination}"
  exit 0
fi

/bin/mkdir -p "${toolchain}/pysigma-helper/fetch" "$(/usr/bin/dirname "${destination}")"
temporary="$(/usr/bin/mktemp -d "${toolchain}/pysigma-helper/fetch/${rid}.XXXXXX")"
trap '/bin/rm -rf -- "${temporary}"' EXIT HUP INT TERM
"${python}" -m venv "${temporary}/venv"
"${temporary}/venv/bin/python" -m pip download \
  --require-hashes --only-binary=:all: --dest "${temporary}/wheelhouse" -r "${requirements}"
(cd "${temporary}/wheelhouse" && /usr/bin/find . -type f -name '*.whl' -print0 | LC_ALL=C /usr/bin/sort -z | \
  /usr/bin/xargs -0 /usr/bin/shasum -a 256 > SHA256SUMS)
/bin/mv "${temporary}/wheelhouse" "${destination}"
printf 'wheelhouse=%s\nlock_digest=sha256:%s\n' "${destination}" "${lock_sha}"
