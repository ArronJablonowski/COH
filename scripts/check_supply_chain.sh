#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-supply-chain.XXXXXX")"
cleanup() { /bin/chmod -R u+w "${temporary}" 2>/dev/null || true; /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM
releasegate="${temporary}/releasegate"
target="$("${COH_GO_BIN:?COH_GO_BIN is required}" env GOOS)/$("${COH_GO_BIN}" env GOARCH)"

"${COH_GO_BIN}" build -trimpath -buildvcs=false -ldflags=-buildid= -o "${releasegate}" ./cmd/releasegate
/bin/chmod 0500 "${releasegate}"

build_bundle() {
  local root=$1 bundle
  bundle="${root}/bundle"
  /bin/mkdir -m 0700 "${root}" "${bundle}"
  "${releasegate}" -mode assemble -root "${repo_root}" -bundle "${bundle}" -target "${target}" -go-binary "${COH_GO_BIN}"
  "${releasegate}" -mode verify -root "${repo_root}" -bundle "${bundle}" -target "${target}" -go-binary "${COH_GO_BIN}"
}

build_bundle "${temporary}/first"
build_bundle "${temporary}/second"

first_names="${temporary}/first.names"
second_names="${temporary}/second.names"
(cd "${temporary}/first/bundle" && /usr/bin/find . -maxdepth 1 -type f -print | LC_ALL=C /usr/bin/sort) > "${first_names}"
(cd "${temporary}/second/bundle" && /usr/bin/find . -maxdepth 1 -type f -print | LC_ALL=C /usr/bin/sort) > "${second_names}"
/usr/bin/cmp -s "${first_names}" "${second_names}" || { echo "release bundle file sets differ" >&2; exit 2; }
while IFS= read -r relative; do
  /usr/bin/cmp -s "${temporary}/first/bundle/${relative}" "${temporary}/second/bundle/${relative}" || {
    echo "release bundle is not reproducible: ${relative}" >&2
    exit 2
  }
done < "${first_names}"

manifest="$(/usr/bin/find "${temporary}/first/bundle" -maxdepth 1 -type f -name '*.release.json' -print)"
archive="$(/usr/bin/find "${temporary}/first/bundle" -maxdepth 1 -type f -name '*.tar.gz' -print)"
[[ -n "${manifest}" && -n "${archive}" ]] || { echo "release outputs are incomplete" >&2; exit 2; }
manifest_digest="$("${COH_QUALITYGATE_BIN:?COH_QUALITYGATE_BIN is required}" -mode digest -input "${manifest}")"
archive_digest="$("${COH_QUALITYGATE_BIN}" -mode digest -input "${archive}")"
printf 'supply-chain target=%s manifest_sha256=%s archive_sha256=%s reproducible=true\n' \
  "${target}" "${manifest_digest}" "${archive_digest}"
