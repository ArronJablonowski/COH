#!/bin/bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
helper="${root}/helpers/pysigma"
allow="${helper}/python-dependencies.allow"
snapshot="${root}/docs/evidence/CYB-105-pysigma-vulnerability-snapshot.json"
toolchain="${COH_TOOLCHAIN_ROOT:?COH_TOOLCHAIN_ROOT must name approved external mutable storage}"
python="${toolchain}/python/cpython-3.13.15-macos-aarch64-none/bin/python3"
requirements="${helper}/requirements-osx-arm64.lock"
mode="${1:-gate}"

[[ "${mode}" == gate || "${mode}" == inventory ]] || { echo "Usage: $0 [gate|inventory]" >&2; exit 64; }
for path in "${allow}" "${snapshot}" "${requirements}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || { echo "Missing pySigma supply-chain input: ${path}" >&2; exit 64; }
done
lock_sha="$(/usr/bin/shasum -a 256 "${requirements}" | /usr/bin/awk '{print $1}')"
wheelhouse="${toolchain}/pysigma-helper/wheelhouses/osx-arm64/${lock_sha}"
[[ -f "${wheelhouse}/SHA256SUMS" && -x "${python}" ]] || { echo "Verified pySigma wheelhouse is unavailable" >&2; exit 64; }
(cd "${wheelhouse}" && /usr/bin/shasum -a 256 -c SHA256SUMS >/dev/null)

if /usr/bin/grep -E '^(diskcache|diskcache-stubs)==' "${requirements}" >/dev/null; then
  echo "Vulnerable cache dependency is present in the runtime lock" >&2
  exit 2
fi

"${python}" - "${wheelhouse}" "${allow}" <<'PY'
import email
import hashlib
import pathlib
import re
import sys
import zipfile

wheelhouse, allow_path = map(pathlib.Path, sys.argv[1:])
rules = {}
for number, line in enumerate(allow_path.read_text().splitlines(), 1):
    if not line or line.startswith("#"):
        continue
    values = line.split()
    if len(values) != 5 or values[0] in rules or values[4] not in {"approved", "review-required"}:
        raise SystemExit(f"invalid dependency allowlist line {number}")
    rules[values[0]] = tuple(values[1:])
observed = set()
for wheel in sorted(wheelhouse.glob("*.whl")):
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = email.message_from_bytes(archive.read(metadata_name))
    name = re.sub(r"[-_.]+", "-", metadata["Name"].lower())
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if name not in rules or rules[name][0] != metadata["Version"] or rules[name][2] != digest:
        raise SystemExit(f"unapproved wheel identity: {name}=={metadata['Version']} {digest}")
    observed.add(name)
if observed != set(rules):
    raise SystemExit("wheel inventory does not exactly match the dependency allowlist")
PY

/usr/bin/jq -e --arg digest "sha256:${lock_sha}" '
  .schema_version == "coh.pysigma-vulnerability-snapshot/v1"
  and .issue == "CYB-105"
  and .requirements == ["FR-055","FR-056","SEC-019"]
  and .source == "https://api.osv.dev/v1/querybatch"
  and .ecosystem == "PyPI"
  and .rid == "osx-arm64"
  and .runtime_lock_digest == $digest
  and .package_count == 22
  and .vulnerabilities == []
  and (.excluded_findings | length == 1)
  and .excluded_findings[0].package == "diskcache"
  and (.excluded_findings[0].aliases | contains(["CVE-2025-69872","GHSA-w8v5-vhqr-4h9v","PYSEC-2026-2447"]))
' "${snapshot}" >/dev/null

review_count="$(/usr/bin/awk '$5 == "review-required" {count++} END {print count+0}' "${allow}")"
package_count="$(/usr/bin/awk 'NF && $1 !~ /^#/ {count++} END {print count+0}' "${allow}")"
if [[ "${mode}" == gate && "${review_count}" != 0 ]]; then
  echo "pySigma license review required for ${review_count} dependencies" >&2
  exit 3
fi
echo "pysigma-supply-chain summary: packages=${package_count} vulnerabilities=0 excluded_vulnerable=1 license_reviews=${review_count} mode=${mode}"
