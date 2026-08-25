#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export COH_NATIVE_STORAGE_ROOT="${COH_NATIVE_STORAGE_ROOT:-$(dirname "${repo_root}")}" 
export COH_TOOLCHAIN_ROOT="${COH_TOOLCHAIN_ROOT:-$(dirname "${repo_root}")/COH-toolchains}"

artifact_root="${COH_E03_ARTIFACT_ROOT:-${COH_TOOLCHAIN_ROOT}/ci-artifacts/CYB-7}"
mkdir -p "${artifact_root}"
run_directory="$(mktemp -d "${artifact_root}/run.XXXXXX")"
export COH_REPLAY_EVAL_ARTIFACT_ROOT="${run_directory}/replay"

run_gate() {
  local name="$1"
  local script="$2"
  echo "E03 gate start: ${name}"
  "${repo_root}/${script}" 2>&1 | /usr/bin/tee "${run_directory}/${name}.log"
  echo "E03 gate passed: ${name}"
}

run_gate domain-contract scripts/verify_domain_contract.sh
run_gate storage-contract scripts/verify_storage_contract.sh
run_gate sqlite-store scripts/verify_sqlite_store.sh
run_gate postgres-store scripts/verify_postgres_store.sh
run_gate temporal-adapter scripts/verify_temporal_adapter.sh
run_gate replay-faults scripts/verify_replay_faults.sh

commit="$(git -C "${repo_root}" rev-parse HEAD)"
if [[ -n "$(git -C "${repo_root}" status --short)" ]]; then
  worktree_clean=false
else
  worktree_clean=true
fi

cat >"${run_directory}/integration-result.json" <<EOF
{
  "schema": "coh.e03-integration-result/v1",
  "issue": "CYB-7",
  "commit": "${commit}",
  "worktree_clean": ${worktree_clean},
  "children_done": 6,
  "children_total": 6,
  "domain_conformance": "passed",
  "sqlite_conformance": "passed",
  "postgresql_conformance": "passed",
  "temporal_replay": "passed",
  "persisted_boundary_crash_injection": "passed",
  "duplicate_confirmed_effects": 0,
  "migration_apply_rollback": "passed",
  "mixed_version_rejection": "passed",
  "result": "passed"
}
EOF

(
  cd "${run_directory}"
  find . -type f ! -name all-artifacts.sha256 -print0 |
    LC_ALL=C sort -z |
    xargs -0 /usr/bin/shasum -a 256 >all-artifacts.sha256
)

echo "CYB-7 integration evidence: ${run_directory}"
echo "E03 integration verification: children=6/6 conformance=passed replay=passed crash-faults=passed mixed-version-rejection=passed failures=0"
