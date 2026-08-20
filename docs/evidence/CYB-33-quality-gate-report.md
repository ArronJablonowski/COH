# CYB-33 CI quality-gate verification report

| Field | Value |
|---|---|
| Issue | COH-E02-02 / CYB-33 |
| Requirements | NFR-027, EVAL-029 |
| Snapshot date | 2026-08-19 |
| Module | `github.com/ArronJablonowski/COH` |
| Baseline | Go 1.26.7, required |
| Qualification | Go 1.27.0, required-to-pass and non-promoting |
| Native storage | `/Volumes/Untitled/Codex/toolchains` |
| Docker dependency | None |
| Hosted evidence | Not yet run; requires the first pushed commit |

## Verdict scope

The local implementation and pre-document validation runs satisfy the CYB-33
contract. The current source must still complete the final frozen-tree baseline
and qualification runs described below. No hosted GitHub Actions run is claimed
before the repository's first push.

`quality_gate_promotable` is a local quality-gate field, not a release decision.
It can be true only for a clean committed source state in the required baseline
lane after final evidence publication. It never means product GA readiness,
human approval, CYB-37 completion, M9 completion, or authority to release.
The current repository is unborn and modified, so the value is false.

## Two-plane evidence model

The gate hashes every repository evidence document as source input. Embedding a
final report or publication digest back into this document would change the
source digest and therefore create an impossible self-reference. CYB-33 uses
two evidence planes instead of weakening source coverage:

1. This repository report freezes the contract, static input digests,
   verification commands, pre-document evidence, expected outputs, negative
   matrix, and external locator procedure.
2. After this file and
   [the CYB-33 checksum ledger](CYB-33-artifacts.sha256) are frozen, each exact final
   lane digest lives in the content-addressed, manifest-verified external
   `run.*.public/publication-manifest.json`. After the first push, the GitHub
   Actions run URL and downloaded artifact become the hosted locator. The same
   verified marker is attached to Linear without editing this source document.

The final public marker is authoritative only with its exact six-file sibling
set. Recipients verify a downloaded bundle with:

```sh
qualitygate -mode verify-publication -artifact-dir /absolute/path/to/run.public
```

The verifier denies a missing, extra, reordered, one-byte changed, malformed,
or report-contradicting bundle.

## Frozen static inputs

These SHA-256 values do not contain generated lane results and therefore do not
participate in a digest cycle.

| Input | SHA-256 |
|---|---|
| `ci/quality-policy.json` | `6379d35e9c05942a4f0b28e5cf7fc6adb074b363ddfa17f73e5ef6c2c47a6152` |
| `ci/tools.lock.json` | `9309f0f9e1196daa704e7601850756871f3fbf2c6db56eb3f6b96b00169355af` |
| `.github/workflows/quality.yml` | `8f20736011aa5724835459b24bbc02fe626e0859d17e93773011c05e1d23515a` |
| `ci/govulndb.lock.json` | `ff8f308f8a6a8326bd32fba784030df8282cbe27a185efe65db07e3785663726` |
| `ci/licenses.allow` | `531d4590ceb9879fc803f1138852e5b4f17c792533764d1b462e57f7bbd4a5cc` |
| `ci/dependencies.allow` | `a6c1d4391b1ac0332886cf904b9ed61a3ad361cb22502e1e29a0cbb7a6d006b7` |
| `ci/fuzz-targets.txt` | `bd07b718335ca0f953f8ccec0909a15553905e74eb6d9357ffca9cef9fbcd228` |
| Vendored Go vulnerability DB ZIP | `6956c9eda20845fc540d08c38e22129b32effad51375ad3d6374fe1bed6d38cc` |
| Vulnerability DB tree manifest | `a95e1ef286e8f04c1b14f899bc14b99ce2b357231e1abb2aae786ec168a5b75d` |
| Vulnerability DB modified time | `2026-08-19T17:06:06Z` |
| Offline-pack attribution notice | `34b256abd95789fb876fae30edea38614952858e554f01764d1485ea9bc37603` |

The ZIP contains 4,294 files and 6,403,063 uncompressed bytes. Public database
evidence contains its content identity and modified time, not an absolute SSD
path. The raw govulncheck SARIF remains private.

## Pre-document local validation

The following runs passed before the final security remediation and evidence
documents were added. They are historical proof of the lane mechanism, not
evidence for the current source. Their shared source digest was
`c6da51759a58e982db8786f03d98c6a6ef04689dbc34a498644d099a358de059`
over 122 files.

| Artifact | Baseline | Go 1.27 qualification |
|---|---|---|
| External directory | `baseline/run.yayDtP.public` | `go1.27/run.fRF1Jj.public` |
| Quality report file SHA-256 | `ceeaf97b7b481eab3290eb398d1f6bf4bbd89f7761e36e97367cfd5c08f44a88` | `13906b7a8fe97c39d017064ea187590bbf762441fdf04c016e59d36c6fef0804` |
| Report self-digest | `0bd9d55b4b6b68409d1670a5d3acbc010b76d4e0116550424b4ce3c6a0612643` | `7107dac894c7816be2abcd1113966040fd492edb44a273eee917a325c2e6cc11` |
| SBOM SHA-256 | `bcb0d6ca03e3b43b07f17176adbfbc68d52b47d25d9cb7a5a6b9cfc726d93c45` | `bcb0d6ca03e3b43b07f17176adbfbc68d52b47d25d9cb7a5a6b9cfc726d93c45` |
| Internal provenance SHA-256 | `f73218886f7c8ec56a301b0bbc4c0b3d8a988efdc95afae27cfc358269663142` | `4110e2d3347c0b317e650a4597d7db17bd20e6f685c1bfa86b54e15c8f34c94c` |
| DB verification SHA-256 | `dbb84ef00be0a82c570340e975b06e13fa39d8d80692d96b59a38859b3eaa969` | `dbb84ef00be0a82c570340e975b06e13fa39d8d80692d96b59a38859b3eaa969` |
| Publication marker SHA-256 | `032e978de008f639cf8f74f84dbaef32ba338a223116dd14447f55e8fe289298` | `76adaf9534f1bed603140898538f657e7499c7b848e7bb67fd1a7cda87f84b94` |

These older reports used the superseded `release_eligible` field and cannot be
substituted for final evidence under the renamed v1 contract.

## Mandatory negative matrix

| Threat or failure | Expected result | Automated evidence |
|---|---|---|
| Unknown lane, mode, stage, path, or weakened policy | `invalid_input` or `denied` | Go policy/CLI and shell contract tests |
| Dead-branch, shadowed, nested, late, duplicate, unlisted, or zero fuzz seed targets | Denied | AST manifest tests and actual `go test -json` callback proof |
| Executor returns success after deadline | Timeout/canceled | Runner fake-executor regression |
| Cancellation before public rename | No marker or public directory | Publication linearization tests |
| Cancellation after committed rename | Verified success remains committed | Publication linearization tests |
| Stage denial, timeout, cancellation, or recovery | Typed report and private failure manifest | Runner, artifact, and finalization tests |
| Stage failure plus source drift | Primary failure preserved; secondary verification recorded | Dual-failure report regression |
| Worktree, evidence, or removed-history synthetic secret | Exit 2; no plaintext in output/metadata | Mandatory Gitleaks negative suite |
| Shallow, partial/promisor, replace-ref, grafted, or missing Git history | Denied before history acceptance | Secret-history contract suite |
| Repository `core.fsmonitor` or hooks | Never executed | Snapshot and history marker regressions |
| Mutable cache/tool/artifact symlink escape | Denied before outside write | Native/hosted storage tests and Go executor tests |
| Absent, symlinked, stale, or root-device macOS volume | Denied before descendant creation | Mount fact decision tests and live mount preflight |
| Unit, vet, Staticcheck, dependency, or workflow finding | Exit 2 denial | Generated external fixtures and fixed status mapper |
| Malformed/duplicate/extra/forbidden license or digest drift | Invalid/denied | Mandatory license negative suite |
| Module allowlist/tidy/integrity drift | Denied | Dependency helper and generated module fixtures |
| Tool source sum, origin, route, archive, binary, extra entry, or mid-run drift | Denied | Tool-lock, whole-file, and pre/post-stage tests |
| Interrupted or concurrent tool promotion | Rollback or lock denial; no partial pass | Mandatory promotion recovery suite |
| ZIP traversal, absolute/backslash path, symlink, duplicate, expansion, CRC, truncation, missing index | Denied | Vulnerability archive adversarial suite |
| Duplicate/incomplete SARIF metadata or any vulnerability result | Denied | Strict SARIF tests |
| Missing, extra, changed, or report-contradicting public artifact | Denied | Publication verifier tests |
| Stale run directory or output collision | Denied | CLI output/freshness tests |

## Local verification commands

Every command uses mutable state under the external SSD and disables Go
telemetry. The final frozen-tree sequence is:

```sh
env -u BASH_ENV -u ENV /bin/bash scripts/run_ci_quality.sh baseline
env -u BASH_ENV -u ENV /bin/bash scripts/run_ci_quality.sh go1.27
```

The authoritative scripts internally run formatting, workflow syntax/policy,
secrets, architecture, contract negatives, vet, static analysis, unit, race,
fuzz seeds, licenses, dependencies, SBOM, evidence scanning, and provenance.
Additional review commands are:

```sh
env -u BASH_ENV -u ENV /bin/bash -c '
  source scripts/lib/ci_env.sh
  "$COH_GO_BIN" test -count=1 ./...
  "$COH_GO_BIN" test -count=1 -race ./...
  "$COH_GO_BIN" vet ./...
  "$GOBIN/staticcheck" -checks=all -go=1.26 -tests=true ./...
  /bin/bash scripts/check_workflow_policy.sh
  /bin/bash scripts/check_file_sizes.sh
'
```

Go 1.27 uses its own exact toolchain/cache path and omits only Staticcheck under
the locked qualification rule. It still runs every other stage, including unit
and race tests.

## Acceptance trace

| CYB-33 acceptance area | Evidence | State before final frozen runs |
|---|---|---|
| Formatting, vet, static, unit, race, fuzz-seed, architecture | Fixed stage graph and local targeted/full checks | Implemented; final rerun pending |
| Secret, license, dependency checks | Locked policies plus mandatory adversarial fixtures | Implemented; final rerun pending |
| Supported Go versions and qualification semantics | Exact lane contract; Go 1.27 non-promoting and required-to-pass | Implemented; final rerun pending |
| Success, invalid, denial, timeout, cancellation, recovery | Typed exits, reports, failure/public manifests, negative matrix | Implemented; final rerun pending |
| Deterministic machine-readable evidence and provenance | Strict self-digests, exact sets, atomic marker, external final locator | Implemented; final rerun pending |
| SBOM and provenance checks | CycloneDX 1.6 and COH-owned internal predicate | Implemented; signing deferred |
| Native storage and no Docker dependency | Mounted external SSD contract and hosted RUNNER_TEMP contract | Implemented locally |
| Hosted clean-commit run | Pinned GitHub workflow | Pending first commit/push |

## Security, data, migration, and documentation impact

- Security: default-deny stage routing, source/tool re-verification, secret-safe
  failure metadata, full Git history checks, and atomic public evidence are new.
- Data classification: public artifacts contain source/tool/content digests and
  quality metadata. Raw command output and raw SARIF are private and may contain
  sensitive paths or findings.
- Migration: this is the initial `coh.ci-quality/v1` contract. No persisted
  production data migration is introduced. Future schema changes require an
  explicit versioned reader and compatibility decision.
- Documentation: the design contract, this report, README link, and deterministic
  checksum ledger are canonical CYB-33 artifacts.
- Dependencies: production Go code remains standard-library-only. External CI
  tools and the vulnerability snapshot are pinned inputs, not runtime product
  dependencies.

## Explicit limitations and deferrals

- No hosted run is claimed until the initial commit is pushed and GitHub Actions
  completes both lanes.
- Native Go 1.26.7 and 1.27.0 executables are version-checked host inputs, not
  independently attested compiler distributions.
- The process runner reaps one process group; it does not contain a descendant
  that intentionally creates a new session.
- Environment and file controls are not a hostile same-UID sandbox and do not
  provide kernel-enforced network isolation.
- The COH provenance object is unsigned and is not SLSA or in-toto provenance.
- Signed release SBOMs, provenance, compiler/archive trust, and release signing
  belong to CYB-37. Full platform/release assurance belongs to later milestones.
- Docker remains optional and is not used by this quality contract.
