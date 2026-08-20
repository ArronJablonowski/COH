# CI quality contract v1

Status: implemented locally for COH-E02-02 / CYB-33 and extended by
COH-E02-03 / CYB-38 on 2026-08-20.

Requirements: NFR-027 and EVAL-029.

## Purpose and authority

`cmd/qualitygate` is the provider-neutral entrypoint for the COH quality
contract. The same binary and stage graph run natively and in GitHub Actions.
Docker is neither detected nor required.

The gate decides only whether one source state satisfies the CYB-33 quality
contract. `quality_gate_promotable=true` has a deliberately narrow meaning: a
clean, committed source state passed the required Go 1.26.7 lane. It is not a
release authorization, GA readiness signal, security approval, or evidence
that CYB-37 or M9 gates passed. Go 1.27 is required-to-pass but is always
non-promoting while it remains a qualification lane.

The model, repository code under test, and tool output are not authorization
boundaries. The quality runner admits only a closed stage identifier and
invokes `/bin/bash scripts/ci_stage.sh <stage>` with a minimal environment.

## Locked lanes

| Lane | Exact compiler | Enforcement | Staticcheck | Promotability |
|---|---:|---|---|---|
| `baseline` | Go 1.26.7 | Required | Staticcheck 2026.1 / v0.7.0 | Eligible only for clean committed source after every gate passes |
| `go1.27` | Go 1.27.0 | Required-to-pass qualification | Deliberately skipped until qualified | Always false |

The runtime compiler version must equal the lane version exactly. The gate
does not accept a newer patch version as equivalent.

## Fixed stage graph

Stages run in this exact order. Unknown, omitted, reordered, duplicated, or
retimed stages are denied by `ci/quality-policy.json` and its strict reader.
The qualitygate default overall deadline is 30 minutes. GitHub applies a
45-minute job envelope. The earlier deadline wins and is reported through the
typed cancellation/timeout contract.

| Stage | Timeout | Contract |
|---|---:|---|
| `format` | 60 s | `gofmt` has no diff |
| `file-size` | 120 s | Strict v1 policy, complete Git-visible source snapshot, deterministic digest-bound report |
| `workflow` | 120 s | Exact workflow digest, actionlint, ShellCheck, full-SHA actions, least privilege, full history |
| `secret-worktree` | 120 s | Locked Gitleaks policy over current source |
| `secret-history` | 120 s | Complete, non-shallow, non-partial, non-replaced Git history |
| `architecture` | 120 s | CYB-32 graph, canonical bytes, and cancellation assertions |
| `quality-contract` | 180 s | Mandatory denial, invalid, recovery, storage, secret, license, status, and promotion tests |
| `vet` | 120 s | `go vet ./...` |
| `static-analysis` | 180 s | Staticcheck all checks on baseline; recorded skip on Go 1.27 |
| `unit` | 180 s | Uncached unit suite |
| `race` | 300 s | Uncached race suite |
| `fuzz-seed` | 120 s | Exact target manifest and deterministic registered-seed execution |
| `license` | 120 s | Default-deny module and shipped-input license inventory |
| `dependency` | 300 s | Module verification, tidy diff, allowlist, locked offline vuln DB, zero SARIF findings |
| `sbom` | 120 s | Deterministic minimal CycloneDX 1.6 SBOM |
| `supply-chain` | 300 s | Reproducible signed native-bundle contract and offline verification |
| `secret-evidence` | 120 s | Redacted secret scan over private evidence before provenance |
| `provenance` | 120 s | COH-internal materials and subject statement |

`scripts/test_ci_quality.sh` is itself an authoritative stage. Its fixtures are
created below the external temporary root; no inactive or `testdata` Go package
is checked into the source tree to evade the all-source CYB-32 scanner.

## Typed outcomes

| Process exit | Machine code | Meaning |
|---:|---|---|
| `0` | passed | Every required check completed successfully |
| `1` | `tool_failure` | Invocation, host, parser, or unexpected process failure |
| `2` | `denied` | A reviewed quality or security policy rejected the input |
| `64` | `invalid_input` | The caller supplied an invalid mode, lane, path, or contract |
| `124` | `timeout` | A deadline expired before the commit point |
| `130` | `canceled` | Cancellation won before the commit point |

Tools such as `go test`, `go vet`, and Staticcheck use exit 1 for findings but
can also use it for operational errors. Missing or tampered executables and
invalid entrypoint state are rejected in preflight; after that preflight, the
fixed dispatcher conservatively treats exit 1 from these four commands as a
quality denial. It preserves distinct invocation exits, signals, and the other
typed codes. A stage context that has expired wins even if a defective executor
returns success.

## Source and Git integrity

The preflight snapshot hashes the complete Git-aware source set, physical file
mode, VCS revision, and modified state. A second snapshot after the last stage
must match. Ignored active Go, build, script, CI, and policy inputs are denied.

Git runs through `/usr/bin/git` with caller Git routing removed,
`core.fsmonitor=false`, `core.hooksPath=/dev/null`, and
`GIT_NO_REPLACE_OBJECTS=1`. The secret-history gate denies shallow clones,
partial/promisor clones, replacement refs, grafts, missing objects, and hosted
unborn repositories before scanning every reachable revision.

This is integrity checking, not a hostile same-UID sandbox. Code under test can
still attempt same-UID races, create a new session, or use OS networking. The
runner guarantees cleanup for descendants that stay in its process group.
Adversarial execution requires the later isolated runner boundary.

## Tools, dependencies, and network phases

`ci/tools.lock.json` binds module path, package, version, module sum, `go.mod`
sum, upstream origin revision, platform, compiler lane, and whole executable
digest. The private tool directory rejects missing, extra, symlinked,
oversized, or byte-modified entries before and after every stage.

Connected bootstrap is a separate acquisition phase. It uses the fixed Go
proxy and SumDB, validates source metadata, builds in a private temporary tree,
verifies complete binary digests, and promotes the directory under a lock.
Interrupted promotion rolls back to the previous verified directory; concurrent
promotion cannot bypass the lock. ShellCheck download uses `curl -q`, HTTPS-only
routing, bounded time/size, a locked archive digest, and `TAR_OPTIONS` removal.

Authoritative gate stages always set `GOPROXY=off` and `GOSUMDB=off`, including
connected runs. Offline bootstrap performs verification only and fails closed
when any cache, binary, database, or manifest is absent or changed.

The Go vulnerability snapshot is the vendored, content-addressed 2026-08-19
archive. Extraction rejects traversal, absolute and backslash paths, symlinks,
duplicates, excessive expansion, CRC/truncation, and missing indexes. The exact
tree manifest and semantic indexes are verified before govulncheck. SARIF is
strictly decoded and any result is a denial; govulncheck's SARIF exit zero is
not treated as proof of zero findings.

## Native and hosted storage

Native macOS defaults to the workstation external volume contract. A caller may
instead set `COH_NATIVE_STORAGE_ROOT` to an existing, real, trusted directory;
the toolchain root and every mutable Go cache, module cache, GOPATH, temporary
directory, tool directory, XDG directory, Staticcheck cache, lock, download,
and artifact path must remain below that root. The fixed stage environment
forwards the explicit root only after validating that containment. This Studio
uses `/Users/aj_lobster/Developer` with mutable state under
`/Users/aj_lobster/Developer/COH-toolchains`; no external drive is required.

All prospective paths are checked through their nearest existing canonical
parent before creation and re-resolved afterward. Symlink escapes are denied
before an outside write. `TMPDIR` is fixed to the trusted `GOTMPDIR`, including
for scrubbed secret-history scans, so macOS Git cannot silently scan zero
commits after losing its native temporary-directory environment.

Hosted runs apply the same prospective check below an already existing
`RUNNER_TEMP`. Native Linux requires an explicit, pre-existing real
`COH_TOOLCHAIN_ROOT`. Paths containing spaces are supported.

The native Go executable is exact-version checked but is a host trust input; it
is not independently supply-chain attested by CYB-33. GitHub `setup-go` provides
a stronger external acquisition record. CYB-37 adds a separate native release
contract with compiler-bound binaries, signed release SBOM/checksum/provenance
records, and SLSA-compatible provenance. Its public CI fixture signer proves
mechanics only and cannot authorize a production release.

## Evidence and commit points

Successful and failed evidence are deliberately separate.

Private success evidence contains bounded stage logs, raw govulncheck SARIF,
the full evidence manifest, the report, SBOM, database verification, and the
COH-internal provenance statement. Private failure evidence contains only
allowlisted stage artifacts, a strictly verified failure report, and
`failure-manifest.json`; the manifest records names, lengths, digests, status,
and typed outcome, never log content. Missing or interrupted logs are explicit.
Failed evidence is never uploaded by the supplied workflow.

The public success bundle contains exactly:

- `architecture-report.json`
- `ci-provenance.json`
- `coh.cdx.json`
- `govulndb-verification.json`
- `quality-report.json`
- `publication-manifest.json`

Raw logs and raw SARIF are not public. `publication-manifest.json` is the
atomic commit marker. A canceled or failed finalization removes any uncommitted
success report and marker. Cancellation immediately before rename prevents
publication; once the verified sibling-directory rename commits, success wins
the race. `qualitygate -mode verify-publication -artifact-dir <download>`
checks exact membership, every digest, the report self-digest, and the
promotability agreement.

The internal CI provenance predicate remains a COH-owned unsigned object and is
not represented as release provenance. The separately signed CYB-37 native
release statement uses in-toto Statement v1 and the SLSA provenance v1
predicate; the two contracts are not interchangeable.

## GitHub Actions contract

The workflow has `contents: read`, no secrets, no write or identity-token
permission, no `pull_request_target`, full checkout history, non-persisted
credentials, and no expression interpolation in shell commands. Every action
uses a reviewed full commit SHA. The baseline and Go 1.27 matrix entries are
both required to pass. The workflow invokes the fixed script through
`env -u BASH_ENV -u ENV /bin/bash` and uploads only a completed `.public`
directory on success.

Workflow concurrency is keyed by workflow and ref with
`cancel-in-progress=true`. A newer run cancels the older run; cancellation must
win before the public-directory rename to prevent a commit. GitHub's job
timeout is 45 minutes and does not weaken the gate's 30-minute default or the
shorter per-stage deadlines.

Repository governance is an operator prerequisite that local code cannot
configure or attest. Protect `main`; require both matrix checks before merge;
require reviewed ownership changes for `.github/workflows`, `ci` policies and
locks, allowlists, `cmd/qualitygate`, `internal/helper/quality`, and gate
scripts; and disallow administrator bypass except a documented, audited
emergency procedure. This prerequisite must be verified after the first push.

Native entrypoints also use `/bin/bash`. A hostile caller environment before
the entrypoint starts remains a host trust input; CYB-33 is not a same-UID host
sandbox.

## Change and recovery policy

Any change to the policy, workflow, stage dispatcher, material list, tool lock,
vulnerability lock, license/dependency allowlist, public artifact set, report
schema, or timeout changes the source and/or locked digest and requires both
lanes plus the adversarial contract suite to pass again. Stale artifact
directories are never reused. Indeterminate or incomplete output cannot be
promoted by a previous marker.

See [CYB-33 quality-gate report](../evidence/CYB-33-quality-gate-report.md) for
the verification matrix and the two-plane evidence procedure.
