# CYB-38 file-size policy verification report

| Field | Value |
|---|---|
| Issue | COH-E02-03 / CYB-38 |
| Requirements | NFR-016, NFR-017, NFR-018, EVAL-027 |
| Contract | `coh.file-size-policy/v1` and `coh.file-size-report/v1` |
| Baseline | Go 1.26.7, required |
| Qualification | Go 1.27.0, required-to-pass and non-promoting |
| Native mutable root | `/Users/aj_lobster/Developer/COH-toolchains` |
| Docker dependency | None |

## Verdict and evidence model

The implementation is fail-closed and remains subject to the final frozen-tree
lanes, independent review, clean-commit hosted Actions, and Linear attachment.
Pre-document checkpoint runs are diagnostic history, not final evidence for the
current source. Historical CYB-32 and CYB-33 artifacts remain evidence for their
own source states and are not rewritten or represented as CYB-38 results.

The repository report and checksum ledger freeze the public contract, tests,
and verification procedure. Final lane outputs live outside the repository in
content-addressed, manifest-verified artifact directories so embedding their
digest cannot alter the source snapshot they attest. Linear receives the final
report, ledger, selected machine reports, exact external locators/digests, and
hosted Actions links after all gates pass.

## Acceptance trace

| Acceptance area | Implementation and automated proof |
|---|---|
| 500 warning, 800 hard denial, 300 script denial | EOF/CRLF and exact boundary tables plus CLI success/denial integration |
| Governed exceptions | Strict schema/decoder; owner, justification, expiry, issue, category, generator, digest, and approved-maximum tests |
| Narrow interface and typed errors | `Source` snapshot/read port; typed invalid, denied, timeout, canceled, and tool-failure mapping |
| Cancellation, timeout, recovery | Checker cancellation/timeout/reuse tests and CLI/finalization cancellation tests |
| Provenance and deterministic evidence | Double snapshot, canonical sorting, policy/exception/source/report digests, stable round-trip verification |
| Symlink and TOCTOU resistance | File/ancestor/policy/report symlink, parent swap, replacement, same-inode mutation, source drift, and output race tests |
| Atomic no-overwrite publication | Sibling temporary, fsync, hard-link linearization, competing destination preservation, and directory fsync regression |
| CI integration | Locked quality policy v1.1.0 stage, artifact allowlist, provenance materials, thin native wrapper, both compiler lanes |
| Architecture/security/license/dependency | Full quality lane stages and mandatory negative contract suites |

## Adversarial matrix

| Case | Required result | Test evidence |
|---|---|---|
| Malformed, duplicate, unknown, trailing, oversized, invalid UTF-8 policy | `invalid_input` | `TestDecodePolicyRejectsMalformedAndWeakenedInputs`, fuzz targets |
| Weakened or reordered thresholds/exceptions | Denied or invalid | policy validation and schema parity tests |
| 500/501, 800/801, 300/301 with LF, CRLF, terminated/unterminated EOF | Exact pass/warn/deny | checker boundary tables |
| Missing, expired, stale, wrong digest/class/header, over-max exception | Denied with tracked finding | exception lifecycle tables |
| Cancellation or deadline before completion | Typed canceled/timeout report; recovery succeeds | checker cancellation/timeout/recovery test |
| Source replacement or mutation during scan | Denied; no false success | source read and double-snapshot race tests |
| File, ancestor, policy, report, or output-parent symlink | Invalid or denied before unsafe publication | OS source, CLI, and report tests |
| Concurrent report destination | Competitor preserved; writer denied | atomic publication race regression |
| Tampered, noncanonical, wrong-type, duplicate, oversized report | Verification denied | strict report suite |
| Native storage escape or missing root | Denied before outside write | shell storage contract and executor environment regressions |

## Commands

```sh
export COH_NATIVE_STORAGE_ROOT=/Users/aj_lobster/Developer
export COH_TOOLCHAIN_ROOT=/Users/aj_lobster/Developer/COH-toolchains

# Focused baseline and qualification (vet, unit, race)
COH_GO_VERSION=1.26.7 bash -c 'source scripts/lib/go_ssd_env.sh; go vet ./internal/helper/filesize ./internal/helper/quality ./cmd/qualitygate; go test -count=1 ./internal/helper/filesize ./internal/helper/quality ./cmd/qualitygate; go test -count=1 -race ./internal/helper/filesize ./internal/helper/quality ./cmd/qualitygate'
COH_GO_VERSION=1.27.0 COH_CI_GO_VERSION=1.27.0 bash -c 'source scripts/lib/go_ssd_env.sh; go vet ./internal/helper/filesize ./internal/helper/quality ./cmd/qualitygate; go test -count=1 ./internal/helper/filesize ./internal/helper/quality ./cmd/qualitygate; go test -count=1 -race ./internal/helper/filesize ./internal/helper/quality ./cmd/qualitygate'

# Complete offline lanes on one frozen source tree
COH_CI_OFFLINE=true /bin/bash scripts/run_ci_quality.sh baseline
COH_CI_OFFLINE=true /bin/bash scripts/run_ci_quality.sh go1.27
```

## Compatibility, migration, and limitations

This change introduces no runtime service, persistence format, production-data
migration, generic shell/HTTP capability, Docker requirement, or executor
bypass. v1 readers reject unknown versions; any future version needs explicit
compatibility and migration notes. Absolute workstation paths appear only in
local/Linear evidence locators, never in portable machine reports.

Warnings are non-denying evidence by design. The current large PRD and research
dossier are documentation, not handwritten production code; their expected
warnings remain visible and cannot suppress a future production or script
denial.
