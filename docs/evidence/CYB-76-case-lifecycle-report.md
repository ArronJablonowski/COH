# CYB-76 case lifecycle verification

| Field | Value |
|---|---|
| Stable key | COH-E10-01 |
| Requirements | FR-002, FR-028, SEC-014, SEC-015, SEC-037 |
| Implementation commit | `49306c65f17f6a2e8abadbaf549eb57c0307d23e` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI report digest | `1d089a7710b4874919c79fe3758dfd77435df005b7885a5aa518919cf1e2dc9c` |
| CI report file SHA-256 | `3b6cea31adaaea4cbd19aed76f7ab1f9c8b9b45dd83dc792cc28cb155b2e8df0` |
| Focused verifier log SHA-256 | `89adcbfed78feddf9973c722786f40b0115eccb3ff2cf9006a62f7fff4a63287` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.7XkOdp/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB76.plPDtF/case-lifecycle.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.7XkOdp/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.7XkOdp/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.7XkOdp/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.7XkOdp/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.7XkOdp/ci-provenance.json`

## Acceptance evidence

| Criterion | Evidence |
|---|---|
| Complete lifecycle | The controller implements create, classify, assign, place/release hold, close, reopen, export, and authorized deletion. `TestControllerExecutesCompleteCaseLifecycleAndReplay` executes all nine operations and validates every resulting record and receipt. |
| Exact tenant, case, actor, policy, deadline, and revision binding | Commands, authorization requests, decisions, records, and receipts use closed strict schemas and canonical digests. Mutation tests change organization, tenant, case, actor, actor revision, policy, deadline, and nested record values and prove validation fails closed. Cross-case and cross-tenant commands return before authority or mutation. |
| Optimistic and idempotent storage | Every non-create operation requires the exact current revision. Current record and immutable receipt commit atomically through the guarded metadata repository. Concurrent close commands produce exactly one revision-two winner and one conflict. Exact replay returns the original result only after fresh authority; changed replay is denied. |
| Retention, hold, export, and deletion | Classification can only remain equal or become more restrictive. Legal hold records its reason digest and blocks deletion. Retention blocks early deletion. Export advances a bounded count and preserves the signed-manifest digest. Deletion writes an attributable durable tombstone and never physically deletes metadata, receipts, provenance, or audit history. |
| Audit and provenance | Allowed records contain a canonical audit-event digest and a provenance digest chained to the exact prior record. Success is not released until audit append succeeds. A committed result whose audit append failed is recovered by exact replay, which republishes the original event and records fresh replay authority without applying another transition. Denials and concurrency conflicts are audited. |
| Failure semantics | Focused tests cover malformed input, policy denial, cross-scope access, stale and concurrent revisions, cancellation, timeout, tampered state, changed replay, audit failure, and crash recovery with typed errors and no unauthorized mutation. |
| Durable restart | `TestCaseLifecycleCurrentAndReceiptsSurviveSQLiteRestart` creates and closes a case, closes the SQLite process, reloads revision two after restart, and recovers the original revision-one receipt without reapplying the create transition. |
| Narrow architecture | Reflection fixes the authority, auditor, store, and clock method surfaces. Public records reject executable fields and raw content. The verifier prohibits broker, policy, provider, transport, connector, HTTP, and shell imports. The repository-wide architecture gate reports zero violations. |
| Migration and rollback | The adapter adds the validated `case_lifecycle` metadata kind and uses the existing generic canonical metadata table, so no SQL DDL change is required. Older binaries reject the unknown kind. Rollback disables writes while preserving current records, tombstones, and receipts for forward recovery. |

## Requirement trace

- **FR-002:** every command, authority request, durable key, audit event, record,
  and result is bound to exact organization, tenant, case, and actor identity.
- **FR-028:** retention policy, retain-until, legal hold, export-manifest
  references, and authorized tombstone deletion are first-class lifecycle state.
- **SEC-014:** organization and tenant identity is checked before authority,
  storage, audit, replay, and result release; cross-tenant tests fail closed.
- **SEC-015:** deterministic case-scoped keys, canonical envelope validation, and
  exact record/receipt scope prevent cross-case resolution or mutation.
- **SEC-037:** hold and retention block deletion; the deleting actor, reason,
  authority, audit event, prior provenance, and tombstone remain durable.

## Verification summary

The focused verifier passed the strict schema/wire contract, all nine lifecycle
operations, state and deletion invariants, canonical binding mutations,
invalid input, policy denial, cross-scope isolation, stale and concurrent
revision handling, cancellation, timeout, tamper denial, exact and changed
replay, audit repair, SQLite restart, repeated execution, race detection, vet,
static analysis, architecture, file-size, link, and clean-diff gates.

The first baseline attempt exposed an existing retrieval-recovery fixture with
an expired absolute deadline. That fixture was changed to a future-relative UTC
deadline, and its recovery path passed 20 repetitions plus the race detector.
The subsequent clean baseline passed all 18 required stages: format, file-size,
workflow, worktree/history/evidence secret scans, architecture, quality
contract, vet, static analysis, unit, race, fuzz seeds, license,
dependency/vulnerability, SBOM, supply chain, and provenance. The report binds
the exact clean implementation commit and is promotable. No unresolved
blocking finding remains for CYB-76.
