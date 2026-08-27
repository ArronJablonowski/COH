# CYB-78 governed evidence redaction verification

| Field | Value |
|---|---|
| Stable key | COH-E10-04 |
| Requirements | FR-030, SEC-036 |
| Implementation commit | `05dca4c6a470ed9afdd89e5f3b1db410cab540df` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `f86f01e426570e0b34614a99e7620d3fb82833be4250bb5b574020941f53758f` |
| CI report file SHA-256 | `11c2fbd26c66b94700c8989973376759814f78c3e44c26482961bc229c1546b6` |
| Focused verifier log SHA-256 | `b164cff7dc05565a52cb0eb5b9ac428fde1a9829fb21541099b1e3a03599c99d` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB78.Ogyu8t/governed-redaction.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/architecture-report.json`
- Full race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/govulncheck.sarif`
- SBOM: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/coh.cdx.json`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.d44Gxc/ci-provenance.json`

## Acceptance evidence

| Criterion | Evidence |
|---|---|
| Derived artifact with explicit governance and immutable source | The strict command, plan, mapping, completed record and receipt bind actor/revision, exact source artifact and encrypted manifest, signed rule/revision, reason, approved plan, approval-use proof, policy/revocation, derived and encrypted mapping ingestion receipts, custody, audit and provenance. The encrypted-CAS integration test resolves the unchanged source after publishing distinct derived and mapping objects. |
| Default deny, exact scope and fail-closed audit | Preflight resolves case, plan, rule, source and custody both before and after exact approval use; authority is last. Stale scope/state, source drift, malformed plans, revoked approval or authority, changed decision, invalid publication, custody/audit failure, cancellation and timeout yield no receipt. Valid denials append and verify a bounded safe event; denial-audit failure cannot become usable success or denial evidence. |
| Replay, tamper, stale state, revocation and recovery | Durable progress advances `planned → published → custodied`; final record and receipt commit atomically. Exact replay reauthorizes and verifies the stored audit without repeating transformation, publication or custody. SQLite restart, lost response, exact concurrency and changed replay are covered. Mapping mutation, custody-proof substitution, source/ciphertext drift and canonical binding changes fail closed. |
| Automated success/failure and quality gates | The focused verifier covers strict schemas, forbidden surfaces, success, denial, timeout, cancellation, recovery, adversarial mutations, 10 repeated runs, focused race, vet, static analysis, architecture, file size and documentation. The clean implementation commit passed all 18 baseline stages, including repository-wide unit/race, secrets, licenses, dependencies/vulnerabilities, SBOM, supply chain and provenance. |
| Required verification evidence | This report and retained logs cross-reference CYB-78, COH-E10-04, FR-030 and SEC-036. Named traces prove adversarial behavior, exact positive policy/approval bindings, completed custody/audit proof, and denial/revocation evidence. |

## Required evidence cross-reference

- **Adversarial test trace:** `TestPlanValidationRejectsInvalidAndOverlappingSpans`,
  canonical mutation tests, encrypted-CAS segment/rule/ciphertext drift,
  substituted publication, durable mapping tamper, malformed custody/audit proof,
  changed replay, concurrency, restart and lost-response tests appear by name in
  the retained focused log.
- **Policy decision:** `AuthorizationRequest` and `Decision` canonical bindings
  cover exact case, actor revision, source, plan, approval fingerprint, policy,
  revocation, case revision, custody head and expiry. Preflight tests prove the
  positive decision is obtained only after post-approval re-verification.
- **Approval and audit proof:** approval-use authorization and verification bind
  the exact intent and durable use proof. Success is released only after the
  `redact/completed` custody receipt and deterministic completed event both
  verify. Exact replay verifies the stored event before returning its receipt.
- **Denial and revocation evidence:** revoked approval, explicit revoked authority,
  changed decision, stale state, cancellation, timeout, custody failure and audit
  failure are bounded failures. The revocation orchestration test proves a safe
  `denied` event is appended before any plaintext transformation or publication.

## Security and privacy evidence

The public contracts and reflected narrow ports contain no plaintext, selected
text, replacement content, credentials, policy source, paths, network clients,
shell, callbacks, providers, connectors or executors. The trusted transformer
uses two verified passes, bounded buffers and forward-only streams. Publication
failure closes and clears its plaintext source. Encrypted-CAS tests scan every
persisted object and prove source, derived and mapping plaintext are absent.
Mapping access remains a separately governed custody operation and is not
implied by possession of the derived artifact or final receipt.

## Migration, rollback and downstream release

The validated `redaction_record` metadata kind uses the existing guarded generic
metadata tables and requires no SQL DDL. Rollback disables new redaction and
release while retaining the V1 reader, progress, records, receipts, source,
derived objects, encrypted mappings, ingestion/custody/audit evidence and
historical rule/key revisions. CYB-77 may consume only a valid completed receipt
with its matching durable record, custody and audit proof; a CAS reference,
partial progress or mapping possession is not release authority.

## Requirement trace

- **FR-030:** every successful redaction creates a distinct immutable derived
  artifact and encrypted mapping bound to exact rule, reason, actor, source,
  approval, custody, audit and provenance while retaining the source.
- **SEC-036:** the workflow is an exact, default-deny approved transformation;
  no interface permits in-place source mutation, implicit authority, plaintext
  metadata persistence, uncustodied release or unverifiable mapping.

## Verification summary

The focused verifier completed twice and passed contract, implementation,
adversarial, repeated, focused race, vet, static-analysis, architecture,
file-size, documentation-link and clean-diff checks. The final clean baseline
passed all 18 required stages and bound exact unmodified implementation commit
`05dca4c6a470ed9afdd89e5f3b1db410cab540df`. No unresolved blocking finding
remains for CYB-78.
