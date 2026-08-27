# CYB-14 cases, evidence, and provenance integration verification

| Field | Value |
|---|---|
| Stable key | COH-E10 |
| Requirements | FR-002, FR-019, FR-020, FR-023, FR-028, FR-029, FR-030, NFR-011, SEC-014, SEC-015, SEC-020, SEC-023, SEC-036, SEC-037, SEC-042, EVAL-012, EVAL-013 |
| Implementation checkpoint | `077c4e809b1968a91fc0237e450f151934d57015` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during focused/baseline verification | `false` |
| CI report digest | `195b86b78d5d93047087b3593588dfcb20b0b1450fd5e7ca97392223a0ef2970` |
| CI report file SHA-256 | `d0f01974e05ab2fe29c2825858b8625beb3e3c8754088cedf6ec49b5e643a968` |
| Focused verifier log SHA-256 | `5f7a2e7cc6d80e75feff8d2e476592b2c229437c36e9c17cbbf4792e58d1294c` |

## Evidence locations

- Focused parent verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB14.wQBT4r/e10-integration.log`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.jHzAPj/quality-report.json`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.jHzAPj/architecture-report.json`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.jHzAPj/unit.log`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.jHzAPj/race.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.jHzAPj/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.jHzAPj/ci-provenance.json`
- Checksums: [CYB-14-artifacts.sha256](CYB-14-artifacts.sha256)

## Child completion evidence

| Child | Capability | Immutable evidence | Focused gate |
|---|---|---|---|
| CYB-76 / COH-E10-01 | Case lifecycle, classification, retention, hold, export reference, tombstone | [case lifecycle report](CYB-76-case-lifecycle-report.md) and [checksums](CYB-76-artifacts.sha256) | `verify_case_lifecycle.sh` |
| CYB-71 / COH-E10-02 | Immutable encrypted ingestion, manifests, receipts, provenance | [immutable CAS report](CYB-71-immutable-cas-ingestion-report.md) and [checksums](CYB-71-artifacts.sha256) | `verify_immutable_cas_ingestion.sh` |
| CYB-79 / COH-E10-03 | Append-only custody and independent verification | [custody report](CYB-79-chain-of-custody-report.md) and [checksums](CYB-79-artifacts.sha256) | `verify_chain_of_custody.sh` |
| CYB-78 / COH-E10-04 | Approved redaction, derived evidence, encrypted mapping | [redaction report](CYB-78-governed-redaction-report.md) and [checksums](CYB-78-artifacts.sha256) | `verify_governed_redaction.sh` |
| CYB-77 / COH-E10-05 | Signed import/export, hold, deletion, lifecycle recovery | [signed lifecycle report](CYB-77-signed-evidence-lifecycle-report.md) and [checksums](CYB-77-artifacts.sha256) | `verify_signed_evidence_lifecycle.sh` |

The parent verifier refuses to run if any child report, checksum manifest,
focused verifier, production adapter, integration fixture, or operational
design is absent or linked. It executes all five child gates before the parent
composition and adversarial trace.

## Parent integration acceptance

| Criterion | Authoritative evidence | Result |
|---|---|---|
| Case scoping and immutable evidence are enforced from ingest through export or governed deletion | `TestCOHE10ComposedExportUsesImmutableEncryptedEvidenceAndDurableStores` composes current case lifecycle, encrypted ingestion, receipt-bound artifact-set catalog, encrypted CAS source reads, custody/checkpoint verification, Ed25519 signing, pathless package construction, export lifecycle, and durable SQLite recovery. `TestCOHE10GovernedDeletionOrdersTombstoneDispositionCustodyAndRecovery` proves authorization custody precedes tombstone, exact ciphertext disposition, completion custody, and final commit; artifact ciphertext becomes unresolvable while the tombstone, encrypted manifest, ingestion receipt, catalog, custody, audit, provenance, and disposition attestation remain durable. | Pass |
| Byte mutation, lineage break, custody gap, and unauthorized redaction are detected | Real ingestion/catalog tests reject changed length/reference and missing parent edges. Receipt-bound CAS reads reject artifact and ciphertext drift. The custody verifier rejects insertion, deletion/gap, reorder, mutation, fork, truncation, and missing audit coverage. Redaction preflight denies revoked/changed approval or authority before plaintext; the lifecycle verifier rejects parent, mapping, ingestion-receipt, custody, and audit substitution. | Pass |
| Signed exports verify independently and preserve original bytes plus all transformations | The composed original-plus-derived export recovers the released package with two exact byte payloads, source/derived roles, parent artifact and manifest edges, redaction receipt/mapping, custody interval, checkpoint proof, component set, detached Ed25519 signature, trust/revocation bindings, and manifest digest. Package verification is independent of the export service and rejects signature, manifest, key, bounds, lineage, custody, checkpoint, or trust substitution. | Pass |

## Positive cross-leaf proof

The export fixture starts from a real restricted case, ingests source bytes into
the encrypted CAS, records initial custody, derives separately encrypted
redacted bytes and canonical mapping, commits a governed redaction receipt and
custody proof, registers the ordered two-artifact set, and exports through the
real lifecycle adapters. Release occurs only after package, signature, custody,
checkpoint, redaction, case, audit, and final receipt verification. Exact replay
returns the same committed release without repeating transformation or custody.

The deletion fixture starts from a real case and immutable artifact set, waits
past retention, and enforces this observed call order:

```text
custody.authorized → case.tombstone → disposition → custody.completed → commit
```

It then closes and reopens SQLite and the encrypted CAS, proving the case
tombstone, deletion receipt, disposition attestation, ingestion/catalog
metadata, encrypted manifest, custody history, audit, and provenance survive.

## Parent adversarial trace

| Class | Named trace | Required outcome |
|---|---|---|
| Byte/reference mutation | `TestEvidenceReceiptAndEncryptedObjectsSurviveSQLiteRestart`, `TestOpenIngestedArtifactRequiresExactReceiptAndVerifiesPlaintext`, `TestManifestHeaderSignatureAndVerificationBindingsRejectMutation` | Changed artifact facts, ciphertext, manifest, signature, or package binding is denied before release |
| Broken lineage | Catalog broken-parent subcase and `TestAdapterRejectsBrokenLineageAndMappingSubstitution` | Missing/substituted parent artifact, parent manifest, mapping, or derived receipt is denied |
| Custody gap | `TestVerifierRejectsInsertionDeletionReorderMutationForkAndTruncation`, `TestVerifierRejectsMissingAuditCoverage` | No valid report or release from an incomplete, unaudited, changed, or forked chain |
| Unauthorized redaction | `TestPreflightRejectsRevokedApprovalAndChangedDecision`, `TestOrchestratorAuditsRevocationDenialBeforePlaintextOrPublication`, lifecycle ancestry/custody/audit rejection | No plaintext read, transformation, publication, completed receipt, or export from revoked/changed authority |
| Partial deletion | `TestCOHE10PartialDeletionResumesExactPlanWithoutMetadataLoss` | One removed and one remaining ciphertext yields no attestation; exact retry converges on the durable plan and preserves all metadata/manifests |
| Lost response | `TestLifecycleDispositionRemovesExactBytesAndPreservesMetadataAcrossRestart`, lifecycle/custody/repository lost-response tests | No guessed success or duplicate effect; exact recovery returns one immutable result |
| Consequential-boundary failure | `TestDeleteServiceFailsClosedAtEveryIrreversibleBoundary`, `TestDeleteServiceResumesEveryDurableProgressPhase`, `TestDeleteServiceRejectsTamperedDispositionOnReplay` | No completed-deletion claim before every ordered proof; exact phase recovery only |

## Findings and operational assumptions

The original seven parent integration findings are all closed in the
[COH-E10 integration design](../design/e10-evidence-integration.md). Production
adapters now cover case/lifecycle projection, incomplete hold-release lookup,
artifact sets, redaction ancestry, ordered lifecycle custody, exact physical
disposition, and parent composition evidence. There are no unresolved blocking
findings for CYB-14.

The operational design is authoritative for migration, recovery, rollback,
privacy, retention, key/trust history, and consistent backup/restore. In brief:

- deploy readers, validators, key/trust/checkpoint history, and exact recovery
  tooling before adapters and writers;
- recover only canonical durable phases with fresh authority and never repair
  custody, infer success, reopen tombstones, or reconstruct disposed bytes;
- rollback disables writers/releases while retaining all readers, ciphertext,
  quarantine, receipts, tombstones, custody, audit, provenance, public keys,
  revocation history, progress, and attestations needed for forward recovery;
- treat manifests, mappings, stable digests, timing, reasons, quarantine,
  verification reports, lifecycle metadata, and backups as sensitive case data;
  and
- restore metadata, encrypted CAS, audit/checkpoints, quarantine, keys, and
  trust/revocation history as one consistency boundary before enabling work.

## Requirement trace

- **FR-002, SEC-014, SEC-015:** every case, artifact, redaction, custody,
  lifecycle, package, receipt, and adapter conversion binds exact organization,
  tenant, case, actor revision, policy, and provenance; cross-scope work denies.
- **FR-019, FR-020, NFR-011, EVAL-012, SEC-023:** bounded single-stream
  ingestion verifies plaintext identity while storing only chunked AEAD
  ciphertext, encrypted manifests, immutable receipts, and restart-safe state.
- **FR-023, SEC-020, EVAL-013:** collection, derivation, redaction, export, hold,
  and deletion extend an append-only custody chain independently verified from
  genesis with audit/checkpoint coverage and adversarial gap/fork detection.
- **FR-030, SEC-036:** redaction requires exact independent approval and fresh
  authority, preserves source bytes, encrypts the canonical mapping, appends
  custody/audit, and proves source-to-derived ancestry before export.
- **FR-028, FR-029, SEC-037, SEC-042:** signed pathless packages bind immutable
  evidence, transformations, custody, checkpoint, trust, revocation, purpose,
  destination, approval, and case state. Hold/retention block deletion;
  eligible deletion is freshly authorized, tombstoned, exactly attested,
  custody-completed, attributable, replay-safe, and history-preserving.

## Verification summary

The retained parent verifier passed all five leaf verifiers, successful source
and derived export, governed deletion ordering/restart, every named adversarial
class, 10 repeated parent runs, focused race, vet, static analysis,
architecture, file size, Markdown links, and clean-diff checks. It ended with:

```text
E10 integration summary: children=5 case=scope+retention evidence=immutable+encrypted lineage=verified redaction=authorized+custodied export=signed+independent deletion=tombstone+attested adversarial=mutation+lineage+custody-gap+unauthorized-redaction+partial-delete+lost-response recovery=restart+exact failures=0
```

The same clean checkpoint passed all 18 baseline stages: format, file size,
workflow validation, worktree/history/evidence secret scans, architecture,
quality contract, vet, static analysis, unit, race, fuzz seeds, license,
dependency/vulnerability, SBOM, supply chain, and provenance. The report is
promotable, verification passed, and VCS was unmodified.

## Reproduction and release gate

```sh
./scripts/verify_e10_integration.sh
./scripts/run_ci_quality.sh baseline
```

The independent security architecture review tracked by CYB-173 remains a hard
gate before the first production release. This report does not claim that the
independent review has occurred and does not weaken that follow-up.
