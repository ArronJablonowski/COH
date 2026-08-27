# CYB-79 chain-of-custody verification

| Field | Value |
|---|---|
| Stable key | COH-E10-03 |
| Requirements | FR-020, FR-023, SEC-020, EVAL-013 |
| Implementation commit | `9e03dc4bcb01ad41adc88693c7c62281f56c362e` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `4bc05ddcdbcb6104194521108f7a4b773bbbc7fe54a6a4803938ae2252085121` |
| CI report file SHA-256 | `b42302930c60f266d85cc3b578f57fe331afb7620e5bed43499c51c18d5a6f25` |
| Focused verifier log SHA-256 | `06655cb09f2716d422d70cdb54286ebfaf009accdf60bd7ccb9b33d7bd50602c` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB79.1oR6wU/chain-of-custody.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/govulncheck.sarif`
- SBOM: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/coh.cdx.json`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.27p1hS/ci-provenance.json`

## Acceptance evidence

| Criterion | Evidence |
|---|---|
| Complete bound custody operations | Strict commands, authority requests, decisions, records, and receipts bind organization, tenant, case, actor/revision, time, operation/phase, artifact, encrypted manifest, source or destination facts, policy, revocation, expected head, audit, and provenance. Success tests cover acquisition, access, transformation, redaction, transfer, export, hold placement/release, deletion authorization, and deletion completion. |
| Default-deny security boundary | Validation and narrow-port reflection prohibit evidence bytes, manifest plaintext, credentials, policy source, raw destinations, callbacks, network, shell, connector, provider, and executor surfaces. Approval/revocation denial, stale actor/case/head/artifact, cross-scope access, changed replay, timeout, cancellation, audit failure, and tampered replay yield no usable result. Denial audit contains bounded safe reason codes and digests. |
| Append-only atomic persistence | The guarded repository commits the immutable record, case head, idempotency receipt, receipt-digest index, and outbox evidence in one optimistic transaction. There is no update, delete, sequence skip, or repair operation. A simulated lost commit response recovers the exact receipt and one record. |
| Restart and concurrency | A two-record acquisition-to-access chain survives SQLite close/reopen with its exact head, order, links, receipts, and two outbox messages. Twelve concurrent identical calls converge on one append and receipt. Concurrent changed commands at genesis produce one winner and one typed conflict. |
| Independent verification | The read-only verifier walks from genesis, reconstructs each receipt, checks idempotency recovery, prior authorization ancestry, evidence and lineage, deterministic audit binding, audit coverage, and the durable head. A trusted covering checkpoint is required for `valid`; a complete uncheckpointed interval is `incomplete`. |
| Adversarial trace | `TestVerifierRejectsInsertionDeletionReorderMutationForkAndTruncation` rejects every named mutation class. Missing audit coverage is rejected. Canonical mutation tests cover every command security dimension, record, precommit, receipt, and stale binding. The focused log retains the complete named trace. |
| Policy, approval, revocation, and audit proof | Controller decisions are canonical, expiry-bounded, head-bound, and carry the current policy and revocation digests. Approval-required, approval-invalid, revoked, and stale-actor paths are denial-audited. Allowed results are withheld until the deterministic custody event is appended and verified; exact replay repairs a missing historical event without another custody append. |
| Checkpoint and key custody | The auditor port owns checkpoint signature, public-key revision, and revocation-interval verification. The custody verifier accepts only its bounded proof and has no signing key capability. Missing or malformed trust anchoring cannot produce an independently valid report. |
| Export and deletion ancestry | Transfer, export, and deletion completion resolve an immutable prior authorization receipt and compare the exact operation, artifact, policy, purpose, destination/recipient, reason, and artifact set. Export package signatures remain CYB-77's separate boundary and must be valid alongside custody proof. |
| Migration, rollback, recovery, and privacy | The validated `custody_record` kind uses existing generic metadata tables, so no SQL DDL is required. Rollback disables new writes/releases but retains readers, records, receipts, CAS objects, audit data, and historical verification keys. Recovery never edits history. Stable digests and timing inherit case access and retention controls. |
| Quality and supply chain | The focused verifier passed strict schemas, all operation/failure tests, repetition, race, vet, static analysis, architecture, size, documentation links, and clean diff. The exact clean implementation commit passed all 18 required baseline stages and produced vulnerability, SBOM, supply-chain, and provenance evidence. |

## Required evidence cross-reference

- **Adversarial test trace:** focused log sections for canonical mutation,
  verifier insertion/deletion/reorder/mutation/fork/truncation, missing audit,
  concurrent exact replay, competing head writes, restart, and lost response.
- **Policy decision:** `Decision` canonical binding and controller allow/deny
  tests bind policy, actor revision, scope, head, expiry, and revocation digest.
- **Approval and audit proof:** approval-required/invalid denial tests plus
  allowed-event append/verify, replay repair, checkpointed valid report, and
  uncheckpointed incomplete report tests.
- **Denial and revocation evidence:** named denial trace covers approval,
  revocation, stale actor/case/artifact, cross-scope, cancellation, timeout,
  tampered replay, and fail-closed audit failure without sensitive values.

## Requirement trace

- **FR-020:** every custody link resolves and binds the immutable artifact,
  encrypted manifest, manifest provenance, and ingestion receipt.
- **FR-023:** every evidence-handling operation extends the case-local chain;
  transformations and redactions additionally prove immutable parent ancestry.
- **SEC-020:** exact case scope, optimistic head comparison, immutable records,
  chain hashes, receipts, and deterministic tenant-audit cross-binding prevent
  silent insertion, deletion, reorder, rewrite, fork, or duplicate append.
- **EVAL-013:** the retained focused trace proves all required mutation,
  concurrency, fault, restart, replay, audit, revocation, and genesis-verifier
  cases fail closed or converge to one exact result.

## Verification summary

The focused verifier passed the strict contract and forbidden-surface checks,
all nine operation families, policy/approval/revocation denials, stale and
cross-scope boundaries, invalid input, cancellation, timeout, tamper, audit
failure and repair, exact and changed replay, lost-response recovery, SQLite
restart, concurrent convergence/conflict, independent verification mutations,
10 repeated runs, race detection, vet, static analysis, architecture, file
size, documentation links, and clean-diff checks.

The clean baseline then passed all 18 required stages: format, file size,
workflow policy, worktree/history/evidence secret scans, architecture, quality
contract, vet, static analysis, unit, race, fuzz seeds, license, dependency and
vulnerability, SBOM, supply chain, and provenance. The report binds exact clean
commit `9e03dc4bcb01ad41adc88693c7c62281f56c362e`, marks it promotable, and records
zero failed stages. No unresolved blocking finding remains for CYB-79.
