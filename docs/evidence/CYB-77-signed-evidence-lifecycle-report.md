# CYB-77 signed evidence lifecycle verification

| Field | Value |
|---|---|
| Stable key | COH-E10-05 |
| Requirements | FR-028, FR-029, SEC-037, SEC-042 |
| Implementation commit | `6e9400174d908702f6fe59b8f64607e76f8698a3` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `08bbf47505910c5e60325bb944aa7de68eacdaa9ba9b8936e83ff2a3e307c35f` |
| CI report file SHA-256 | `0a793fc77bede879faadf11ea8d30a57d9b88abb2d7d1997acd88772b8dea2a9` |
| Focused verifier log SHA-256 | `fdd936171121835c34b6fc97c36ea246f4c09f3bf800e6f3d0ad663462afe861` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/cyb77-focused.Z0TcA0/verify-signed-evidence-lifecycle.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/govulncheck.sarif`
- SBOM: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/coh.cdx.json`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.67zO2X/ci-provenance.json`

## Acceptance evidence

| Criterion | Evidence |
|---|---|
| Classification, legal hold, signed packages, verified import, and authorized deletion | Export resolves classified immutable evidence, validates lineage/redaction/custody/checkpoint proof, obtains fresh authority, signs a canonical pathless package, and releases it only after completion proof. Import parses in an isolated bounded worker and publishes only after complete signature, trust, revocation, digest, lineage, custody, checkpoint, scope, and local-authority verification. Hold, incomplete release, and retention facts fail closed. Deletion requires fresh approval and authorization custody before tombstone and verified physical disposition. |
| Default deny, exact actor/scope, confidentiality, audit, and stale/revoked state | Strict schemas and canonical bindings cover organization, tenant, case, actor revision, policy, approval, revocation, case revision, custody head, artifact/package set, deadline, and idempotency. Narrow ports expose no keys, credentials, paths, policy source, network, shell, provider, connector, executor, or generic callback. Valid denials are bounded and attributable; audit failure cannot produce a usable result. |
| Invalid input, denial, timeout, cancellation, provenance, and recovery | Named tests cover malformed and noncanonical schemas, hostile framing, compression, traversal, links, duplicates, size abuse, signature/key/lineage/checkpoint drift, cross-scope substitution, stale authority, denial, cancellation, timeout, dependency failure, partial import, restart, and every durable recovery phase. Exact progress and immutable record/receipt bindings preserve provenance and reject changed replay. |
| Automated success/failure and all applicable gates | The focused verifier covers strict contracts, all lifecycle services and adapters, SQLite restart/lost-response/concurrency/tamper behavior, 10 repeated runs, race, vet, static analysis, architecture, file size, documentation links, and clean diff. The exact clean implementation commit passed all 18 repository-wide baseline stages. |
| Required verification evidence | This report and retained logs cross-reference CYB-77, COH-E10-05, FR-028, FR-029, SEC-037, and SEC-042. The named trace below identifies adversarial tests, exact policy/approval bindings, custody/audit proof, and denial/revocation evidence. |

## Required evidence cross-reference

- **Adversarial test trace:** retained focused output names coherent import
  mutation, hostile package-reader, export signature/package substitution,
  retention/hold bypass, disposition tamper, dependency-fault, changed replay,
  fresh revocation, cancellation, timeout, restart, lost-response, and concurrent
  convergence tests.
- **Policy decision:** `AuthorizationRequest` and `Decision` canonical digests
  bind the exact command, actor revision, case and custody snapshot, artifact or
  package set, policy, approval, revocation, expiry, and current retention/hold
  facts. Recovery obtains fresh authority before consequential continuation.
- **Approval and audit proof:** export and deletion bind explicit approval;
  custody authorization precedes package release or disposition. Completed
  results are withheld until deterministic audit, custody, immutable lifecycle
  record, receipt, and outbox commit all validate.
- **Denial and revocation evidence:** stale policy, actor, case, custody,
  approval, key, trust, checkpoint, retention, legal hold, pending hold release,
  changed replay, and fresh revocation yield typed bounded denial with no usable
  package, imported reference, or completed deletion.

## Persistence, recovery, and concurrency

The production store uses the guarded `evidence_lifecycle` metadata kind. Each
progress phase advances by one optimistic revision. Completion atomically
writes completed progress, the immutable lifecycle record, immutable receipt,
and deterministic outbox event. SQLite tests prove process restart, simulated
lost commit response, durable tamper rejection, concurrent exact phase/commit
convergence, changed-intent rejection, and changed-result rejection. The
baseline initially exposed a losing-commit race; commit `6e94001` added exact
completed-progress receipt recovery and passed 50 normal plus 10 race-enabled
focused reproductions before the final clean gates.

## Operations, migration, privacy, and key custody

The operator runbook documents signer-only private-key custody, public-key and
revocation retention, exact package compatibility, offline verification limits,
dedicated import quarantine, retention/hold/deletion checks, forward recovery,
fail-closed rollback, sensitive metadata handling, and consistent backup/restore
requirements. V1 adds a validated metadata kind and requires no SQL DDL. Readers,
trust history, and recovery tooling deploy before writers. Rollback disables new
consequential writes while preserving restrictive holds, progress, receipts,
tombstones, quarantine, verification keys, revocations, custody, and audit.

## Requirement trace

- **FR-028:** signed import/export, retention, legal hold, attributable deletion,
  durable recovery, and immutable receipts are explicit governed operations.
- **FR-029:** canonical manifests bind the complete artifact set and lineage,
  contributing component versions, policy/approval/revocation, custody interval,
  audit checkpoint, signing key revision, validity, and provenance.
- **SEC-037:** current retention and hold facts block disposition; deletion is
  freshly approved and authorized, tombstoned, attested per encrypted object,
  custody/audit chained, and preserves immutable history.
- **SEC-042:** import is pathless, forward-only, bounded, uncompressed in V1,
  strictly verified in an isolated non-Web worker, and cannot publish partial or
  untrusted references.

## Verification summary

The final focused verifier passed strict contract and forbidden-surface checks,
success and adversarial paths, repeated and race execution, SQLite restart and
concurrency, vet, static analysis, architecture, file-size, documentation-link,
and clean-diff checks. The final clean baseline passed all 18 required stages
and bound unmodified implementation commit
`6e9400174d908702f6fe59b8f64607e76f8698a3`. No unresolved blocking finding
remains for CYB-77. Independent security architecture review remains a
non-blocking follow-up required before the first production release.
