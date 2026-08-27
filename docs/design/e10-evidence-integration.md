# COH-E10 evidence integration

| Field | Value |
|---|---|
| Issue | COH-E10 / CYB-14 |
| Children | CYB-76, CYB-71, CYB-79, CYB-78, CYB-77 |
| Requirements | FR-002, FR-019, FR-020, FR-023, FR-028, FR-029, FR-030, NFR-011, SEC-014, SEC-015, SEC-020, SEC-023, SEC-036, SEC-037, SEC-042, EVAL-012, EVAL-013 |
| Status | Integration findings open |

## Purpose

This integration closes the gap between the five independently verified COH-E10
leaves. Parent acceptance requires one production-composable path from a current
case through immutable encrypted ingestion, optional governed redaction,
append-only custody, signed export or authorized disposition, and independent
verification. Leaf-local fakes are not evidence that these boundaries compose.

## Authoritative flow

1. Load one exact case lifecycle record and reject stale, deleted, cross-tenant,
   or classification-incompatible work.
2. Ingest source bytes once through the encrypted CAS and retain the immutable
   artifact, encrypted manifest, ingestion receipt, and provenance binding.
3. Register an immutable ordered artifact set whose digest binds every evidence
   reference, role, parent edge, and governed-redaction proof.
4. If a derived artifact is included, resolve and verify its immutable redaction
   record, encrypted mapping, source ancestry, ingestion receipts, custody, and
   audit proof. Possession of a derived reference is not redaction authority.
5. Resolve and verify the complete custody interval for every subject. A missing,
   reordered, forked, truncated, unaudited, or uncheckpointed interval cannot
   authorize release or completed disposition.
6. For export, apply the exact case export transition, build and independently
   verify the pathless signed package, append authorization/completion custody,
   commit lifecycle evidence, and only then expose the release handle.
7. For deletion, prove current retention and hold eligibility, append
   authorization custody, commit the case tombstone, disposition only the exact
   verified encrypted objects, append completion custody, and retain all
   metadata, provenance, audit, public verification, and attestation history.

## Integration findings

| ID | Boundary | Current evidence | Missing parent-level capability |
|---|---|---|---|
| E10-I01 | Case lifecycle | CYB-76 repository/controller and CYB-71 read adapter are production-backed | CYB-77 has no adapter that maps current records and exact lifecycle receipts into `CaseStore`/`CaseLifecycle`. |
| E10-I02 | Hold-release safety | CYB-77 services fail closed when `HasIncompleteHoldRelease` is true | No durable case-scoped index can answer that query after restart without knowing the release idempotency key. |
| E10-I03 | Artifact sets | CYB-71 persists and verifies individual immutable evidence and manifests | No immutable artifact-set registry resolves a requested set digest into verified ordered evidence, lineage, and component bindings. |
| E10-I04 | Redaction ancestry | CYB-78 creates digest-bound immutable records and receipts | No receipt-digest lookup adapter verifies each derived artifact and mapping named by an export set. |
| E10-I05 | Custody | CYB-79 provides a production repository, controller, and read-only verifier | CYB-77 has no adapter that records a multi-subject lifecycle request and returns/verifies its exact receipt set and checkpointed interval. |
| E10-I06 | Physical disposition | CYB-71 CAS supports staging, immutable publication, verification, and safe abandonment | Published-object removal/cryptographic erasure, exact recovery, and durable per-object disposition attestations have no production adapter. |
| E10-I07 | Composition evidence | Each leaf has focused and clean baseline evidence | No focused parent verifier or end-to-end integration fixture proves the full ingest/redact/custody/export/delete chain. |

These are blocking findings for CYB-14 only. They do not invalidate the leaf
contracts or their completed acceptance evidence; they prevent claiming that the
parent integration is production-composable.

## Closure slices

1. Add a case/lifecycle adapter and a durable case-scoped incomplete-release
   index whose active and completed transitions are atomic with lifecycle
   progress and final receipt commits.
2. Add an immutable artifact-set catalog over the guarded repository. Registration
   validates every referenced ingestion record and computes ordered artifact-set,
   lineage, and component digests; resolution re-verifies them.
3. Add receipt-digest resolution to governed redaction storage and a narrow
   verifier adapter that checks each derived artifact, source parent, encrypted
   mapping digest, audit, custody, and provenance binding.
4. Add the lifecycle-to-custody adapter over the CYB-79 controller, repository,
   and verifier. Multi-subject progress must advance the expected head exactly
   once per ordered subject and recover the same receipt set.
5. Add encrypted-CAS disposition with a narrow exact-object request, no caller
   paths, per-object outcome proof, atomic durable attestation, same-intent
   recovery, and preservation of immutable metadata history.
6. Compose the real adapters in a parent integration fixture and add mutation,
   cross-scope, unauthorized-redaction, custody-gap, restart, lost-response,
   concurrency, export verification, and deletion-recovery tests.

## Closed integration invariants

- Every adapter accepts and returns typed metadata only; evidence streams stay
  inside encrypted CAS, package quarantine, or the isolated import worker.
- Organization, tenant, case, actor revision, policy, approval, revocation,
  lifecycle revision, custody head, artifact set, and provenance are compared at
  every conversion rather than copied as implicit trust.
- Lookup indexes are digest-bound conveniences, not authority. Their targets are
  reloaded and fully validated before use.
- No successful result is exposed between boundaries. Exact replay resumes from
  durable progress, while changed input, changed result, or ambiguous physical
  disposition fails closed.
- Original immutable source evidence remains resolvable after redaction and
  signed export. Governed deletion removes only verified encrypted evidence
  objects and never removes the case tombstone, manifests, receipts, custody,
  audit, provenance, public keys, or disposition attestation.

## Verification plan

The parent gate will run all five child verifiers plus focused cross-leaf tests,
10 repeated runs, race detection, vet, static analysis, architecture, file size,
documentation links, and a clean full baseline. Its retained report will map the
three CYB-14 acceptance criteria to named integration and adversarial traces and
cross-reference each immutable child evidence set.
