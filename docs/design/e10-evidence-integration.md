# COH-E10 evidence integration

| Field | Value |
|---|---|
| Issue | COH-E10 / CYB-14 |
| Children | CYB-76, CYB-71, CYB-79, CYB-78, CYB-77 |
| Requirements | FR-002, FR-019, FR-020, FR-023, FR-028, FR-029, FR-030, NFR-011, SEC-014, SEC-015, SEC-020, SEC-023, SEC-036, SEC-037, SEC-042, EVAL-012, EVAL-013 |
| Status | Implemented and verified |

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

## Integration finding closure

| ID | Boundary | Original parent-level gap | Resolution | Status |
|---|---|---|---|---|
| E10-I01 | Case lifecycle | No production mapping from current records and exact receipts into signed-lifecycle and custody case ports | `lifecyclecase` applies and resolves signed lifecycle operations; `custodycase` independently projects canonical current records and hold/release/delete receipts, including a domain-separated retention-policy binding | Closed |
| E10-I02 | Hold-release safety | No durable case-scoped incomplete-release lookup | The lifecycle repository atomically maintains a case-scoped incomplete-release marker with progress and final receipt commits and proves restart/replay behavior | Closed |
| E10-I03 | Artifact sets | No immutable requested-set resolver | `evidencecatalog` registers and re-verifies ordered receipt-bound artifacts, manifests, parent edges, lineage, components, scope, and set digest | Closed |
| E10-I04 | Redaction ancestry | No receipt-digest verifier for each derived artifact and mapping | `lifecycleredaction` resolves canonical redaction records, receipts, encrypted mappings, ingestion receipts, custody and audit proofs, and exact source ancestry | Closed |
| E10-I05 | Custody | No multi-subject lifecycle recorder/recovery adapter | `lifecyclecustody` advances an ordered receipt set over the real custody controller and ledger, recovers exact sets, and requires a complete independently verified checkpointed interval | Closed |
| E10-I06 | Physical disposition | No exact published-object removal and attestation adapter | `lifecycledisposition` writes a durable exact-object plan, removes only receipt-bound encrypted artifacts, converges after partial/lost responses, and retains manifests and metadata history | Closed |
| E10-I07 | Composition evidence | No full parent integration or verifier | Real SQLite export, derived-redaction, and governed-deletion compositions plus `verify_e10_integration.sh` prove success, restart, replay, adversarial, repeated, and race behavior | Closed |

There are no unresolved blocking integration findings. Closure does not weaken
the five leaf contracts: every conversion reloads and validates the leaf's
canonical evidence rather than treating a lookup index or adapter result as
authority.

## Closure slices

1. [x] Add a case/lifecycle adapter and a durable case-scoped incomplete-release
   index whose active and completed transitions are atomic with lifecycle
   progress and final receipt commits.
2. [x] Add an immutable artifact-set catalog over the guarded repository. Registration
   validates every referenced ingestion record and computes ordered artifact-set,
   lineage, and component digests; resolution re-verifies them.
3. [x] Add receipt-digest resolution to governed redaction storage and a narrow
   verifier adapter that checks each derived artifact, source parent, encrypted
   mapping digest, audit, custody, and provenance binding.
4. [x] Add the lifecycle-to-custody adapter over the CYB-79 controller, repository,
   and verifier. Multi-subject progress must advance the expected head exactly
   once per ordered subject and recover the same receipt set.
5. [x] Add encrypted-CAS disposition with a narrow exact-object request, no caller
   paths, per-object outcome proof, atomic durable attestation, same-intent
   recovery, and preservation of immutable metadata history.
6. [x] Compose the real adapters in a parent integration fixture and add mutation,
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

## Migration and cutover

The five leaf metadata kinds use the existing guarded canonical metadata table;
the integration adds no SQL DDL. The encrypted CAS adds private versioned object
storage and key revisions. Cutover must deploy in this order:

1. schema readers, canonical validators, repository readers, encrypted-CAS key
   revisions, public signing trust/revocation history, checkpoint verification,
   and exact recovery tooling;
2. the case, catalog, redaction, custody, source, signing, package, disposition,
   and lifecycle adapters; then
3. writers and release endpoints only after a restored staging target verifies
   the complete case/metadata/audit/CAS/trust set.

Queued operations remain bound to their original contract version and exact
durable phase. Deployment never translates an old receipt, rewrites provenance,
or infers a missing phase from external state.

## Recovery and reconciliation

- Ingestion publishes no reference until encrypted artifact, encrypted manifest,
  receipt, provenance, and audit facts verify. Pending markers identify staged or
  published objects after interruption; reconciliation never invents a receipt.
- Redaction resumes only `planned → published → custodied → completed` from an
  exact canonical progress record, reauthorizes, and never repeats a completed
  transformation, publication, custody append, or audit release.
- Export, import, hold, release, and deletion recover their exact durable phase,
  revalidate current case, authority, approval, revocation, custody, checkpoint,
  trust, and evidence facts, and reject changed replay.
- Deletion recovery preserves the order `authorization custody → tombstone →
  exact disposition → completion custody → final commit`. A partial disposition
  has no completed-deletion claim; retry reuses the durable object plan, treats
  an already absent exact object as converged, and completes the remaining set.
- Ambiguous metadata or CAS responses return no claimed success. Operators use
  receipt/progress/attestation lookup on a separate restored target; they never
  repair a custody chain, reopen a tombstone, or reconstruct disposed ciphertext
  from retained manifests.

## Rollback

Rollback disables new ingestion, redaction, import/export, hold release, and
physical disposition writers before removing a newer binary. It retains V1
readers and validators, decrypt-only historical key revisions, public signing
and revocation history, quarantine, manifests, receipts, tombstones, custody,
audit checkpoints, provenance, progress, and disposition plans/attestations for
forward recovery.

Rollback never reopens a deleted case, removes or rewrites immutable history,
fabricates completion, repeats an external effect, or recreates an artifact that
was already physically disposed. If an older binary cannot validate a metadata
kind, it must reject it and leave it untouched.

## Privacy, retention, and backup assumptions

Artifact, derived-artifact, and redaction-mapping plaintext remain inside the
encrypted CAS or bounded package/import workers. Public and durable contracts
contain typed references and digests, never plaintext, keys, raw paths, policy
source, approval bodies, credentials, callbacks, or backend error strings.

Manifests, mappings, stable digests, timing, purposes, reasons, verification
reports, lifecycle metadata, quarantine, and attestations are still sensitive
case data. Access, retention, legal hold, audit, export, and backup policy apply
to them. Deployments should normalize or salt low-entropy purpose/reason/rule
inputs before hashing when dictionary recovery is plausible.

Backup and restore are one consistency boundary across case metadata, guarded
records, encrypted CAS, audit/checkpoints, quarantine, key revisions, public
verification keys, and revocation/trust history. A restore is not eligible for
import, export, redaction, hold release, or deletion until the parent verifier
can validate that complete set. Deletion intentionally preserves metadata and
manifests while removing exact artifact ciphertext; backup expiry and erasure
policy must therefore distinguish retained evidence history from disposed bytes.

## Immutable child evidence cross-reference

| Child | Capability | Evidence report | Checksum manifest | Focused verifier |
|---|---|---|---|---|
| CYB-76 / COH-E10-01 | Case lifecycle, retention, hold, tombstone | [case lifecycle report](../evidence/CYB-76-case-lifecycle-report.md) | [CYB-76 checksums](../evidence/CYB-76-artifacts.sha256) | `verify_case_lifecycle.sh` |
| CYB-71 / COH-E10-02 | Immutable encrypted ingestion and manifests | [immutable CAS report](../evidence/CYB-71-immutable-cas-ingestion-report.md) | [CYB-71 checksums](../evidence/CYB-71-artifacts.sha256) | `verify_immutable_cas_ingestion.sh` |
| CYB-79 / COH-E10-03 | Append-only custody and independent verification | [custody report](../evidence/CYB-79-chain-of-custody-report.md) | [CYB-79 checksums](../evidence/CYB-79-artifacts.sha256) | `verify_chain_of_custody.sh` |
| CYB-78 / COH-E10-04 | Governed redaction and encrypted mappings | [redaction report](../evidence/CYB-78-governed-redaction-report.md) | [CYB-78 checksums](../evidence/CYB-78-artifacts.sha256) | `verify_governed_redaction.sh` |
| CYB-77 / COH-E10-05 | Signed packages, import/export, hold, deletion | [signed lifecycle report](../evidence/CYB-77-signed-evidence-lifecycle-report.md) | [CYB-77 checksums](../evidence/CYB-77-artifacts.sha256) | `verify_signed_evidence_lifecycle.sh` |

## Verification and release follow-up

The parent gate runs all five child verifiers plus focused cross-leaf tests, 10
repeated parent runs, race detection, vet, static analysis, architecture, file
size, documentation links, and clean-diff checks. The retained CYB-14 report
maps the three acceptance criteria to named integration and adversarial traces.

No integration finding blocks CYB-14 completion. The independent security
architecture review tracked by CYB-173 remains a hard gate before the first
production release; this integration evidence does not claim that review has
occurred.
