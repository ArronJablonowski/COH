# Signed evidence lifecycle

| Field | Value |
|---|---|
| Issue | COH-E10-05 / CYB-77 |
| Requirements | FR-028, FR-029, SEC-037, SEC-042 |
| Package contract | `coh.evidence-package/v1` / `1.0.0` |
| Lifecycle contract | `coh.evidence-lifecycle/v1` / `1.0.0` |
| Status | Design frozen for implementation |

## Purpose and boundary

This leaf owns signed evidence export and import, retention and legal-hold
orchestration, and explicitly authorized physical disposition. It composes the
implemented case lifecycle, encrypted content-addressed store, custody ledger,
governed redaction, policy/approval, and tamper-evident audit boundaries. It
does not reinterpret or repair any of their records.

An export is usable only when its canonical manifest, detached signature,
package framing, artifact digests, lineage, custody interval, audit checkpoint,
and current release authority all verify. An import is untrusted input until an
isolated worker has completely validated those same facts under local trust and
resource policy. Retention and legal hold are current case facts, not advisory
manifest fields. Physical disposition requires a fresh exact authorization and
never deletes the case tombstone, lifecycle receipts, custody records, audit
history, signed manifests, or provenance required to prove what happened.

The model, provider, connector, executor, and Web process cannot sign, verify,
import, release, change retention or hold, or dispose evidence directly. Raw
filesystem paths, private keys, credentials, policy source, network clients,
shell commands, executable callbacks, and arbitrary extension maps do not cross
the workflow boundary.

## Frozen package format

V1 uses a streaming, pathless framed container rather than ZIP, TAR, or another
general archive format. The package is:

1. a fixed `COHEVPKG1` magic value and fixed-width format header;
2. one bounded RFC 8785 canonical JSON manifest frame;
3. one bounded detached-signature frame over the exact manifest bytes; and
4. the manifest-declared number of raw artifact frames, in manifest order, each
   carrying only a digest, byte length, media-type token, and exact payload.

There are no filenames, filesystem paths, directories, hard links, symbolic
links, devices, sparse extents, nested packages, optional fields, or executable
metadata. Compression is closed to `none` in V1. A compressed content encoding,
archive media type, trailing frame, duplicate artifact, reordered frame, or
undeclared byte is invalid. This makes decompression amplification impossible
in V1 while requiring future compressed versions to define and test explicit
compressed and expanded byte bounds before admission.

The importer parses directly from a forward-only stream into quarantine-owned
encrypted staging. It never extracts to a caller-selected path and never loads
an artifact or package into one unbounded byte slice. Before reading payloads it
enforces configured positive limits for manifest bytes, signature bytes,
artifact count, individual artifact bytes, aggregate package bytes, media
types, and processing deadline. Limits can be stricter than manifest claims;
they can never be widened by the package.

## Canonical export manifest

The strict manifest binds:

- schema/contract/package versions and a unique manifest identifier;
- organization, tenant, case, case revision and classification;
- exporting actor and revision, purpose and destination/recipient digests;
- ordered artifact and encrypted-manifest references, lengths, media types,
  classifications, source/derived roles, and complete parent lineage;
- completed redaction receipt and mapping digest references where applicable,
  without mapping plaintext;
- policy bundle, decision, approval, and revocation digests;
- every contributing model, tool, query, and transformation name, version, and
  immutable digest;
- complete custody interval and verification-report digest;
- tenant audit checkpoint identifier, digest, sequence, signing-key revision,
  and verification proof digest;
- export signing algorithm, public key identifier and positive revision;
- created-at, valid-until, package byte bounds, and idempotency digest; and
- prior lifecycle provenance and the manifest's canonical digest.

The only V1 signing algorithm is Ed25519. Algorithm and key identifiers are
closed tokens, not caller-selected implementation names. The signer accepts
canonical manifest bytes plus a metadata-only authorization and returns a
detached signature and public key identity; private key material never enters
the workflow. The workflow independently verifies its own output before any
package is releasable.

Signature validity alone is not release or import authority. Export also needs
current policy/approval and custody authorization. Import verifies the signer
against a separately configured local trust root, allowed purpose and scope,
key revision, validity interval, and revocation status. Offline verification
can prove package structure, signature, content, lineage, custody proof, and
checkpoint proof only against the trust roots and revocation snapshot supplied
to that verifier; its report states those exact inputs and never claims current
online authorization.

## Lifecycle state and durable progress

Each operation has an immutable intent and an exact idempotency receipt. Work
that crosses durable systems also has a monotonic progress record. Closed
states are:

| Operation | Durable phases |
|---|---|
| export | `planned`, `authorized`, `packaged`, `custodied`, `case_recorded`, `completed` |
| import | `quarantined`, `verified`, `authorized`, `published`, `custodied`, `completed` |
| place hold | `planned`, `case_recorded`, `custodied`, `completed` |
| release hold | `planned`, `case_recorded`, `custodied`, `completed` |
| delete | `planned`, `authorized`, `tombstoned`, `disposed`, `custodied`, `completed` |

Progress may advance by one valid transition or recover the exact same phase;
it cannot skip, regress, change its canonical command, or overwrite a receipt.
A final record and receipt commit atomically. Exact replay obtains fresh
authority where authority is still meaningful, validates every durable fact,
and resumes without a second package, signature, case transition, custody link,
or disposition. Changed idempotency reuse is denied.

## Narrow ports

| Port | Allowed surface | Explicit exclusion |
|---|---|---|
| `Authority` | Decide an exact metadata-only operation and current revocation state | Policy source, approval token, evaluator, credential |
| `CaseStore` | Load current case and resolve exact lifecycle receipts | Generic mutation or repository access |
| `CaseLifecycle` | Apply an exact export, hold, release, or tombstone command | Physical evidence access or deletion |
| `EvidenceResolver` | Resolve and stream a verified immutable artifact and manifest | Caller paths, arbitrary CAS query, mutation |
| `RedactionResolver` | Verify a completed redaction receipt and source lineage | Mapping plaintext or new transformation |
| `Custody` | Append exact authorized/completed operations and verify a complete interval | Record repair, update, deletion, or evidence bytes |
| `Signer` | Sign canonical manifest bytes under an authorized key revision | Private-key export or generic signing oracle |
| `SignatureVerifier` | Verify one closed algorithm/key/signature binding | Trust-root mutation or authority inference |
| `PackageWriter` | Build and verify one bounded pathless package in quarantine | Network destination or caller filesystem path |
| `PackageReader` | Isolated, bounded forward-only verification and staged streams | Web-process parsing, extraction, seek, nested archive |
| `Publisher` | Publish verified staged artifacts through CYB-71 semantics | Partial-reference release or mutable overwrite |
| `Disposer` | Idempotently disposition an exact verified encrypted object set and return an attestation | Metadata/audit deletion or arbitrary path removal |
| `Store` | Recover intent/progress/receipt and commit valid transitions | Generic query, delete, or silent merge |
| `Auditor` | Append and verify deterministic redacted events | Raw destination, package, evidence, keys, or free text |
| `Clock` | Current canonical UTC time | Timer, scheduler, or callback |

The production `PackageReader` runs in a dedicated import worker process with a
fixed protocol, unprivileged identity, no listener, no application database or
signing-key access, a private quarantine root, and configured memory, CPU, file,
process, and byte limits. The Web process may submit only an opaque staged-input
reference and bounded metadata to that worker; it cannot parse package bytes.

## Export ordering

| Step | Durable or observable state | Failure posture |
|---|---|---|
| Validate command, limits, deadline, and idempotency | None or exact prior intent | Invalid or changed input denied before artifact access |
| Load current case and retention/hold facts | Read-only snapshot | Deleted, stale, or policy-ineligible state denied |
| Resolve artifact set, manifests, redaction receipts, and lineage | Internally verified streams and metadata | Missing/tampered/cross-scope content withheld |
| Verify complete custody interval and trusted audit checkpoint | Read-only proof | Incomplete or untrusted proof cannot export |
| Obtain fresh release authority | Exact decision | Denial/revocation audited; no package release |
| Append export `authorized` custody | Durable authorization link | No bytes leave quarantine |
| Build canonical manifest, sign, frame, and independently verify | Quarantined package plus durable progress | Signature/package failure yields no release |
| Append export `completed` custody | Durable completion link | Binds manifest, package, destination, signature, and prior authorization |
| Record case export manifest through case lifecycle | Durable case receipt and audit | Replay repairs; package still withheld |
| Verify final record/receipt/custody/audit bindings | Complete proof | Any mismatch quarantines the package |
| Return a release handle | Usable package | Handle streams only the exact verified package |

Package construction can precede custody completion because its bytes remain in
workflow-owned quarantine. A package reference, signature, or lifecycle export
count alone is never release authority. Cancellation after a durable step
returns no handle; exact replay resumes and verifies the same result.

## Import ordering

| Step | Durable or observable state | Failure posture |
|---|---|---|
| Accept an opaque bounded staged-input reference | Quarantine only | No Web parsing, CAS reference, or case mutation |
| Isolated worker parses frames and enforces all limits | Quarantined staged streams | Unknown, trailing, compressed, or oversized data rejected |
| Verify canonical schema, detached signature, key trust/revocation, every digest, lineage, custody proof, and checkpoint | Complete import verification report | Partial or offline-incomplete proof cannot import |
| Load target case and obtain fresh import authority | Exact local scope decision | Source signature never grants local authority |
| Publish each artifact through immutable ingestion | Encrypted CAS objects and exact ingestion receipts | Published partial progress is not caller-visible |
| Append acquisition/transfer custody for every artifact | Complete local lineage and custody links | No imported reference released before all links verify |
| Commit final import record and receipt, append/verify audit | Durable complete import | Lost response recovers exact receipt |
| Return imported references | Usable local references | Only the final verified artifact set is returned |

If publication or custody stops midway, exact progress records identify the
same package and completed artifacts. Replay verifies them and continues; a
different package cannot adopt them. Reconciliation may retain or abandon
unreferenced encrypted objects under existing CAS rules, but never manufactures
a completed import. Imports do not preserve foreign authorization as local
authority and do not silently merge a foreign case into an existing case.

## Retention and legal hold ordering

Retention eligibility is computed from the exact current case record, tenant
policy digest, trusted time, artifact-set digest, and any stricter artifact or
imported-manifest constraint. A later eligible date wins. Expiry makes deletion
eligible; it does not schedule or authorize deletion by itself.

Placing a hold commits the case-lifecycle transition first, then records the
exact lifecycle receipt and affected artifact set in custody. This is safe on
interruption because the restrictive state is already effective. Releasing a
hold also commits the audited lifecycle transition first, but CYB-77 keeps a
durable `release_hold` operation incomplete until custody records and verifies
the release. Export and physical deletion must reject an incomplete hold
operation even if the case snapshot says the hold is false. A replay repairs
custody; it never recreates or silently skips the lifecycle transition.

Hold placement/release needs fresh authority and exact expected case revision.
History is immutable. A hold cannot be backdated, scoped by free-form path, or
released by possessing its prior receipt. Imports and exports apply current
tenant policy to holds; deletion is unconditionally denied while any applicable
hold is active or its release operation is incomplete.

## Deletion and physical disposition ordering

Deletion is a multi-boundary operation, not a direct CAS delete:

1. validate the exact artifact set, reason digest, approval, actor, deadline,
   case revision, policy, expected custody head, and idempotency identity;
2. prove retention elapsed, no applicable hold or incomplete hold release, and
   a complete verified custody/audit interval;
3. obtain fresh irreversible-action authority and append custody `delete /
   authorized` for that exact set;
4. apply the case-lifecycle `delete` transition, yielding the immutable
   attributable tombstone and exact lifecycle receipt;
5. re-read the tombstone, authorization, hold/retention facts, and artifact set,
   then ask the narrow disposer to process only those encrypted objects;
6. durably retain the disposition attestation, including per-object outcomes,
   mechanism, key revision, attempted/completed times, and canonical digest;
7. append custody `delete / completed` bound to the prior authorization,
   lifecycle receipt, artifact-set digest, and disposition-attestation digest;
8. verify custody and audit, then atomically commit the final deletion receipt.

The disposer is idempotent: an object already proven absent under the same
intent converges on the same safe outcome, while an unexpected locator, object,
key revision, or partial result fails closed. The workflow reports physical
disposition only for the mechanism the adapter actually verified. A tombstone
alone never claims bytes were destroyed. Conversely, a disposition interruption
never restores the case or releases evidence; exact replay finishes evidence
and custody accounting.

Deletion preserves metadata needed for audit immutability and provenance. A
retention policy may require preservation of the signed export manifest,
detached signature, public verification keys, disposition attestation, and
verification reports after evidence bytes are gone. Private-key destruction is
a separate key-custody action and cannot be inferred from object removal.

## Failure and adversarial matrix

| Fault or attack | Required outcome |
|---|---|
| Unknown schema/version/field, malformed frame, duplicate or trailing bytes | Reject before release or publication; safe denial audit where identity is valid |
| Oversize count/frame/package, compressed input, archive media, traversal/link/device attempt | Isolated worker rejects; no extraction, CAS reference, or existence oracle |
| Manifest, signature, key revision, revocation, artifact, lineage, component, custody, or checkpoint tamper | Invalid proof; no import/export result |
| Cross-tenant/case, destination/source, actor, policy, or classification substitution | Binding denial; no artifact disclosure or adoption |
| Stale case, hold, retention, custody head, approval, policy, or revocation state | Fresh authorization required; old decision unusable |
| Changed idempotency replay | Denied; no progress or receipt adoption |
| Signer/verifier/package worker/publisher/custody/audit unavailable | No usable package/import; exact durable recovery only |
| Cancellation or timeout at any precommit boundary | No claimed success; quarantine and progress reconciled by exact replay |
| Cancellation after durable mutation | No result release; bounded independent completion or exact recovery |
| Partial multi-artifact import | Published objects remain hidden; replay completes identical package or reconciliation retains/abandons safely |
| Hold or retention bypass attempt | No physical disposition; denial is attributable and audited |
| Disposer partial failure or lost response | No completed-deletion claim; exact attestation recovery and retry |
| Audit/custody failure after package or disposition | Success withheld; replay repairs the same deterministic records without repeating effects |
| Concurrent identical command | One canonical operation/receipt; all callers converge after verification |
| Concurrent changed command | One optimistic winner; loser conflicts and must reload/reauthorize |
| Corrupt progress, receipt, tombstone, custody, audit, or attestation | Quarantine affected operation; never synthesize or skip state |

Errors expose only typed bounded reason codes and non-sensitive digests. Package
bytes, evidence, raw destination/source values, signer errors, storage paths,
key material, and backend text are cleared or redacted before crossing the
boundary.

## Migration, recovery, and rollback

V1 adds validated lifecycle metadata kinds and package schemas to the existing
guarded repository; no new SQL table is required. Readers, validators, isolated
worker protocol, public verification keys, and recovery tooling ship before
writers. SQLite restart and concurrent tests prove exact progress and receipts;
the PostgreSQL adapter must pass the same store conformance suite before that
deployment profile is promoted.

Recovery scans only bounded known progress records. It verifies the original
command, quarantine identity, package digest, CAS receipts, case state, custody
head, audit proof, disposition attestation, and current authority before
advancing. It never edits an immutable record, guesses whether deletion
happened, imports partial evidence, or releases a package from quarantine.

Rollback disables new imports, exports, hold releases, and physical disposition
while retaining V1 readers, progress/receipts, quarantined packages, encrypted
objects, case tombstones, custody/audit history, signing and verification public
keys, revocation history, and disposition attestations. Restrictive holds stay
effective. Forward recovery resumes from the exact verified phase; rollback
does not downgrade a package, reopen a tombstoned case, or fabricate missing
custody.

## Privacy and key-custody assumptions

Manifests and reports omit evidence bytes, raw destinations/recipients, policy
source, approval values, credentials, private keys, and redaction mappings, but
their identifiers, digests, lengths, classifications, timestamps, lineage, and
component versions remain sensitive. They inherit case access, encryption,
backup, retention, and audit controls. Low-entropy purposes, reasons,
destinations, and recipients are normalized, domain-separated, and nonce-bound
before hashing to resist dictionary recovery.

Signing private keys live only in the configured signer boundary. Public keys,
key revisions, trust decisions, revocation intervals, and old verify-only keys
remain available for the longest applicable package/evidence retention period.
Rotation never rewrites an old signature. Backup and disaster recovery must
restore public verification history and audit checkpoints before package
release or import resumes.

## Verification plan

The focused gate must prove:

1. strict schema and canonical Go wire synchronization for every V1 payload;
2. pathless streaming framing, exact byte/count/type limits, and rejection of
   compression, trailing data, duplicates, traversal, links, and nested input;
3. complete manifest/signature/key/revocation/artifact/lineage/component/custody
   and audit-checkpoint verification, including an offline verifier;
4. exact export authorization-before-release and import verification-before-
   publication ordering;
5. retention, hold placement/release recovery, authorized deletion ancestry,
   disposition attestation, tombstone, custody, and audit immutability;
6. invalid input, denial, stale state, revocation, changed replay, cancellation,
   timeout, dependency faults, partial work, concurrency, restart, and recovery;
7. plaintext, key, path, destination, mapping, and backend-error confidentiality;
8. narrow-port reflection, Web-process and forbidden-import architecture tests;
9. SQLite integration plus repeated, race, vet, static, file-size, Markdown,
   secret, license, dependency, SBOM, provenance, and full baseline CI gates.

## Requirement trace

| Requirement | Frozen design evidence |
|---|---|
| FR-028 | Import/export, retention, legal hold, deletion, signed manifests, verification, progress, and receipts are explicit governed operations. |
| FR-029 | The canonical export manifest binds every artifact digest, complete lineage, policy/model/tool versions, custody proof, audit checkpoint, and detached signature. |
| SEC-037 | Current retention and hold facts block disposition; deletion is freshly authorized, tombstoned, attested, custody/audit chained, explicit, attributable, and preserves immutable history. |
| SEC-042 | Import uses an isolated non-Web worker, forward-only bounded pathless framing, closed media types, no V1 compression, strict schema/signature verification, and no extraction surface. |

No unresolved V1 design, authority, package, release-order, or disposition
decision remains for implementation.
