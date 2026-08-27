# Chain-of-custody records

| Field | Value |
|---|---|
| Issue | COH-E10-03 / CYB-79 |
| Requirements | FR-020, FR-023, SEC-020, EVAL-013 |
| Chain scope | One append-only sequence per organization, tenant, and case |
| Lineage scope | Directed acyclic graph of immutable artifact and manifest digests |
| Audit anchor | Deterministic event in the tenant tamper-evident audit chain |
| Status | Implemented; closure verification in progress |

## Purpose and boundary

The custody boundary proves who performed or authorized an evidence operation,
when it occurred, in which case, against which immutable artifact and manifest,
from which prior custody state, and under which current policy and revocation
state. It records acquisition, access, transformation, redaction, transfer,
export, hold, deletion authorization, and completed deletion without storing
raw evidence or sensitive destination values.

Custody is not a second copy of the tenant audit log. The two structures prove
different facts and cross-bind each other:

- the tenant audit chain proves global ordering and coverage of security events;
- the case custody chain proves case-local evidence handling order; and
- the artifact-lineage graph proves ancestry from immutable source manifests to
  every derived artifact.

Every committed custody record has a deterministic redacted audit event. Its
evidence digests bind the record's domain-separated precommit digest, prior
head, artifact and manifest, and authority decision. The final record stores
the resulting audit-event digest; its record and chain hashes therefore bind
that exact event without a circular hash dependency. A custody result is not
released until the event is durably appended. Independent verification must
validate both chains and their exact cross-reference.

The model, provider, connector, and executor cannot append custody directly.
They submit typed inputs to a trusted workflow. The workflow receives no raw
credential, policy source, evidence byte stream, arbitrary metadata map,
filesystem path, network client, shell, executor, or generic callback.

## Frozen invariants

1. A chain is keyed by exact organization, tenant, and case. Sequence one uses
   the all-zero genesis hash; every later record names the exact prior sequence
   and chain hash.
2. The chain head, immutable record, and idempotency receipt commit atomically.
   No API permits record or head deletion, rewriting, reordering, or insertion.
3. Every record binds a fresh case snapshot, actor identity and revision,
   operation and phase, trusted occurrence time, artifact and encrypted-manifest
   references, authority and revocation state, prior chain link, and provenance.
4. Artifact content is identified only by a CAS-verified SHA-256 digest and
   length. A manifest reference is resolved and verified before append.
5. A transformation or redaction names every parent artifact and parent
   manifest digest and the immutable child artifact and manifest. A parent set
   is non-empty, sorted, unique, same-case, and cannot contain the child.
6. Access, transfer, and export bind a purpose digest. Transfer and export also
   bind a destination or recipient digest; raw destinations and identities are
   excluded from custody, audit, logs, and errors.
7. Hold and deletion records bind the current case-lifecycle revision and legal
   hold state. Completed deletion cannot be recorded without a prior exact
   deletion authorization and cannot bypass retention or legal hold.
8. Exact replay obtains current authority, verifies the stored record and both
   chains, repairs a missing deterministic audit append, and returns the
   original receipt. Changed idempotency reuse is denied.
9. Success is fail closed. Cancellation, timeout, corrupt state, stale state,
   unavailable verification, authority denial, revocation, storage conflict, or
   audit failure yields no usable custody result or evidence release.
10. Custody metadata never contains evidence bytes, manifest plaintext, raw
    source or destination values, approval material, credentials, or free-form
    operator text.

## Operation and phase matrix

| Operation | Allowed phase | Required evidence binding | State or lineage effect |
|---|---|---|---|
| `acquire` | `completed` | Ingestion receipt, artifact and encrypted manifest, source identity digest | Establishes the first custody link for an artifact; no duplicate acquisition under another receipt |
| `access` | `authorized` | Artifact, manifest, purpose, actor, current case and policy | Must commit and audit before plaintext is released to the authorized caller |
| `transform` | `completed` | Parent set, child artifact and manifest, component/version digests | Adds a child lineage node; never changes any parent |
| `redact` | `completed` | Parent, derived artifact, rule/reason/mapping/approval digests | Reserved for CYB-78; source remains immutable and resolvable under separate authority |
| `transfer` | `authorized`, `completed` | Artifact, manifest, destination/recipient and transfer-receipt digests | Authorization precedes release; completion binds the resulting external receipt |
| `export` | `authorized`, `completed` | Export-manifest/package, destination and detached-signature digests | Authorization precedes release; completion binds the independently verifiable package |
| `place_hold` | `completed` | Case-lifecycle receipt, reason digest, affected artifact-set digest | Records the exact lifecycle revision that made the hold effective |
| `release_hold` | `completed` | Case-lifecycle receipt, reason and authority digests | Records the exact lifecycle revision that released the hold |
| `delete` | `authorized`, `completed` | Reason, lifecycle revision, artifact set, prior authorization for completion | Authorization is required before deletion; completion records the durable tombstone, never fabricated byte destruction |

Denied attempts are mandatory tenant-audit events but are not successful links
in the custody chain. The audit event binds the rejected command digest,
operation, actor, case, policy decision, revocation state, and safe reason code.

## Typed boundary

| Port | Allowed surface | Explicit exclusion |
|---|---|---|
| `Authority` | Authorize an exact metadata-only custody request | Policy source, approval value, credential, evaluator handle |
| `CaseStore` | Load the minimum current lifecycle snapshot and exact receipt | Lifecycle mutation, retention mutation, generic repository access |
| `EvidenceResolver` | Resolve and verify committed artifact, manifest, and ingestion receipt facts | Evidence bytes, raw keys, arbitrary CAS path or deletion |
| `Ledger` | Load head, resolve an exact immutable receipt, atomically append, and read an ordered verification interval | Update, delete, skip sequence, repair, generic query |
| `Auditor` | Append one bounded deterministic audit event and expose verification proof | Evidence or manifest content, mutable log access |
| `Clock` | Current canonical UTC time | Timer callback or scheduler |

The published command and decision contracts use closed operation and phase
values. Optional operation-specific values are explicit nullable fields with a
strict operation matrix; there is no map of extensions. Public records are
owned copies and have no executable fields.

## Canonical bindings

The command binding covers schema and contract version, request and
idempotency identity, exact case, actor and revision, operation and phase,
artifact and encrypted-manifest references, parent references, source,
purpose, destination/recipient, rule/reason/mapping, external receipt,
case-lifecycle receipt, deletion authorization, policy, expected case and
custody revisions, and deadline.

The authority request adds the current case state, classification, retention,
hold, provenance, and revision; verified artifact/manifest facts; and the exact
current custody head. The decision repeats the complete command and head
binding and adds outcome, bounded reason, decision identity/revision, current
revocation digest, issue/expiry times, and policy digest. Any mismatch, expired
decision, later-than-command expiry, or stale head is denial.

For hashing only, the record chain hash is replaced with the all-zero digest.
The stored chain hash is domain-separated SHA-256 over the canonical record
preimage. The record digest separately binds the complete canonical stored
record. The immutable receipt binds the command, authority decision, record
digest, chain hash, audit-event digest, and provenance digest.

## Append and release ordering

| Step | Durable or observable state | Failure posture |
|---|---|---|
| Validate command and deadline | None | Typed invalid input; no dependency call |
| Recover idempotency identity | Existing exact receipt or none | Changed replay denied before artifact resolution |
| Load case and custody head | Read-only snapshot | Missing, deleted, corrupt, or stale state denied |
| Resolve artifact, encrypted manifest, and required prior receipt | Internally verified facts only | No custody append or caller-visible plaintext |
| Obtain fresh authority | Exact bound decision | Denial/revocation audited; no append or release |
| Construct canonical record and receipt | Memory only | Invalid binding denied |
| Atomically append record, advance head, and store receipt | Complete custody link | Lost response recovered by exact idempotency replay |
| Append deterministic tenant audit event | Custody link exists; success withheld | Replay repairs audit without another custody append |
| Verify stored record and audit binding | Complete cross-chain proof | Integrity failure stops affected writes and release |
| Return receipt or release authorized evidence | Usable success | Only after every prior step succeeds |

For acquisition and derived artifacts, CAS publication may precede custody
append, but the higher-level workflow withholds the new reference until custody
and audit succeed. A crash can therefore leave an encrypted, already-referenced
artifact receipt awaiting its custody link, never a released reference with an
unrecorded acquisition. Exact replay completes the same link.

## Replay and concurrency

The idempotency digest is scoped to the exact case. Recovery compares the
complete command binding in constant time, validates the immutable receipt,
recomputes the record and chain hashes, resolves artifact and manifest facts,
obtains current authority, and verifies the corresponding audit event. It does
not append a second custody record.

The caller supplies an expected case revision and expected custody sequence and
head hash. Concurrent different commands at one head have one winner; the loser
returns a typed conflict and must reload and obtain fresh authority. Concurrent
identical commands with the same idempotency identity converge on one receipt.
An idempotency identity reused with any changed field is denied. A later event
cannot use a decision bound to an earlier head.

## Failure and adversarial matrix

| Boundary or fault | Required evidence |
|---|---|
| Malformed/unknown field or operation-field mismatch | Reject before storage, authority, resolver, or audit success |
| Missing/cross-tenant/cross-case artifact or manifest | No disclosure, append, or existence oracle; safe denial audit only |
| Digest, length, manifest, receipt, lineage, record, or head tamper | Integrity denial; affected writes stop |
| Stale actor, case revision, custody head, policy, approval, or revocation | No append; stale exact decision cannot be reused |
| Authority denial or unavailable authority | No successful link or evidence release; denial is safely audited when possible |
| Cancellation or deadline at every boundary | No partial record/head/receipt transaction; committed result is recovered exactly |
| Metadata write, transaction, or lost response | Complete atomic link or no link; exact recovery never duplicates sequence |
| Audit append or checkpoint failure | Custody may be committed, but no usable result; replay repairs the same event |
| Concurrent exact replay | One record and receipt; every caller sees the same verified result |
| Concurrent changed commands | One head winner; every loser conflicts and must reauthorize |
| Invalid transform parent, cycle, missing child, or mismatched manifest | No lineage node or custody link |
| Transfer/export destination substitution | Decision binding mismatch; no authorized release |
| Hold/retention bypass or deletion without prior authorization | Denied; no deletion-completed record |
| SQLite restart and guarded-store recovery after commit boundaries | Ordered chain and receipt recover without fork, gap, or duplicate; PostgreSQL rollout repeats the same store conformance suite |
| Verifier input insertion, deletion, reorder, mutation, truncation, or checkpoint change | Independent verification fails at the exact affected boundary |

## Independent verification

Verification starts from genesis or a separately trusted tenant audit
checkpoint and consumes the complete ordered case interval. It proves:

- exact scope, contiguous sequence, prior link, canonical record digest, chain
  hash, durable head, and immutable receipt;
- every artifact and manifest digest/length through the encrypted CAS resolver;
- every transformation parent and child edge, absence of cycles, and exact
  manifest ancestry;
- operation/phase legality, deletion authorization ancestry, and lifecycle
  receipt bindings;
- the matching deterministic tenant audit event, audit chain link, checkpoint
  signature, signing-key revision, and revocation interval; and
- that every custody-affecting audit event has exactly one custody record and
  every custody record has exactly one matching audit event.

The verifier rejects mutation, insertion, deletion, reordering, truncation,
forks, broken lineage, orphan children, invalid manifests, unknown keys,
checkpoint tampering, and custody/audit coverage disagreement. It reports an
error and never invents a missing link or treats a partial interval as complete.

The implemented `custody.Verifier` is read-only. It starts at the all-zero case
genesis, consumes the complete ordered interval, reconstructs every immutable
receipt, checks idempotency recovery and prior-authorization ancestry, resolves
artifact and manifest facts, regenerates the deterministic audit binding, and
compares the terminal record with the durable head. It has no authority, append,
repair, key, evidence-byte, or release capability.

## Checkpoint and signing-key custody

The `Auditor` boundary owns tenant audit-chain and checkpoint verification. A
production implementation must validate the checkpoint signature with the
configured public-key revision, prove that the key was trusted and not revoked
at the checkpoint interval, and reject unknown algorithms, revisions, gaps, or
revocation ambiguity before returning an `AuditProof`. The custody verifier
accepts only the resulting bounded proof and records the final checkpoint ID
and digest in its verification report.

Checkpoint private keys never enter the custody workflow or verifier. They stay
in the audit signer boundary and follow that component's rotation, backup,
dual-control, and destruction procedure. Public verification keys, revisions,
revocation statements, and old verify-only material remain available for the
full custody-retention period. A complete genesis-based walk without a covering
checkpoint may prove structural consistency, but its report is `incomplete`;
it is not a substitute for the required external trust anchor.

## Export verification boundary

Custody export authorization and completion bind the artifact, encrypted
manifest, purpose, destination or recipient digest, policy, prior authorization
receipt, and external receipt digest. They do not claim that an export package
signature or package bytes were independently verified. CYB-77 owns that
package format, detached signature, verification key, and offline verifier.
Before release, that workflow must require both its valid package proof and the
matching valid custody report and authorization receipt. Neither proof may be
used to infer or repair the other.

## Recovery and operational response

- A lost metadata response is recovered by reading the exact immutable
  idempotency receipt; recovery never advances the head again.
- An audit failure after metadata commit withholds success. Exact replay obtains
  fresh authority, verifies the stored interval, and repairs the deterministic
  audit event without adding a custody record.
- A stale competing append reloads the head and reauthorizes; it never retries
  with the old decision.
- Corrupt, forked, truncated, or unverifiable state is quarantined. Operators
  restore a complete storage and audit backup to a separate recovery target,
  verify from genesis or a trusted checkpoint, and only then resume writes.
- Recovery never edits a record, synthesizes a receipt, skips a sequence,
  replaces an audit event, or releases evidence while verification is partial.

## Privacy assumptions

Custody metadata contains identifiers, classifications, timestamps, lengths,
and stable digests. Although it excludes evidence bytes, manifest plaintext,
credentials, raw destinations, and free-form operator text, these values remain
sensitive because digests and timing can be linkable. Storage, logs, verifier
reports, backups, and exported proofs therefore inherit the case's access and
retention controls. Destination, recipient, source, reason, mapping, approval,
and external receipt values are normalized and hashed before entering the
boundary; callers must use domain-specific nonces where low-entropy values
would otherwise permit dictionary recovery. Error and audit surfaces expose
only bounded reason codes and digests.

## Migration and rollback

V1 uses the existing guarded metadata repository with a new validated
`custody_record` kind for a case head, immutable sequence records, and
idempotency receipts. SQLite and PostgreSQL therefore require no new SQL table.
The kind validator and reader ship before the writer is enabled. Existing
ingestion receipts are not retroactively described as custody records; cutover
records a bounded, explicit acquisition link before an existing artifact is
first released through a custody-aware path.

Rollback disables new custody-sensitive releases and appends but retains the
V1 reader, record/head/receipt data, CAS objects, manifests, audit chain, and
historical verification keys. It never rewrites records into an older format,
deletes unknown fields, synthesizes a link, or releases evidence without the
custody gate. Forward recovery resumes from the exact verified head.

## Requirement trace

| Requirement | Frozen design evidence |
|---|---|
| FR-020 | Every custody link resolves and binds the strict encrypted artifact manifest and its provenance digest. |
| FR-023 | Collection, transformation, redaction, export, and deletion are closed operations that extend the case chain and, where applicable, the immutable lineage graph. |
| SEC-020 | Custody records are append-only, exact-tenant/case scoped, hash-chained, cross-bound to the existing append-only tenant audit chain, and cannot be updated or deleted. |
| EVAL-013 | The independent verifier consumes bytes, manifests, lineage, custody and audit chains, receipts, heads, and signed checkpoints and rejects every specified mutation class. |

No unresolved design decision remains for implementation. CYB-78 owns governed
redaction policy and mapping semantics, while CYB-77 owns signed packages,
retention enforcement, holds, and physical deletion. Both consume this frozen
custody record interface and must not weaken its append, authority, or
verification invariants.
