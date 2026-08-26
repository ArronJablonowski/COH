# Case lifecycle

| Field | Value |
|---|---|
| Issue | COH-E10-01 / CYB-76 |
| Requirements | FR-002, FR-028, SEC-014, SEC-015, SEC-037 |
| Contract | `coh.case-lifecycle/v1` / `1.0.0` |
| Data | Case metadata and immutable digest references only |
| Status | Design frozen for implementation |

## Purpose

The case lifecycle is the tenant- and case-scoped control boundary for creating,
classifying, assigning, holding, closing, reopening, exporting, and deleting a
case. Every command carries organization, tenant, case, actor, actor revision,
policy digest, expected case revision, idempotency key, and deadline. Missing or
inconsistent identity is rejected before authority or storage is called.

Deletion is a durable tombstone transition. It never erases audit history,
provenance, prior lifecycle receipts, or evidence custody records. Physical
artifact disposition, signed import/export bundles, and evidence retention are
implemented by later COH-E10 leaves and must consume this lifecycle state.

## State and classification

The closed case states are `open`, `closed`, and `deleted`. The closed
classifications are `public`, `internal`, `confidential`, and `restricted`.
Classification may stay unchanged or become more restrictive. Reducing a
classification is outside this leaf because it requires governed redaction and
separate authority in COH-E10-04.

Each current record binds:

- exact organization, tenant, and case UUIDv7 identifiers;
- creator, owner, and current assignee actor UUIDv7 identifiers;
- classification and lifecycle state;
- retention-policy UUIDv7 and UTC retain-until boundary;
- legal-hold state and the current hold reason digest, when held;
- last export manifest digest and export count;
- deletion reason digest and deleting actor, when tombstoned;
- policy, authorization, audit, intent, idempotency, prior-provenance, and
  provenance digests; and
- created, updated, and positive optimistic revision values.

The record carries references and digests, never evidence bytes, credentials,
policy source, approval tokens, signed bundle bytes, or executable capability.

## Operation matrix

| Operation | Required current state | Required input | Result | Local invariant |
|---|---|---|---|---|
| `create` | absent | classification, owner/assignee, retention policy and retain-until | `open` revision 1 | actor creates only the exact scoped case authorized by policy |
| `classify` | `open` or `closed` | classification | state unchanged | classification cannot become less restrictive |
| `assign` | `open` or `closed` | assignee actor | state unchanged | assignee is an explicit UUIDv7; no implicit current user |
| `place_hold` | `open` or `closed` and not held | hold reason digest | held | reason and actor are attributable |
| `release_hold` | `open` or `closed` and held | hold reason digest | not held | fresh authority is required; prior hold remains in provenance/audit |
| `close` | `open` | none | `closed` | no inferred or repeated transition |
| `reopen` | `closed` | none | `open` | fresh authority and optimistic revision are required |
| `export` | `open` or `closed` | immutable signed-manifest digest | state unchanged, export count advances | deleted cases cannot export; bundle construction remains COH-E10-05 |
| `delete` | `open` or `closed` | deletion reason digest | `deleted` tombstone | legal hold must be false and retain-until must have elapsed |

Every non-create command requires the exact current revision. Create requires
expected revision zero and an absent case. Unknown, repeated, skipped, stale,
cross-tenant, cross-case, less-restrictive, held-delete, early-delete, or
post-delete operations fail closed.

## Authorization boundary

The controller depends on a narrow `Authority` port. It passes a data-only
authorization request containing the canonical command digest, operation,
organization/tenant/case, actor and revision, current case revision/state,
requested classification or assignee, reason/manifest digests, legal-hold and
retention facts, policy digest, and deadline.

The authority returns a short-lived allow or deny decision binding every field,
a current revocation digest, issue/expiry times, and a canonical decision
digest. The controller recomputes the decision digest and rejects changed
scope, actor, operation, revision, policy, request, retention, hold, or expiry.
The port cannot supply policy source, credentials, connectors, executors,
callbacks, shell, HTTP, storage, or evidence content.

Authorization is evaluated for the initial command and again on exact replay.
A stored success never grants future authority. Denied or revoked replay
returns no lifecycle result.

## Durable transaction and replay

The `Store` port is limited to current load, receipt recovery, and optimistic
commit. Its repository adapter writes two records atomically through the
guarded `workflow.MetadataStore`:

1. the current case record at the exact organization/tenant/case key and next
   positive revision; and
2. an immutable receipt keyed by organization, tenant, case, and the hashed
   idempotency key.

The receipt preserves the complete resulting record. An exact replay recovers
that record, revalidates current authority, verifies its canonical provenance,
and repairs or repeats the deterministic audit append without applying the
transition again. Reusing the key for a different canonical command is denied.
A stale expected revision is a conflict. An ambiguous commit is recovered only
by the same immutable request; the controller never guesses whether a mutation
occurred and never silently merges state.

Case deletion uses the same put transaction and advances the revision to a
tombstone. The metadata record is not physically deleted. This preserves the
case identifier, deletion authority, attribution, policy, audit reference, and
provenance needed by SEC-037.

## Audit and provenance

Every allowed or denied operation produces a tenant- and case-scoped
tamper-evident audit event. Allowed results are not released until the resulting
record is durably committed and the corresponding audit append succeeds. Audit
unavailability therefore returns no successful result. If commit succeeded but
audit failed, exact replay repairs audit publication without applying a second
transition.

The event contains no case content. It binds operation, actor revision, request,
policy, authorization, revocation, prior record, resulting record, reason or
manifest digest, outcome, and timestamp. Each record's provenance digest chains
from the exact previous record provenance; revision one has an empty previous
digest. Export, hold, release, and deletion remain attributable even though
their content exists only as immutable external references.

## Cancellation, timeout, and failure semantics

| Condition | Typed result | Mutation or release behavior |
|---|---|---|
| malformed or unsupported command | `invalid_input` | no authority, store, or audit call |
| authorization denial, revocation, or binding drift | `denied` | no mutation; denial audit required |
| missing non-create case | `not_found` | no mutation |
| stale revision or concurrent winner | `conflict` | no overwrite or merge |
| caller canceled before commit | `canceled` | no successful result; retry exact command to recover |
| deadline elapsed before commit | `timeout` | no successful result; retry exact command to recover |
| ambiguous storage failure | `unavailable` | no claimed result; exact recovery only |
| audit unavailable after durable commit | `unavailable` | state remains durable; exact replay repairs audit |
| corrupt stored record, receipt, or provenance | `denied` | no result or mutation |

Dependency errors are mapped to safe typed errors without retaining raw backend
details. Audit uses a bounded cancellation-independent context so a caller
cannot suppress the required record after a committed transition.

## Migration and rollback

The generic guarded metadata repository already stores canonical typed
envelopes, so this leaf requires no SQL table change. The repository adapter
introduces the `case_lifecycle` metadata kind and deterministic current/receipt
keys. SQLite close/reopen tests must prove current state and exact receipts
survive process loss.

Cutover deploys code that recognizes the new kind before accepting lifecycle
commands. An older binary rejects the unknown kind and must not mutate or
delete it. Rollback therefore disables lifecycle writes while retaining
records for forward recovery; it never converts a tombstone into physical
deletion or reopens a case implicitly.

## Verification plan

The focused gate must prove:

1. strict published schema and canonical Go wire synchronization;
2. all nine operations and every legal/illegal state transition;
3. exact organization, tenant, case, actor, policy, deadline, and revision
   binding at authority, store, audit, and result boundaries;
4. classification monotonicity, explicit assignment, legal hold, retention,
   tombstone deletion, and post-delete denial;
5. idempotent replay, changed replay, stale/concurrent revision, ambiguous
   commit recovery, audit repair, and SQLite restart;
6. invalid input, policy denial, revocation, tamper, cross-scope access,
   cancellation, timeout, and dependency failure;
7. narrow-port reflection and forbidden-import architecture checks; and
8. repeated execution, race detection, vet, static analysis, file-size,
   Markdown-link, clean-diff, and full baseline CI.

## Requirement trace

| Requirement | Design evidence |
|---|---|
| FR-002 | Every command and record requires organization, tenant, case, and actor context. |
| FR-028 | Retention, legal hold, export-manifest references, and authorized tombstone deletion are first-class lifecycle state. |
| SEC-014 | Exact organization and tenant scope is checked at command, authority, storage key, audit, and result boundaries. |
| SEC-015 | Case-scoped keys and record validation prevent resolving or mutating another case. |
| SEC-037 | Hold and retention block deletion; deletion is explicit, attributable, audited, provenance-chained, and never erases immutable history. |
