# Query evidence and provenance

| Field | Value |
|---|---|
| Issue | COH-E12-05 / CYB-92 |
| Requirement | FR-053 |
| Upstream contracts | COH-E12-01 connector lifecycle, COH-E12-02 bounds admission, COH-E12-04 runtime broker |
| Evidence boundary | COH-E10 encrypted evidence ingestion and immutable custody |
| Decision | Persist an encrypted native-query artifact and a redacted, digest-chained query-evidence manifest |

## Boundary and data classification

Query evidence has two deliberately separate layers.

1. The exact native query text is a case-scoped evidence artifact. It is sent
   through the narrow COH-E10 ingestion adapter and is encrypted before durable
   publication. Its plaintext digest and length are bound into the query
   manifest, but its text, locator, key reference, and ciphertext metadata are
   never copied into query state, SQL projections, audit events, or errors.
2. The query-evidence manifest is a redacted immutable record. It contains only
   tenant-scoped identifiers, closed enums, bounded counters and timestamps,
   and cryptographic digests binding the admitted query, source, scope, bounds,
   validator, execution, result, completeness, cancellation, and prior record.

Result rows remain COH-E10 evidence artifacts. The manifest binds their exact
artifact digest and ingestion provenance; it never embeds rows. Classification
and retention are inherited from the case/evidence decisions and may be
narrowed by current authority, never selected or weakened by the query runtime.

## Threat model and fail-closed invariants

| Threat or ambiguity | Required behavior |
|---|---|
| Native query or result leakage | Persist content only through encrypted artifact ingestion. Manifest, audit, errors, and canonical transition identity contain digests and bounded metadata only. |
| Artifact substitution | Native-query and result bindings include artifact digest, length, media type, classification, manifest digest, manifest provenance digest, and ingestion receipt digest. Any changed binding is conflict. |
| Query/source/scope substitution | The first record binds query ID/digest, execution/attempt, organization, tenant, case, actor, source, bounds decision, and validator version/digest. Later records must match exactly. |
| Missing native artifact | No query-start record may commit until encrypted ingestion returns a validated binding matching the requested plaintext digest and length. |
| Chain fork, gap, or reorder | Append requires an exact expected head. Revision increases by one and `previous_provenance_digest` equals the current head. Genesis alone has no predecessor. |
| Lost append response | A canonical transition ID and idempotency key recover the committed record. Exact retry replays it; changed reuse conflicts. |
| Concurrent transition | The append-only store performs atomic expected-head compare-and-swap. Exactly one competing successor wins; callers reload and reconcile rather than overwrite. |
| Partial or truncated result | Completeness is a closed value and can only stay equal or degrade according to the CYB-87 terminal record. No transition may relabel partial, truncated, canceled, failed, or uncertain as complete. |
| Cancellation uncertainty | Intent and vendor outcome are separate digests. Requested-but-unconfirmed cancellation is `uncertain`, never `canceled` or `complete`. |
| Dependency outage or caller cancellation | Return a typed retryable error promptly. Never infer a commit, artifact publication, completion, or cancellation outcome from a lost response. |
| Generic storage or execution bypass | Ports expose only native-query/result artifact ingestion, query-evidence expected-head append/recovery, audit append, and time. They expose no executor, SQL, filesystem, CAS, or connector methods. |

## Canonical record and transitions

One stream exists for each tenant-scoped query attempt. Its immutable identity
binds `case + query_id + query_digest + execution_digest + attempt_id`. The
genesis `started` record additionally binds the admitted bounds, source, actor,
validator, encrypted native-query artifact, and initial runtime-session digest.

Subsequent records are one of `validated`, `page`, `result`, `truncated`,
`partial`, `cancellation_requested`, `canceled`, `uncertain`, or `failed`.
Each record binds the exact CYB-87 session revision/digest and cumulative
statistics. Page/result records also bind the encrypted result artifact and its
COH-E10 provenance. Terminal records bind explicit completeness and, when
applicable, cancellation intent/outcome digests.

Canonical JSON uses explicit schema and contract versions, UTC RFC3339Nano
timestamps, decimal integer counters, closed enums, sorted object fields, and
SHA-256 digests. The provenance digest is computed over the full redacted record
with its own digest field empty. The transition ID is computed from immutable
stream identity, revision, predecessor, event, runtime-session digest, artifact
binding, completeness, statistics, and cancellation bindings. It is safe for
idempotency and contains no plaintext.

## Ports, idempotency, and recovery

`NativeQueryIngestor` accepts an exact digest, length, media type,
classification, lineage, and a cancellation-aware forward-only source. It
returns only a redacted artifact binding. A production adapter translates this
to COH-E10 `evidenceingest.Command` with `QuerySource` and `QueryComponent`.

`EvidenceStore` exposes `LoadHead`, `Recover`, and `Append`. `Append` receives
the exact expected head, transition ID, and complete canonical record. The
store must atomically reject a stale head and must return the prior record for
an exact transition replay. A different record or transition under an existing
idempotency key is conflict.

The controller always recovers before side effects. Query-start then ingests
the native query and appends genesis. If ingestion succeeds but append fails,
the immutable artifact remains valid and the same idempotency key recovers it;
retry cannot create a different lineage. For all later transitions, the
controller loads and validates the complete head before forming one successor.
It appends audit only after a durable record is recovered or committed. Audit
failure is explicit and retryable; it cannot roll back or mutate evidence.

## Retention, redaction, compatibility, and rollback

Query artifacts and manifests use the case classification and COH-E10 retention
and legal-hold controls. Deletion, export, redaction, and custody operations are
owned by the existing evidence lifecycle; this component cannot bypass them.

Changing canonical identity, record events, completeness precedence, statistic
semantics, artifact binding, chain rules, or idempotency behavior requires a new
major contract plus migration and adversarial evidence. Rollback stops new
records while preserving every committed artifact and chain entry. It never
rewrites history or upgrades an incomplete outcome.
