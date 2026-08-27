# COH-E12 read-only query broker integration

| Field | Value |
|---|---|
| Parent | COH-E12 / CYB-16 |
| Leaves | COH-E12-01 through COH-E12-05 |
| Requirements | FR-045, FR-046, FR-047, FR-048, FR-053, FR-054, SEC-013, NFR-008 |
| Decision | One typed, admitted, bounded, read-only lifecycle with explicit completeness and encrypted provenance |

## Integrated lifecycle

1. COH-E12-01 accepts a typed query containing exact tenant/case/source scope,
   resource allowlist, capability/schema digests, native text, UTC half-open
   bounds, finite limits, authority digests, request time, and deadline. Its SPI
   exposes schema, validation, execution, poll, page, and cancellation records;
   it has no mutation or generic HTTP method.
2. COH-E12-03 resolves schemas only through bounded, tenant/source/capability
   cache keys. Expired, changed, partial, or oversized schema data cannot become
   current authority.
3. COH-E12-02 verifies fresh actor, source, allowlist, capability, policy,
   approval, revocation, audit, E-stop, scope, UTC interval, and limit facts.
   It emits an immutable allowed/denied decision before execution.
4. COH-E12-04 starts only from the exact allowed decision and validated
   execution. Its signed session binds organization, tenant, case, query,
   attempt, source, actor, profile, limits, counters, status, and prior state.
   Every external operation receives an authoritative rate reservation. Pages
   are withheld until their bounded transition is durably recorded.
5. COH-E12-05's prepared runtime recorder turns revision one into evidence
   genesis, encrypting native text through COH-E10. Later runtime revisions are
   appended by expected-head CAS. The redacted chain preserves query, validator,
   result digest, completeness, statistics, cancellation, and provenance.

## Cross-leaf invariants

- Scope, source, query, admission, execution, attempt, and case identities may
  never change between leaves. A mismatch fails closed before adapter work or
  persistence.
- Native text and result content use encrypted case-scoped evidence artifacts.
  Runtime state, repository envelopes, audit events, errors, and public
  manifests contain only bounded metadata and digests.
- `complete` requires vendor confirmation and no partial, unknown, cancellation,
  timeout, or cap condition. Partial and unknown observations can only preserve
  or reduce completeness.
- Runtime profiles can narrow admitted limits; they cannot widen them. Limit
  exhaustion with more vendor data is explicit `truncated`, and offending pages
  are not released.
- The only connector runtime methods are `Poll`, `NextPage`, and `Cancel`.
  There is no generic executor, shell, HTTP, SQL, filesystem, or write surface.
- A page or terminal result is not caller-visible until its signed runtime
  revision has been durably committed to the query-evidence chain.

## Compatibility and migration

Each leaf uses explicit schema and contract versions. Changing query identity,
scope, UTC-bound semantics, limit accounting, completeness precedence, runtime
session identity, evidence transition identity, or repository keying requires a
new major contract and adversarial migration evidence.

The v1 repository adds `query_evidence` metadata records: one mutable-by-CAS
head and immutable idempotency recovery records. Production rollout must
register this record kind and migration checksum before enabling queries. There
is no in-place rewrite of evidence. A future migration writes a new version,
verifies complete predecessor continuity, and retains the old chain through the
case retention/legal-hold lifecycle.

## Recovery and rollback

After process loss, the broker loads the last signed runtime/evidence state and
re-polls under fresh authority and a new rate reservation. A lost append response
is recovered by the exact idempotency record. Unknown vendor outcome remains
`uncertain`; recovery never infers completion or cancellation.

Rollback disables new query starts, attempts bounded cancellation of active
vendor jobs, and leaves encrypted artifacts and immutable evidence records in
place. It must not relabel partial, truncated, canceled, uncertain, or failed
records. Readers remain capable of decoding every retained v1 record.

## Privacy and operational limits

Classification, retention, legal hold, export, redaction, and disposition are
owned by COH-E10. Query code cannot weaken them. Native text may contain case
identifiers or sensitive detection logic and is therefore never searchable
plaintext. Result rows remain encrypted artifacts, not metadata columns.

Operational maxima are finite at every boundary: document sizes, native query
length, schema entries, resources, rows, bytes, duration, pages, slices, cost,
requests per minute, poll backoff, session capacity, cancellation wait, record
wait, and repository document size. Production rate authority and metadata CAS
must be shared across replicas; process-local counters are test-only.
