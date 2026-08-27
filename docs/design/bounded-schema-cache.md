# Bounded schema cache

| Field | Value |
|---|---|
| Issue | COH-E12-03 / CYB-88 |
| Requirements | FR-045, FR-054 |
| Upstream contract | COH-E12-01 / CYB-85 query connector SPI |
| Authority boundary | COH-E05 policy, approvals, audit, E-stop |
| Evidence boundary | COH-E10 immutable provenance and custody |
| Decision | Memory-only, tenant/source/version scoped, bounded, and fail closed on stale metadata |

## Boundary and threat model

The schema cache accelerates read-only connector discovery without becoming an
authority source. It accepts only immutable, validated, complete CYB-85 schema
pages from a narrow loader port. It cannot execute queries, call arbitrary HTTP,
fetch credentials, evaluate policy, or widen a resource allowlist.

| Threat or ambiguity | Fail-closed invariant |
|---|---|
| Cross-tenant or cross-source reuse | Cache identity binds organization, tenant, source, sorted resource scope, capability digest, adapter version, and schema version. |
| Policy or case confusion | Callers retain responsibility for current authority admission; the cache stores no actor, case, approval, policy, or authorization state and grants none. |
| Stale vendor metadata | Entries are usable only before both their configured TTL and trusted capability validity. Expired data is removed and is never served during loader failure. |
| Partial discovery | Only complete schema pages with no continuation handle are cacheable. Partial pages and cursors are denied. |
| Provenance loss or substitution | The immutable CYB-85 schema-page digest, schema digest, and provenance digest are preserved and revalidated on every insertion. |
| Unbounded memory | Configuration sets positive entry, total-byte, per-entry-byte, and TTL caps; oversize values are rejected and eviction is deterministic. |
| Concurrent duplicate loads | One in-flight load exists per exact key; waiters remain independently cancelable and receive mutation-safe copies. |
| Broad invalidation | Invalidation requires an exact organization, tenant, and source, with optional exact version bindings; it cannot flush unrelated tenants or sources. |
| Secret disclosure | The memory-only cache holds validated schema metadata and digests, never credentials, query text, result rows, URLs, vendor tokens, or raw vendor errors. |
| Cancellation or timeout | Context cancellation is typed and never inserts a late result for that caller; an independently bounded load may complete only for still-active waiters. |

## Identity, freshness, and eviction

The canonical key contains organization ID, tenant ID, source ID, a digest of
the exact sorted resource allowlist, capability digest, adapter version, and
schema contract version. The case and actor are deliberately excluded because
schema metadata is tenant/source data, not case authority. Reusing a cache hit
still requires the caller's separate current policy and query admission.

An entry records its immutable validated page, insertion time, expiration time,
byte size, and a monotonic access sequence. Effective expiration is the earlier
of configured TTL and the trusted capability `valid_until`. Expired entries are
removed before capacity eviction. Remaining capacity eviction selects the least
recently accessed entry, using canonical key order as a stable tie-break.

## Loader and failure semantics

The loader receives a validated cache request rather than a URL, credential, or
vendor SDK object. A miss initiates at most one load for the exact key. Loader
errors are mapped to closed typed codes: invalid input, denied, canceled,
timeout, unavailable, conflict, or internal. Raw vendor error text is not
persisted or exposed.

Fresh hits do not contact the loader. Expired hits behave as misses. If refresh
fails, the former value remains unusable. Recovery retries from immutable input
and may insert only a complete page whose request, source, schema version,
capability/version binding, and provenance satisfy the exact request.

## Invalidation and compatibility

Exact tenant/source invalidation is idempotent. Optional capability, adapter,
and schema-version selectors narrow it further. Source reconfiguration,
credential rotation, adapter upgrade, capability refresh, or vendor schema
change must invalidate affected entries before new work is admitted.

Changing key fields, freshness meaning, completeness rules, provenance
bindings, or stale-data behavior is security-sensitive and requires a new major
cache contract plus migration and adversarial evidence. Rollback clears the
process-local cache; it never rewrites persisted query or provenance records.
