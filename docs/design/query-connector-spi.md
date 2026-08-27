# Read-only query connector SPI

| Field | Value |
|---|---|
| Issue | COH-E12-01 / CYB-85 |
| Requirements | FR-045, FR-054 |
| Contract version | `1.0.0` |
| Canonical profile | `COH-CJ-1` |
| Authority dependencies | COH-E05 policy/approval/audit |
| Evidence dependencies | COH-E10 immutable evidence and provenance |
| Analytical dependencies | COH-E11 normalized, temporal, entity, and projection contracts |

## Boundary decision

`internal/domain/queryconnector.Connector` is the only vendor-neutral query
surface. It exposes capability probe, schema discovery, validation, execution,
polling, paging, cancellation, typed limits, explicit completeness, statistics,
and adapter-held opaque handle references. It does not expose generic HTTP,
headers, credentials, vendor tokens, mutation methods, or untyped option maps.

Authority is supplied as immutable actor, authorization, policy-decision, and
audit-reservation digests. A connector consumes those bindings; it cannot mint
authority or infer approval. Query scope names organization, tenant, case,
source, and allowlisted resources. Bounds and limits are explicit values, never
connector defaults. CYB-84 will enforce the UTC and policy semantics without
widening this SPI.

Opaque vendor handles remain inside an adapter. The shared contract carries
only a scoped handle ID and digest plus issue/expiry time, so credentials,
URLs, continuation tokens, and vendor payloads cannot cross the boundary.

## Lifecycle and evidence

The lifecycle is `Probe -> DiscoverSchema -> Validate -> Execute -> Poll ->
NextPage* -> Cancel?`. Unsupported capability, stale identity, missing
authority, invalid input, denial, timeout, cancellation, unavailable source,
or recovery conflict has a distinct typed error. Retrying creates a new attempt
while retaining the query identity and evidence lineage.

Completeness never derives from row count. Results separately report complete,
partial, truncated, and vendor-confirmed state with bounded reason codes and
statistics. Canonical query, validation, execution, page/result, cancellation,
and provenance digests become inputs to COH-E12-05 evidence records.

## Compatibility and migration

Readers accept only exact advertised schema and contract versions and reject
unknown fields. Adding an optional field still requires mixed-reader evidence;
removing, renaming, retyping, changing bounds, exposing opaque values, or
changing canonical semantics requires a new major schema contract. Migration
creates a new record with lineage and never rewrites evidence. Rollback restores
the prior reader and schema together.

This document records the boundary audit and initial Go surface. JSON schemas,
fixtures, canonical decoders, compatibility tests, and full verification
evidence are completed in the remaining CYB-85 short tasks.
