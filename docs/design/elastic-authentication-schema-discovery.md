# Elastic authentication and schema discovery

| Field | Value |
|---|---|
| Issue | COH-E13-01 / CYB-93 |
| Parent | COH-E13 / CYB-20 |
| Requirements | FR-045, FR-046, FR-047, FR-048, FR-053, FR-054, SEC-013, NFR-008 |
| Decision | A typed, read-only Elastic discovery adapter with broker-owned credentials, pinned source identity, exact target resolution, and bounded field capabilities |

## Vendor contract

COH uses only three typed Elastic operations in this leaf:

1. `GET /` establishes cluster identity and build metadata. Elastic requires the
   cluster `monitor` privilege. A self-managed deployment must match the
   configured `cluster_uuid`, supported version range, build flavor, and build
   snapshot policy. Elastic Serverless reports a compatibility version, so COH
   instead pins its configured deployment identity, TLS peer identity, build
   flavor `serverless`, and cluster UUID.
2. `GET /_resolve/index/{name}?expand_wildcards=open` resolves only configured
   local allowlist expressions. Elastic requires `view_index_metadata`.
3. `POST /{index}/_field_caps` requests an explicit, sorted field allowlist
   against the exact resolved concrete targets with `allow_no_indices=false`,
   `ignore_unavailable=false`, `expand_wildcards=open`, and
   `include_unmapped=true`. Elastic requires both `view_index_metadata` and
   `read`.

The adapter does not expose an arbitrary method, URL, header, query parameter,
JSON body, script, runtime mapping, index filter, or vendor SDK request. It does
not create or manage API keys. Operators provision a dedicated read-only API
key or equivalent credential and register only its secret reference with COH.

Authoritative references:

- [Elastic cluster information API](https://www.elastic.co/guide/en/elasticsearch/reference/current/info-api.html)
- [Elastic resolve index API](https://www.elastic.co/docs/api/doc/elasticsearch/v8/operation/operation-indices-resolve-index)
- [Elastic field capabilities API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-field-caps)
- [Elastic security privileges](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-privileges.html)

## Trust boundaries

Configuration is trusted only after normal COH configuration admission. It
binds one source ID to an exact HTTPS origin, deployment kind, expected cluster
UUID, supported version range, adapter version, credential class/reference,
TLS peer identity digest, resource allowlist, field allowlist, and finite
request, response, target, field, page, and lifetime limits. Redirects, proxies
selected by ambient environment, plaintext HTTP, userinfo, fragments, and
non-root base paths are denied.

The credential broker owns credential resolution and lifetime. Each vendor call
consumes a fresh single-use lease bound to the organization, tenant, case, task,
action digest, exact target digests, operation, audience, and TLS identity.
Credential bytes exist only inside the broker callback and the bounded request
construction; they are never retained by the adapter, logged, returned, placed
in an error, or serialized into evidence.

The transport authenticates the configured TLS peer before releasing the
credential. It enforces TLS 1.3, system or configured trust roots, exact
hostname verification, the configured peer identity digest, finite deadlines,
bounded response bodies, no redirects, and cancellation. The adapter records
only redacted request/response digests and credential-lease decision digests.

## Target admission

Caller scope may narrow the configured resource allowlist but cannot widen it.
Each configured expression and requested resource is a canonical lower-case
Elastic name or a narrowly placed suffix wildcard. COH rejects empty values,
commas, colons, `_all`, bare `*`, leading dots, traversal-like segments,
percent-encoding, control characters, and remote-cluster syntax.

Resolution is performed once per discovery attempt. The returned aliases, data
streams, and concrete indices are normalized, sorted, deduplicated, and checked
against both the requested expression and configured allowlist. Hidden,
restricted, closed, frozen, system, or unexpected targets fail the whole
attempt. Alias and data-stream membership is bound into the provenance digest;
a target substitution between resolution and field discovery is a conflict,
not a partial success.

Field capabilities are requested only for exact resolved targets and configured
fields. The adapter never sends wildcard fields, runtime mappings, or an index
filter. Unknown response keys are tolerated only within vendor-defined field
metadata; identity, type, searchable/aggregatable, and per-index exception
fields are decoded strictly and bounded. A field with conflicting Elastic types
becomes separate deterministic schema entries only when COH has an explicit
lossless type mapping; otherwise discovery fails as unsupported.

## Capability, paging, and caching

`Probe` emits a `coh.query-capability/v1` snapshot only after identity, version,
scope, and transport checks succeed. It asserts read-only, schema discovery,
validation, paging, cancellation, statistics, and finite hard limits. The
source identity digest binds the admitted configuration, TLS peer, deployment,
cluster UUID, build identity, resource expressions, fields, and privilege
profile.

Discovery deterministically chunks sorted target/field pairs before requests,
never after an oversized response. Each page contains at most 4,096 canonical
COH schema entries and is bound to request, capability, source identity,
resolution, chunk, response, lease decision, and transport receipt digests.
Opaque cursors contain no vendor token and expire with the capability. Cursor
state is adapter-owned, single-source, request-bound, and idempotently
recoverable. The schema cache keys by tenant, source, resource scope, and
capability digest; incomplete pages never become a complete cached snapshot.

## Failure, recovery, and rollback

Authentication denial, privilege denial, TLS or cluster mismatch, unsupported
version, target drift, malformed or oversized response, partial shard result,
timeout, cancellation, or audit failure fails closed with a bounded redacted
reason. No previous cache entry is silently relabeled current.

Retry begins from identity and target resolution under fresh authority and a
new credential lease. An exact repeated request produces the same normalized
schema and provenance inputs; a changed cluster, build, TLS identity, target
membership, capability, or configuration requires a new capability and cache
key. Concurrent identical loads may coalesce only at the existing schema-cache
boundary.

Rollback disables the Elastic source for new probes and discovery, revokes
outstanding credential leases, expires adapter cursor state, and preserves
existing signed evidence. It does not delete vendor data, credentials, cache
history, or evidence. Re-enablement requires fresh identity discovery and
authority.

## Compatibility policy

The initial production adapter supports self-managed Elastic major versions 8
and 9 only after recorded-fixture qualification for the exact minor family.
Unknown majors, snapshots, and unqualified minors fail closed. Serverless is a
separate deployment profile because Elastic documents its reported version as
compatibility metadata. Adding endpoints, authentication schemes, target
kinds, wildcard behavior, type mappings, or relaxed decode rules requires a
contract review and new adversarial fixtures.
