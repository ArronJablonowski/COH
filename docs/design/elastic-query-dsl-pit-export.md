# Bounded Elastic Query DSL and PIT export

| Field | Value |
|---|---|
| Issue | COH-E13-03 / CYB-94 |
| Parent | COH-E13 / CYB-20 |
| Dependencies | COH-E12, COH-E13-01 |
| Requirements | FR-048, FR-049 |
| Decision | Strictly decode and rebuild a small Query DSL subset, validate it on every exact target shard, and export through an adapter-owned PIT using stable `search_after` and one-row lookahead |

## Vendor facts and version policy

Elastic validates a Query DSL body without executing it at
`POST /{index}/_validate/query`. Validation normally selects one random shard
per index; COH sends `all_shards=true` and rejects any failed shard or invalid
result. Validation supports wildcard and all-index targets, so COH supplies only
the exact sorted concrete indices resolved through the current CYB-93 source
identity and sends `allow_no_indices=false`.

A PIT is a lightweight view of an index state. It is opened explicitly at
`POST /{index}/_pit`. Searches that use a PIT must call `POST /_search` without
an index path, routing, or preference. PIT searches with `search_after` must
keep the query and sort unchanged, carry every sort value from the prior last
hit, and use the newest PIT ID returned by each response. PIT searches add a
unique `_shard_doc` tiebreaker. PITs consume cluster resources and should be
closed with `DELETE /_pit` as soon as export finishes; expiry remains the
backstop after an uncertain close or process loss.

Search may otherwise return partial data after timeout or shard failure. COH
sends `allow_partial_search_results=false` and still requires
`timed_out=false`, zero failed shards, no failure records, and no partial or
skipped remote-cluster state. Scroll, `from`, and total-hit counting are not
used. `track_total_hits=false` avoids unnecessary complete counts; export
completeness comes from exhausting the stable PIT traversal within admitted
bounds.

V1 is qualified only for the same self-managed Elastic minor families admitted
by CYB-93. Serverless, cross-cluster search, async search, scroll, slicing,
aggregations, collapse, suggest, rescore, knn/retrievers, runtime mappings,
scripts, stored queries, and vendor experimental fields are unsupported.

Authoritative references:

- [Validate a query](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-validate.html)
- [Open a point in time](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-open-point-in-time)
- [Paginate search results](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/paginate-search-results)
- [Run a search](https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html)
- [Close a point in time](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-close-point-in-time)
- [Boolean query](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-bool-query)
- [Term-level queries](https://www.elastic.co/docs/reference/query-languages/query-dsl/term-level-queries)

## Caller JSON and strict subset

`Query.NativeText` is one strict JSON object. The decoder rejects duplicate
keys, unknown members, trailing input, non-integer JSON numbers, excessive
input/tokens/depth/clauses/terms, and every value that is not valid for its
current schema type. It accepts exactly these Query DSL-shaped nodes:

```text
match_all: {}
term:       { <logical-field>: <scalar> }
terms:      { <logical-field>: [ <scalar>, ... ] }
range:      { <logical-field>: { gt|gte|lt|lte: <scalar>, ... } }
exists:     { field: <logical-field> }
match:      { <logical-field>: { query: <string>, operator: "and" } }
match_phrase:{ <logical-field>: { query: <string>, slop: 0 } }
bool:       { filter?: [node,...], should?: [node,...],
              must_not?: [node,...], minimum_should_match?: 1 }
```

At least one effective clause is required except for explicit `match_all`.
`should` requires `minimum_should_match: 1`; the value is forbidden without
`should`. All arrays are non-empty. Boolean depth and total clauses are capped.
`term`/`terms` require an operator-configured exact field. `range` requires an
integer, IP, or timestamp field and at least one bound; contradictory or mixed
duplicate bounds are denied. Timestamp values are canonical UTC nanosecond
timestamps, never date math or time-zone input. `exists` requires a configured
filterable field. `match` and `match_phrase` require an explicitly configured
text-searchable string field, use the deployment's qualified analyzer, and
forbid fuzziness, analyzer selection, leniency, boosting, zero terms, prefix,
and synonym controls.

Field names are logical COH names. Wildcards, metadata fields, vendor names,
quoted paths, dynamic fields, nested paths not explicitly configured, lookup
terms, query strings/KQL, regex/fuzzy/prefix/wildcard queries, IDs, percolate,
geo/shape/vector queries, named queries, scoring controls, and every unknown
query type fail as unsupported. No caller object is copied into a vendor body.

## Canonical plan and mandatory policy

Strict decoding creates a typed logical AST. COH validates fields against the
current exact schema and operator definition, then rebuilds canonical vendor
Query DSL from typed nodes and configured vendor names. Scalar types remain
lossless; canonical JSON and a type-tagged AST digest eliminate ambiguous JSON
representations.

The caller AST is placed in filter context. COH independently builds mandatory
filters containing the admitted half-open UTC range (`gte`/`lt`) and optional
exact tenant/source terms. The final query is a canonical `bool.filter` whose
children are the mandatory filters followed by the rebuilt caller filter.
Caller input cannot supply or replace this wrapper. The plan binds the exact
query, capability, schema, source identity, organization, tenant, case, actor,
resource, authority/policy/audit digests, projection, row/page/byte/time caps,
query/filter digests, sort, and validator version.

The projection is a configured list of logical fields mapped to exact vendor
fields. Searches send `_source=false` and an explicit `fields` list; date fields
request `strict_date_optional_time_nanos`. A field response must be present
only when allowed and contain at most one scalar value. Object, ignored,
highlight, inner-hit, explanation, score, version, sequence, script, and
unrequested source output is rejected.

Sort is operator-owned and identical for every page: configured event timestamp
ascending, configured stable event identifier ascending, then `_shard_doc`
ascending. The two configured fields must be sortable and returned with every
hit. `_shard_doc` is valid only inside the owned PIT. Each hit must return the
exact sort tuple with lossless types; the next request uses the tuple from the
last row released to the caller.

## Lifecycle and bounded pagination

Validation first rechecks the current capability and schema, resolves exact
indices, locally compiles the plan, and calls `_validate/query` on all exact
target shards. Vendor validation is defense in depth; it cannot widen the local
allowlist. An accepted plan is cached only until its query deadline and contains
no native JSON text.

Execution rechecks identity and target membership, opens a PIT with a short
keep-alive no later than the query deadline, stores the PIT ID only inside the
bounded adapter state, and returns a digest-only opaque `query_job` handle.
`Poll` performs the first search. `NextPage` requires the exact current opaque
`result_page` handle and performs subsequent searches.

Each vendor search asks for `min(page_rows, remaining_rows) + 1` hits. The extra
hit is lookahead evidence only and is not released. If present, the released
page is incomplete and receives a next-page handle bound to the current plan,
job, page number, latest PIT digest, and last released sort tuple. If absent,
the traversal is complete even when the released page exactly fills its cap;
COH closes the newest PIT before reporting vendor-confirmed completeness. This
avoids an empty proof page and distinguishes exact-cap completion from explicit
truncation. A lookahead beyond the admitted final row/page/byte/time budget
causes shared runtime protective cancellation and explicit truncation.

The adapter atomically replaces the stored PIT ID when a search response
returns a new one. Replay of the exact current operation is coalesced. Changed,
old, substituted, cross-query, cross-actor, or cross-case handles fail. Page and
usage counters are cumulative and monotonic. Process-local plan/job/page state
has fixed capacity, expires by the query deadline, and retains at most one
bounded lookahead result per in-flight operation.

## Failure, cancellation, and recovery

Caller cancellation and deadlines propagate through JSON decoding, schema and
vendor validation, PIT open/search/close, hit decoding, shared runtime, and
evidence recording. Explicit or protective cancellation closes the latest PIT.
Only a valid close response with `succeeded=true` confirms cancellation; a
failed or lost response is uncertain. Close is idempotently replayable against
the same stored PIT until confirmed or expired.

Timeout, any shard failure, malformed or rotated-away PIT state, missing/changed
sort values, changed target identity, response overflow, or process loss never
produces complete evidence. A PIT that reports missing shards is not replaced
mid-export, because a new PIT would describe a different snapshot. Recovery
starts a fresh attempt under current authority and records the prior attempt as
uncertain/partial/truncated as applicable. It never silently resumes from a
new snapshot.

PIT IDs, native JSON, literals, rows, credentials, and vendor errors are absent
from metadata and logs. Evidence contains only encrypted query/result artifacts
and redacted query, plan, filter, schema, capability, target, PIT, sort, page,
request/response, lease, transport, close, completeness, and usage digests.

Rollback disables new Query DSL validation and PIT creation, revokes connector
leases, attempts bounded close for active local PITs, lets uncertain PITs expire,
and preserves durable evidence. Grammar expansion, new query types, changed
sort/projection rules, new endpoints, relaxed completeness, or incompatible
digest/handle changes require new conformance fixtures and contract review.
