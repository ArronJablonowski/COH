# Bounded Elastic Query DSL and PIT export contract v1

This contract publishes the deliberately small Query DSL-shaped JSON subset
implemented for COH-E13-03. COH strictly decodes caller JSON into a typed AST,
validates logical fields and operators, and rebuilds a canonical vendor query.
Caller JSON is never forwarded as a generic Elastic request body.

The accepted roots are `match_all`, `term`, `terms`, `range`, `exists`,
`match`, `match_phrase`, and filter-only `bool`. The operator definition fixes
logical-to-vendor field mappings, per-operator permissions, the safe projection,
stable timestamp/identifier ordering, and hard row/page/page-size ceilings.
COH independently adds the admitted time range and configured tenant/source
filters. Scripts, runtime fields, scoring controls, aggregations, wildcards,
query strings, geo/vector search, caller sorting, caller projection, and unknown
members fail closed.

## Operations

Rollout starts disabled. Qualify the Elastic minor family through CYB-93, load
a current exact schema, validate the secret-free definition, and run
`scripts/verify_elastic_querydsl.sh`. A bounded canary must use the dedicated
read-only principal and current query-bounds admission. Monitor typed denials,
PIT close uncertainty, shard/timeout rejection, process-local capacity, and
vendor latency. Never log PIT IDs, native JSON, literals, rows, credentials, or
vendor bodies.

Validation calls `_validate/query` for every exact resolved target shard.
Execution re-resolves targets, opens an adapter-owned PIT, and pages with one-row
lookahead and the immutable sort `timestamp`, stable identifier, `_shard_doc`.
Each released page consumes one logical shared-runtime work slice, so effective
pages are capped by the admitted page and slice limits. Exact operation replay
is deterministic and concurrent replay is coalesced.

Rollback disables new Query DSL validation and PIT creation, revokes connector
leases, attempts bounded close of locally owned PITs, lets uncertain PITs expire,
and preserves durable redacted/encrypted evidence. Recovery after process loss
or missing PIT state starts a new attempt; COH never resumes against a different
snapshot or reports unknown state as complete.

## Compatibility

V1 is limited to the CYB-93-qualified self-managed Elastic minor families and
the synchronous JSON validate/PIT/search/close APIs. Serverless, cross-cluster
search, async search, scroll, slicing, `from`, caller-controlled sort/source,
partial results, and experimental endpoints are unsupported. Grammar,
projection, sort, endpoint, completeness, or digest/handle changes require new
conformance evidence; incompatible definition or plan shapes require a new
major contract.
