# Bounded Elastic ES|QL contract v1

This contract admits a deliberately small read-only ES|QL language for
COH-E13-02. COH parses caller text into a typed AST and rebuilds the vendor
query; it never forwards arbitrary ES|QL. The accepted pipeline is one logical
`FROM` source followed, in order, by optional `WHERE`, `KEEP`, `SORT`, and
`LIMIT` commands. Every emitted query has an explicit safe projection, stable
sort, and positive final limit.

`elastic-esql-definition.schema.json` describes the secret-free operator
definition. Logical COH fields map to explicit Elastic fields and carry
separate projection, filter, and sort permissions. The definition also fixes
the logical resources, timestamp field, optional tenant/source filter fields,
stable ordering, and a hard row ceiling. It contains no credential, endpoint,
header, script, runtime mapping, or generic request body.

Caller literals are positional parameters. COH builds the mandatory Query DSL
filter independently from the pipeline and binds its digest into the validated
plan. At minimum the filter applies the admitted half-open UTC range; configured
tenant and source predicates are exact terms. The transport resolves the one
logical source through the current CYB-93 capability and sends only exact local
indices to synchronous `POST /_query` with `allow_partial_results=false`.

## Operations

Rollout starts disabled. Qualify the Elastic minor family through CYB-93, load a
current schema, validate the definition, run `scripts/verify_elastic_esql.sh`,
and execute a bounded test query under current bounds admission. Monitor typed
denial reasons, process-local capacity, vendor latency, and unknown outcomes;
never log native text, parameters, rows, credentials, or vendor bodies.

On vendor outage before a response, the same prepared attempt may be retried by
the caller. Once a response is accepted, exact concurrent replay is coalesced
and the prepared plan is destroyed. Loss of adapter state after execution is
reported as unknown, never complete. Process-local plans, executions, and
results have fixed capacity and expire no later than the query deadline.

Rollback disables new ES|QL validation while leaving CYB-93 discovery
available, revokes connector leases, expires local state, and preserves durable
redacted/encrypted evidence. Re-enable requires current capability, schema,
authority, and policy.

## Compatibility

V1 supports only the qualified synchronous JSON ES|QL endpoint. Async handles,
cross-cluster search, Serverless, partial results, columnar output, profiling,
directives, functions, joins, forks, enrichments, aggregations, and every
unrecognized command are unsupported. Expanding the grammar, endpoint set,
type conversions, filter behavior, or digest model requires new conformance
evidence; an incompatible plan shape requires a new major contract.
