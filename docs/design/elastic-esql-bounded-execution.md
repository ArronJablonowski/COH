# Bounded Elastic ES|QL execution

| Field | Value |
|---|---|
| Issue | COH-E13-02 / CYB-91 |
| Parent | COH-E13 / CYB-20 |
| Dependencies | COH-E12, COH-E13-01 |
| Requirements | FR-046, FR-049 |
| Decision | Parse and rebuild a small parameterized ES|QL subset; send an independently bound mandatory Query DSL filter and reject every unqualified command or partial result |

## Vendor facts and version policy

Elastic's ES|QL API accepts a query string and a separate Query DSL `filter`.
The filter is applied before the ES|QL pipeline and can alter the columns
available when it eliminates complete indices. The synchronous endpoint is
`POST /_query`; the async endpoint, added in 8.13, is `POST /_query/async` and
returns its handle in response headers. Both require index `read`. Elastic
supports `allow_partial_results`; COH always sends it as `false` and still
verifies response completeness because a cluster-level default must not control
COH evidence semantics.

ES|QL evolves rapidly across Elastic releases. The CYB-93 qualified minor
family therefore gates this leaf. V1 uses only the synchronous JSON endpoint on
qualified self-managed 8.x/9.x families. Async execution, Serverless, locale,
time-zone directives, cross-cluster search, columnar output, profiling,
approximation, tables, and vendor experimental features are unsupported until
separately qualified.

Authoritative references:

- [Elastic ES|QL REST API](https://www.elastic.co/docs/reference/query-languages/esql/esql-rest)
- [Elastic ES|QL basic syntax](https://www.elastic.co/docs/reference/query-languages/esql/esql-syntax)
- [Elastic async ES|QL API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-esql-async-query)
- [Elastic FORK command](https://www.elastic.co/docs/reference/query-languages/esql/commands/fork)

## V1 grammar

COH does not pass through arbitrary ES|QL and does not try to track the full
vendor grammar. A cancellation-aware tokenizer and parser accepts exactly:

```text
FROM <logical-resource>
[ | WHERE <bounded-expression> ]
[ | KEEP <field> [, <field> ...] ]
[ | SORT <field> [ASC|DESC] [, <field> [ASC|DESC] ...] ]
[ | LIMIT <positive-integer> ]
```

Commands are case-insensitive on input and emitted uppercase. Their order is
fixed and each may occur at most once. The input source is one logical COH
resource ID, not an Elastic expression. CYB-93 resolves it to the exact local
concrete target set after current capability and source-identity checks.

Fields must exist in the current schema and be configured for the command.
Quoted or backtick field identifiers, wildcards, metadata fields, computed
names, aliases, qualified index names, and request-selected vendor fields are
denied. `KEEP` is always emitted explicitly; omission selects the configured
safe default projection rather than every vendor column. `SORT` receives a
stable configured tiebreaker when needed.

The bounded expression grammar supports parentheses, `AND`, `OR`, `NOT`, the
comparators `==`, `!=`, `<`, `<=`, `>`, and `>=`, configured fields, and scalar
string, integer, boolean, IP, or UTC timestamp literals. It denies functions,
subqueries, arrays, named parameters, user placeholders, arithmetic, regex,
KQL/Lucene strings, and null-dependent semantics in v1. COH converts every
literal into an Elastic positional parameter; no caller literal is copied into
the vendor query text.

Directives, semicolons, comments, control characters, triple strings, multiple
pipelines, `FORK`, `FUSE`, `LOOKUP JOIN`, `ENRICH`, `ROW`, `SHOW`, `TS`,
`METRICS`, `SAMPLE`, `RERANK`, `COMPLETION`, `GROK`, `DISSECT`, `MV_EXPAND`,
`STATS`, `INLINE STATS`, `EVAL`, `DROP`, `RENAME`, and every unknown command
fail as unsupported. Parentheses inside expressions cannot introduce a source
command or pipeline.

## Canonicalization and mandatory policy

Parsing produces a typed AST. Validation binds the exact query, capability,
schema, organization, tenant, case, actor, source, resource, UTC half-open time
range, limits, authorization/policy/audit digests, and qualified adapter/source
identity. Canonical vendor ES|QL is generated only from this AST.

The final command is always `LIMIT n`, where `n` is the minimum of the admitted
row limit, runtime-profile limit, adapter hard limit, and any lower caller
limit. Zero, negative, non-decimal, overflowing, repeated, non-final, or
expression-based limits are denied. Removing or changing the final limit after
validation changes the canonical query digest and fails execution admission.

The Query DSL filter is a typed object built independently from the native
pipeline. At minimum it contains the admitted UTC range using `gte` and `lt` on
the configured timestamp field. Configured tenant/source predicates are added
as exact `term` filters. The filter digest is bound into validation, execution,
transport request, and evidence provenance. Caller text cannot supply,
replace, weaken, or omit it.

## Typed transport and result contract

The CYB-93 transport gains one typed `ExecuteESQL` operation. It always sends
JSON row output, `allow_partial_results=false`, `columnar=false`, the canonical
query, positional parameters, and mandatory filter. It exposes no arbitrary
body fields or headers and consumes a fresh credential lease bound to operation
`elastic.esql`, exact target digests, TLS identity, and query/action digest.

The response decoder bounds body bytes, column count, column-name/type length,
row count, cell nesting, aggregate decoded bytes, and duration. Columns must be
unique and within the validated projection. Each row must have exactly the
column count and a lossless COH type conversion. Unknown response structures,
shard/cluster failures, partial flags, target drift, row/byte/column overflow,
or vendor truncation fail explicitly; they cannot produce `complete` evidence.

Every allowed/denied validation and vendor call records only canonical query,
filter, parameter, request, response, lease-decision, transport, capability,
schema, source-identity, and result digests. Native text and rows follow the
encrypted CYB-92 evidence path. Vendor bodies, credentials, and raw errors are
not metadata or logs.

## Recovery, cancellation, and rollback

Caller cancellation and deadlines propagate through tokenization, parsing,
validation, credential dispatch, HTTP, response decoding, runtime accounting,
and evidence persistence. Because v1 is synchronous, a lost response has an
unknown vendor outcome and is not automatically re-executed. An operator or
workflow may submit a fresh attempt under current authority; evidence retains
both attempts and never infers equivalence from matching native text.

Rollback disables new ES|QL admission while leaving CYB-93 discovery available,
revokes connector leases, cancels local waits, and preserves encrypted query
and result evidence. Re-enable requires current qualified capability/schema and
fresh policy. Expanding the grammar, type conversions, endpoint set, partial
semantics, or parameter/filter behavior requires new conformance fixtures;
incompatible AST or digest changes require a new major contract.
