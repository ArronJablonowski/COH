# Security Onion Connect and structured OQL

| Field | Value |
|---|---|
| Issue | COH-E13-04 / CYB-90 |
| Parent | COH-E13 / CYB-20 |
| Dependencies | COH-E12 |
| Requirements | FR-046, FR-050 |
| Decision | Qualify the live OpenAPI contract, compile a small typed OQL subset, and expose only bounded read-only event queries through the shared query runtime |

## Official boundary and version policy

Security Onion Connect is an enterprise API exposed by the manager. API clients
authenticate through OAuth 2.0 client credentials and receive granular
permissions outside OAuth scopes. The query adapter requires only
`events/read`; roles, write permissions, and administrative permissions are not
accepted as substitutes. Token exchange uses `POST /oauth2/token` with HTTP
Basic client credentials and the exact form body
`grant_type=client_credentials`. API calls use the returned bearer token and a
pinned manager CA. Tokens and client secrets are secret values and never enter
configuration documents, query plans, receipts, errors, or logs.

The documented query operation is `GET /connect/events/`. It requires `query`,
`range`, `zone`, `format`, `metricLimit`, and `eventLimit`. The response is an
array of query results containing criteria, elapsed time, events, metrics,
total-event information, and an error array. The API promises results only up
to the requested maximum or a smaller backend maximum. It documents no stable
continuation token for this operation. A successful HTTP status is therefore
not completeness evidence: any response error, reached event/metric cap,
reported total larger than released results, or unexplained response drift is
partial, truncated, or unknown.

Security Onion warns that releases may add response fields and recommends
client generation from the current API definition. COH consequently qualifies
the exact live OpenAPI bytes before enabling the adapter. Qualification binds a
canonical OpenAPI digest, manager identity, adapter version, supported
operations, required parameters, response media types, and security scheme.
Safe additive response properties may be ignored only inside explicitly typed
success envelopes; path, method, parameter, security, type, or required-field
drift denies qualification. A changed digest requires requalification even when
the compatibility check passes. No unqualified version family is assumed.

Authoritative references:

- [Security Onion API setup, RBAC, and OAuth](https://docs.securityonion.net/en/3/main/connect-api/)
- [Security Onion Connect API reference](https://docs.securityonion.net/en/3/main/connect-api/so-api-reference.html)
- [Security Onion OQL behavior](https://docs.securityonion.net/en/3/main/dashboards/)

## Reachability allowlist

The generated/verified transport has no generic request function. Its complete
network surface is:

```text
POST /oauth2/token       obtain a short-lived client-credentials token
GET  /connect/info/      bind the live manager/product identity when qualified
GET  /connect/events/    run one bounded event/metric query
```

The OpenAPI verifier may observe other paths but never turns them into callable
operations. It explicitly rejects any attempt to select non-GET Connect data
operations or paths under assistant, case, client, config, detection, grid,
job, packet, playbook, role, stream, user, or other unlisted families. Cases,
detections, grid administration/metrics, configuration, API-client
administration, packet metadata, PCAP creation/download, arbitrary job output,
and every mutation are unreachable even if the credential is overprivileged or
the live specification later adds them.

The manager base URL is operator-configured as one canonical HTTPS origin. User
info, fragments, cleartext HTTP, redirects, proxy-derived origins, dynamic
hosts, IP/host substitution, and caller-supplied paths are denied. TLS uses an
operator-pinned root set and minimum protocol/cipher policy. Every request binds
the current source, organization, tenant, case, actor, authority/policy/audit
digests, operation, and OpenAPI qualification digest into a redacted receipt.

## Structured OQL subset

`Query.NativeText` is a strict JSON document describing a logical query; it is
not caller OQL. Duplicate keys, trailing input, unknown members, floats where
integers are required, excessive input/tokens/depth/clauses/terms, and invalid
schema types fail closed. V1 admits typed exact comparisons, bounded ranges,
existence predicates, and filter-only boolean composition against configured
logical fields. Optional output instructions are a configured event projection
and zero or more configured group-by fields. Caller-provided Lucene text,
regular expressions, fuzziness, boosts, proximity, wildcard field names,
unbounded wildcard values, OQL pipes, chart/display options, scripts, and
unknown operations are unsupported.

The compiler maps logical fields to exact qualified vendor field names and
escapes every Lucene literal from its typed scalar value. It builds boolean
parentheses and uppercase `AND`/`OR`/`NOT` tokens itself. It independently adds
mandatory configured tenant/source predicates and never accepts a caller
replacement for them. The admitted UTC interval is not embedded as caller OQL;
it is rendered only into the Connect API's fixed range parameters.

The operator owns the pipeline. Event mode emits a configured `table` projection
and deterministic `sortby` fields. Metric mode emits only configured `groupby`
fields. Sort/group fields must exist in the current schema and carry explicit
permissions. The caller cannot add, reorder, or repeat pipe segments. The
canonical typed AST, rendered OQL, range parameters, projection/grouping,
event/metric limits, schema, capability, qualification, scope, authority, and
hard limits are digest-bound in an immutable plan. Native JSON and literals are
discarded after validation.

## Time and limit semantics

COH renders the admitted interval in UTC with a single fixed Go-compatible
format and sends `zone=UTC`; caller zone and format input do not exist. The
rendered range is derived from canonical UTC timestamps and bounded by both the
query admission and adapter hard maximum interval. An inverted, empty, stale,
future, or overlong range is denied.

`eventLimit` and `metricLimit` are positive and clamped by the query admission,
operator configuration, and live qualification. Response bytes, elapsed time,
events, metric groups, rows, pages, slices, request rate, and cost are also
bounded by the shared runtime. V1 issues one Connect events request per admitted
slice. It releases no result until the typed response and evidence transition
are durable.

With no documented continuation cursor, a cap-filled response is not complete.
It is explicitly truncated and records whether the event cap, metric cap,
reported total, backend error, or unknown backend ceiling caused the decision.
Time bisection is permitted only after pinned fixtures prove half-open boundary
behavior, deterministic stable identity, complete deduplication, and monotonic
coverage for the qualified appliance contract. Until then, the safe recovery is
a new policy-bounded query or explicit operator-approved smaller interval—not a
silent assertion that adjacent slices form a complete export.

## Response, runtime, and evidence

The response decoder requires HTTP success, JSON media type, a bounded body,
and one explicitly typed result envelope. Any non-empty `errors` collection,
invalid timestamps, criteria mismatch, negative/overflow count or duration,
missing event identity/time, malformed event payload, unsafe dynamic value,
metric shape drift, or multiple unexplained result envelopes fails closed.
Unknown additive envelope fields are ignored only after qualification and are
never copied to metadata.

Events are projected into configured logical scalar fields. Source/index names,
raw payloads, scores, query criteria, errors, and unrequested dynamic fields are
not released. Metrics are normalized only for configured aggregation keys and
numeric counts. Completeness distinguishes complete, partial, truncated, and
unknown; HTTP success alone never selects complete.

The adapter implements the common query connector lifecycle with bounded
process-local validated plans, execution flights, results, exact replay
coalescing, opaque handles, deadline expiry, shared rate/bounds control, and
protective cancellation. Because the documented events call is synchronous and
has no cancellation endpoint, cancellation stops the local HTTP request and is
confirmed only before a response is accepted; lost or ambiguous transport state
is uncertain. A successful response can be replayed from bounded local state
until recorded, then its native data is destroyed.

Evidence binds the qualification/OpenAPI digest, source identity, typed plan,
rendered-query digest, range digest, limit decision, request/response receipts,
completeness, truncation reason, usage, bounds decision, execution, and result
digests. Client IDs/secrets, bearer tokens, Authorization headers, native JSON,
OQL literals, event rows/payloads, response errors, and vendor bodies are absent
from metadata and logs. Native query and result evidence use the shared
encrypted evidence path.

## Failure, recovery, rollout, and rollback

Authentication or privilege denial, TLS/pin failure, OpenAPI drift, response
warning/error, timeout, cancellation, body overflow, schema drift, backend cap,
or process loss cannot produce vendor-confirmed completeness. Retry before an
accepted response uses a fresh token and current qualification. After uncertain
transport state or adapter-state loss, recovery creates a fresh attempt under
current authority; it never invents a continuation.

Rollout starts disabled. It requires an enterprise-enabled Connect API, a
dedicated API client with exactly `events/read`, pinned manager trust, a passing
live OpenAPI qualification, current schema/capability/bounds admission, the
public conformance suite, and a bounded canary. Rollback disables new Security
Onion validation, revokes connector leases and the API client, expires local
state, and preserves durable evidence. New endpoint families, OQL operators,
permissions, response shapes, pagination/slicing behavior, or incompatible
digest/plan changes require contract review and new fixtures.
