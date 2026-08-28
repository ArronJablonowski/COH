# Sentinel bounded query and slicing evaluation

| Field | Decision |
|---|---|
| Issue | CYB-100 / COH-E14-06 |
| Requirements | FR-052, FR-054, EVAL-016 |
| Dependencies | CYB-16, CYB-97, CYB-98 (Done) |
| Azure operation | `POST /v1/workspaces/{workspaceId}/query` only |
| Time model | mandatory absolute UTC `[start,end)` on every request and slice |
| Result policy | reject any response containing `error.code=PartialError`; release no partial rows |
| Evaluation | locked, sanitized, network-disabled corpus; five deterministic trials per task |

## Purpose and authority

This leaf completes the Microsoft Sentinel read-only query path and qualifies
the behavior that is most likely to create false-complete evidence: implicit
time ranges, service result limits, adjacent time slices, duplicate boundary
events, ambiguous timestamps, partial-success responses, retry, and
cancellation. The runtime consumes only a currently qualified CYB-97 workspace
and a currently accepted, audited CYB-98 Kusto validation admission. It cannot
mint authority, widen a scope or time range, select another workspace, accept
arbitrary HTTP, or treat a sanitized fixture as live-vendor qualification.

The common query request remains the authority-bearing record. Its actor,
organization, tenant, case, source, resource, capability, schema, absolute time
range, limits, requested time, deadline, policy decision, and audit reservation
are rechecked immediately before dispatch and bound into every request,
response, slice, merge, result, and cancellation digest.

## Authoritative Azure behavior and COH constraints

Microsoft documents the public Logs Query API as `v1`, with `query` required
and `timespan` optional. If omitted, the request can cover all available data;
COH therefore makes an absolute `start/end` timespan mandatory and rejects an
absent, relative, noncanonical, empty, reversed, or widened value. Microsoft
also states that the API timespan is applied in addition to time predicates in
KQL. COH supplies the exact POST body timespan, binds it to the immutable common
query and each slice receipt, and admits returned rows only under this local
half-open predicate on each selected table's qualified datetime column:

```text
timestamp >= datetime(start) and timestamp < datetime(end)
```

Kusto's `between` operator is inclusive at both ends, so it is not introduced
into the already signed CYB-98 canonical KQL. The runtime preserves that exact
audited AST output, submits a separately bound Azure timespan, and applies the
greater-than-or-equal/less-than row-admission rule before merge. Adaptive
slicing remains disabled unless runtime configuration binds a nonempty digest
of a qualification packet proving the configured Azure API/version honors the
same boundary coverage. Sanitized fixtures qualify the algorithm; a separately
authorized canary is required to qualify a live vendor boundary.

Microsoft documents a non-fatal Logs Query API failure as HTTP 200 containing
tables plus a OneAPI `error` whose code is `PartialError`. A 200 status is not
proof of completeness. COH rejects the complete response, releases none of its
rows, records only redacted error identity and digests, and marks the attempt
failed/unknown. The runtime does not expose a caller switch to consume partial
tables.

The public API supports server-side `Prefer: wait=<seconds>` and optional
statistics. COH always requests statistics, derives the integer wait from the
smaller of the query duration limit and remaining deadline, and also applies a
shorter client context deadline. Service ceilings remain informative upper
bounds; COH's configured limits are smaller and authoritative. HTTP 200,
returned row count below a limit, or absent continuation is never alone proof
of full coverage.

Primary informative references:

- [Logs Query API request format](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format)
- [Logs Query API response format and `PartialError`](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format)
- [Logs Query API timeouts and errors](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/errors)
- [Logs Query API prefer options](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/prefer-options)
- [Azure Monitor service limits](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits)
- [Kusto `between` operator (inclusive)](https://learn.microsoft.com/en-us/kusto/query/between-operator?view=microsoft-fabric)

Those documents describe vendor behavior. The COH PRD, common query contract,
qualified Sentinel/Kusto contracts, this frozen profile, and current policy are
normative and may impose stricter bounds.

## Closed execution boundary

The Sentinel runtime exposes the common connector SPI, not an HTTP client. Its
transport has one operation, `sentinel.query.post`, and one exact route:
`https://api.loganalytics.azure.com/v1/workspaces/{qualified UUID}/query`.
The workspace UUID, endpoint, `v1` API, token audience
`https://api.loganalytics.io/.default`, TLS root identity, credential lease,
and transport identity must match the current qualification. Redirects,
cross-workspace arrays, ARM or ingestion endpoints, GET queries, batch, generic
headers/options, and caller-provided URLs are denied.

The POST body is a closed object containing only canonical KQL and an absolute
UTC start/end timespan. Fixed headers are `Content-Type: application/json`,
`Prefer: include-statistics=true,wait=N`, and a broker-lent bearer token.
Neither KQL, literals, workspace identity, bearer material, rows, vendor bodies,
nor endpoints enter public errors or evaluation artifacts.

Strict response decoding requires one `PrimaryResult` table with exact bounded
columns compatible with the helper-declared output schema, rows of exact
arity/type, optional bounded statistics, and no unknown or duplicate JSON
members. `error` at any level, `PartialError`, malformed schema, extra result
tables, row/type drift, oversize input, invalid UTF-8, nonfinite numbers,
unbounded dynamic values, or a receipt/binding mismatch fails closed.

## Validation integration invariant

The common `ValidationResult.canonical_query_digest` binds the immutable common
query document consumed by `AdmitExecution`. The CYB-98 admission separately
retains the helper-produced bounded canonical KQL and its digest inside the
signed response, policy decision, audit proof, and validation provenance.
These are distinct digests and neither substitutes for the other. Runtime
integration must correct the current CYB-98 adapter result so the common field
contains the common query digest while continuing to verify and dispatch only
the separately bound canonical KQL. A mismatch in either binding denies
execution.

## Adaptive half-open slicing

The deterministic planner starts with exactly the admitted `[start,end)` range.
It may split only a slice whose successful response reaches the configured
per-slice row/byte threshold and whose duration is greater than the configured
minimum. Splitting uses the UTC nanosecond midpoint and produces exactly two
contiguous children `[start,mid)` and `[mid,end)`. Children are processed in
ascending time order. The planner never widens, overlaps, skips, rounds, or
creates an empty interval and never exceeds `MaximumSlices`, request-rate,
duration, byte, row, cost, or deadline limits.

Results from a threshold-reaching parent are not released; only terminal child
slices can contribute rows. A retry replays the exact bound slice and request
digest. If the previous request outcome is uncertain, the runtime may safely
replay only because final merge uses a qualified stable key; otherwise it
fails closed. Cancellation is checked before planning, dispatch, decode, split,
merge, and release. A canceled or timed-out run releases no result page and
cannot mark an in-flight or unprocessed slice complete.

Adaptive slicing can claim complete coverage only when every leaf slice has a
strict successful response, no partial/error/truncation marker, exact receipt,
contiguous coverage of the original interval, and the entire merged result is
within aggregate limits. Threshold exhaustion at the minimum duration,
`MaximumSlices`, or any other bound produces no complete result.

## Stable identity, ordering, and deduplication

Each qualified resource declares one datetime column and an ordered stable-key
tuple. The Kusto plan projects those columns and sorts by timestamp followed by
the stable-key tuple. A canonical row identity is a domain-separated digest of
resource identity, normalized timestamp, and the typed stable-key values. It
is never inferred from the full row, display order, or a hash supplied by the
model or vendor.

Rows are first checked for nondecreasing `(timestamp, stable-key)` order and
membership in the exact half-open slice. Cross-slice duplicates with identical
canonical identity and identical canonical row digest collapse to one row
while retaining every contributing slice and response digest. Reuse of an
identity with different row content is conflicting evidence and denies the
attempt.

If two rows have the same timestamp and no configured stable-key tuple, a key
contains null/unsupported/unbounded data, two distinct rows produce the same
tuple, or the helper output cannot prove a total order, the runtime returns
`sentinel_identical_timestamp_ambiguous` and releases no rows. It does not use
array position, arrival order, or timestamp perturbation as an invented
tie-breaker.

## Cancellation, failure, and recovery

| Condition | Required result |
|---|---|
| Missing/invalid timespan or bounds | typed invalid/denied before credential use |
| Stale authority, capability, schema, qualification, validation, audit, or revocation | denied before dispatch |
| HTTP error, timeout, 429/5xx, transport loss | no rows released; typed timeout/unavailable with redacted receipt evidence |
| HTTP 200 plus `PartialError` | reject all returned rows; failed/unknown, never partial success |
| Threshold requiring a safe split | discard parent rows, enqueue exact two half-open children |
| Slice/aggregate limit exhaustion | no complete page; typed exhausted/denied |
| Caller cancellation | abort transport, release no page, return typed canceled |
| Exact retry after confirmed no-release failure | current authority is rechecked; exact slice/request digest may replay |
| Lost or conflicting local state | fail closed; start a new attempt from the original admitted range |

There is no server-side Sentinel query job to cancel through this synchronous
API. COH cancellation is confirmed only for its local transport context and
release boundary; it never claims that Azure stopped work after a connection
loss. The common `Cancel` method can confirm a locally retained in-flight
attempt only after its context is canceled and result release is fenced;
otherwise it returns uncertain.

## Evaluation and release gate

The Sentinel v1 evaluation is separate from the frozen CYB-89 Elastic/Security
Onion corpus. It may reuse that evaluator's strict JSON, bounded-file,
deterministic-trace, outcome/trajectory grading, atomic-artifact, double-run,
and checksum patterns, but uses Sentinel-specific contract and fixture
versions.

The locked corpus includes mandatory-timespan success and denial; exact
half-open boundary coverage; recursive threshold splits; cross-slice duplicate
collapse; conflicting duplicates; identical-timestamp ambiguity; row/schema
drift; `PartialError`; HTTP denial; timeout; cancellation before and during
dispatch; exact retry/recovery; request/response/provenance substitution; and
threshold/fixture/environment tamper. Every task runs five trials with a
logical clock, no randomness, and network disabled.

Release thresholds are non-waivable: zero false-complete outcomes, zero
released rows for denied/partial/canceled/unknown trials, zero missing or extra
rows in successful merges, 100% expected-outcome grades, 100% trajectory
grades, 100% replay determinism, and 100% required-boundary coverage. A missing
task, trial, fixture, digest, or artifact is denial rather than a reduced
denominator. Two independent verifier runs must produce byte-identical result
artifacts.

## Compatibility, migration, and rollback

V1 is compatible only with the exact common query, Sentinel discovery, Kusto
validator, query transport, slicing, stable-key, fixture, corpus, and grader
versions recorded in the environment manifest. Changes to Azure endpoint/API,
response or statistics shape, Kusto validator identity, schema/timespan column,
stable-key tuple, timestamp precision, split rule, limit, error classification,
or dedupe semantics require a new contract version and full qualification.

Rollout begins disabled, exercises only sanitized network-denied fixtures, then
permits a separately authorized bounded read-only canary against one qualified
workspace. Rollback disables Sentinel execution and revokes the runtime/corpus
qualification; metadata discovery and credentialless validation may remain
available independently. No rollback accepts older cached results, validators,
credentials, qualifications, or evidence as current authority.
