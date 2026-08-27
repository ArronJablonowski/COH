# CYB-91 bounded Elastic ES|QL execution report

| Field | Value |
|---|---|
| Issue | COH-E13-02 / CYB-91 |
| Parent | COH-E13 / CYB-20 |
| Requirements | FR-046, FR-049 |
| Implementation baseline | `fb602898172b050f0c551257874210c3567a6744` |
| Focused verification | `scripts/verify_elastic_esql.sh` passed |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.2W4f8j` |
| CI outcome | 18/18 stages passed; promotable; VCS clean |
| CI report digest | `316b6af7a650be39719f82e04e60a2afa93f8fe38c1b0f0502d6133c79a1a026` |
| CI report SHA-256 | `5f996f9b1421567649d0afa5dd6894ae7cda73dc84a9bba83ade8a1a299f0b98` |

## Delivered boundary

- A cancellation-aware tokenizer and parser accepts only one logical `FROM`
  source followed, in fixed order, by optional bounded `WHERE`, `KEEP`, `SORT`,
  and `LIMIT` commands. Unknown syntax and all source-widening, joins, forks,
  functions, directives, comments, scripts, subqueries, and vendor experimental
  commands fail closed.
- The compiler validates logical fields against the current exact schema and an
  operator definition with separate projection/filter/sort permissions. It
  emits only configured vendor field names, positional parameters, an explicit
  safe projection, stable ordering, and a positive final row limit clamped by
  the admitted and adapter limits.
- COH constructs a separate mandatory Query DSL filter from the admitted UTC
  half-open range and optional exact tenant/source terms. The filter, plan,
  schema, capability, scope, authority, and limits are digest-bound. Caller
  text cannot provide, omit, or weaken the filter.
- The typed transport accepts only a validated immutable plan and exact sorted
  concrete indices. It invokes synchronous `POST /_query` with JSON rows,
  `allow_partial_results=false`, `drop_null_columns=false`, and `columnar=false`
  through the CYB-93 fresh-credential and pinned-TLS boundary.
- The response decoder requires HTTP success before evaluating success-only
  headers, rejects warnings and partial/cluster metadata, enforces the exact
  column order and types, bounds bytes/rows/duration, and accepts only scalar
  lossless string/integer/boolean/timestamp/IP cells.
- The adapter implements the shared query connector lifecycle. Exact concurrent
  execution replay is coalesced to one vendor call; failed pre-response calls
  can be retried; successful execution destroys the prepared plan. One bounded
  synchronous result remains behind an opaque job handle until shared runtime
  polling records and releases it.
- Process-local validated plans, execution flights, and results have a fixed
  capacity and independent deadline expiry. Lost adapter state is reported as
  unavailable/unknown, and cancellation of unknown state is uncertain rather
  than falsely confirmed.

## Cross-layer evidence

`TestESQLRuntimeFeedsBoundedSharedRuntimeEvidence` exercises the real Elastic
ES|QL adapter through fresh bounds admission, shared runtime session creation,
rate reservation, polling, page validation, completeness accounting, and
redacted session recording. The terminal session binds the bounds decision,
execution, page, vendor provenance, limits, and usage. The generic CYB-92
runtime recorder remains the durable encrypted-native/redacted-metadata path;
this leaf does not add a parallel evidence store.

The public contract provides a secret-free operator-definition schema, valid
definition, denial corpus, redacted error trace, operations/rollback guidance,
and compatibility boundary. The sanitized Elastic 8.19 fixture manifest and
ES|QL response fixture contain no sensitive values.

## Adversarial and recovery coverage

The compiler corpus covers source substitution, other resources, wildcards,
quoted/backtick identifiers, semicolons, comments, directives, multiple
pipelines, `FORK`, functions/subqueries, unknown and non-filterable fields,
invalid string/integer/IP/timestamp literals, zero/negative/repeated/non-final
limits, token/depth/parameter/input limits, schema mismatch, cancellation, and
deadline.

Transport and runtime coverage includes logical-source leakage, native-literal
leakage, target substitution, authentication/privilege denial, success-header
error precedence, warnings, partial results, cluster metadata, column/type/row
drift, multivalue cells, byte and row caps, caller cancellation, vendor outage
and retry, concurrent replay, validation/handle substitution, unknown state,
deadline expiry, complete state cleanup, and process-local capacity exhaustion.

## Explicit unsupported behavior and rollout

V1 does not support async ES|QL, pagination beyond its one bounded synchronous
page, cross-cluster search, Serverless, columnar output, partial results,
profiling, locale/time-zone directives, computed fields, aggregation, joins,
forks, enrichment, approximation, tables, or vendor experimental features.

Rollout begins disabled and requires a current CYB-93 qualified capability and
schema, current bounds admission, the dedicated read-only Elastic principal,
and successful public verification. Rollback disables new ES|QL validation,
revokes leases, expires process-local state, and preserves durable evidence.

## Residual release condition

No CYB-91 blocking finding remains. The product-level non-blocking follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
