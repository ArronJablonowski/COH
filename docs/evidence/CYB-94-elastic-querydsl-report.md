# CYB-94 bounded Elastic Query DSL and PIT export report

| Field | Value |
|---|---|
| Issue | COH-E13-03 / CYB-94 |
| Parent | COH-E13 / CYB-20 |
| Requirements | FR-048, FR-049 |
| Implementation baseline | `ab65d011071903c427769964e228955eabf79832` |
| Focused verification | `scripts/verify_elastic_querydsl.sh` passed |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.5u7uN7` |
| CI outcome | 18/18 stages passed; promotable; VCS clean |
| CI report digest | `91724a80d8caa0c5a3360766d8e1932ef85b509256da67e71fa3b1e0f1430779` |
| CI report SHA-256 | `e4ff8d4e17a9d7d7655b7d0f376493f2317849124ad0ec1b4b641184dea4334d` |

## Delivered boundary

- A cancellation-aware strict JSON decoder rejects duplicate keys, trailing
  input, non-integer numbers, invalid roots, excessive input/depth/clauses/terms,
  unknown members, and ambiguous or unsupported operators before compilation.
- A typed AST admits only `match_all`, `term`, `terms`, `range`, `exists`,
  restricted `match`, restricted `match_phrase`, and filter-only `bool` against
  operator-configured logical fields and the current exact schema.
- The compiler rebuilds canonical vendor Query DSL and independently composes
  mandatory half-open UTC and optional tenant/source filters. It binds query,
  scope, authority, capability, schema, projection, stable sort, filters, and
  all effective bounds into an immutable digest-addressed plan.
- The typed transport exposes only `_validate/query`, PIT open, PIT search, and
  PIT close. It uses exact sorted concrete indices, all-shard validation,
  `_source=false`, explicit fields, no partial results, stable timestamp/stable
  identifier/`_shard_doc` sort, `search_after`, and one-row lookahead.
- The response boundary rejects warning headers, timeouts, shard failure,
  cross-cluster/partial state, target drift, source or unrequested field output,
  invalid/multivalue cells, sort drift, malformed PIT rotation, oversized
  responses, and unconfirmed closes.
- The shared connector lifecycle revalidates target identity before opening an
  adapter-owned PIT, returns digest-only opaque handles, rotates the stored PIT
  atomically, coalesces exact concurrent replay, and maintains cumulative
  row/byte/time/page/slice statistics under admitted and hard ceilings.
- Terminal completion or explicit truncation closes the newest PIT before the
  result is reported. Failed close is uncertain, never confirmed. Deadline
  expiry and process loss discard raw local PIT state and rely on the bounded
  vendor expiry backstop.

## Cross-layer evidence

`TestQueryDSLRuntimeFeedsSharedExportRuntimeEvidence` exercises the actual
Elastic Query DSL adapter through bounds admission, export session creation,
rate reservation, first-page polling, next-page traversal, cumulative usage,
terminal completion, and redacted session recording. The terminal session
binds the bounds decision, execution, page, vendor provenance, limits, and
usage. Durable evidence remains the shared CYB-92 encrypted-native and redacted
metadata path; this leaf adds no parallel evidence store.

The public contract includes the secret-free definition schema, valid
definition, exact capability snapshot, denial corpus, redacted error trace,
operations/recovery/rollback guidance, and compatibility boundary. The four
sanitized Elastic 8.19 validate/PIT/search/close fixtures and manifest declare
that they contain no sensitive values.

## Adversarial and recovery coverage

Compiler coverage includes JSON ambiguity, duplicate/trailing roots, scripts,
query strings, wildcards, scoring `must`, unknown or unauthorized fields,
operator permission failures, contradictory ranges, floats and type confusion,
noncanonical IP/timestamp literals, excessive or duplicate terms, unsafe text
options, language/scope/schema substitution, cancellation, and deadline.

Transport/runtime coverage includes exact-target and `search_after`
substitution, warning/error precedence, timeout, shard failure, cluster state,
PIT/open/close drift, target/source/score/field leakage, multivalue cells,
sort-shape drift, missing optional fields, row truncation, terminal close,
vendor outage and retry, uncertain close, concurrent replay, actor/job and page
handle theft before vendor access, raw native-text destruction, and end-to-end
shared runtime evidence.

## Capability migration and unsupported behavior

The Elastic capability now advertises exactly `elastic-query-dsl` and `esql`,
not unimplemented KQL/Lucene, and reports the polling/paging/cancellation
features actually exercised by the runtimes. The CYB-93 published capability
fixture and checksum were migrated and its verifier remains passing.

V1 does not support Serverless, cross-cluster search, async search, scroll,
vendor slicing, caller `from`, caller sort/projection/source selection,
aggregations, collapse, suggest, rescore, knn/retrievers, runtime mappings,
scripts, stored queries, partial results, or experimental fields. Rollout starts
disabled behind current CYB-93 qualification and query-bounds admission.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Strict AST, validation, PIT ownership, stable paging, cancellation, completeness | Compiler, typed transport, runtime, design, and focused verifier | Pass |
| Typed allowlisted operations, bounds, redaction, partial/unsupported reporting | Immutable plan, exact endpoints/targets, denial corpus, redacted trace | Pass |
| Invalid input, denial, timeout/cancel, and recovery retain policy/provenance | Adversarial compiler/transport/runtime suites and shared evidence integration | Pass |
| Applicable test, race, architecture, secret, license, dependency, and size gates | Focused verifier plus clean 18/18 full CI | Pass |
| Vendor fixture, capability, conformance report, redacted trace, checksums | Versioned public contract and `CYB-94-artifacts.sha256` | Pass |

## Residual release condition

No CYB-94 blocking finding remains. The product-level non-blocking follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
