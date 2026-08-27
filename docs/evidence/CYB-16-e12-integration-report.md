# CYB-16 COH-E12 read-only query broker integration report

| Field | Value |
|---|---|
| Parent | COH-E12 / CYB-16 |
| Requirements | FR-045, FR-046, FR-047, FR-048, FR-053, FR-054, SEC-013, NFR-008 |
| Implementation baseline | `0a7aea795c46fa4a6defd75a86a92e3a782be511` |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3LF8Mp` |
| CI outcome | 18/18 stages passed; VCS clean |
| CI report digest | `381e8932ede4a6786af4068ba94457ef5129d1678cee313c319484a9345c03a6` |
| CI report SHA-256 | `d5699decb36e3f99f68480b27f3f684df115dbc322b20acde890e39e89d7b1f1` |

## Child closure audit

All five leaves are Done with focused, checksummed evidence:

- COH-E12-01 / CYB-85: common typed read-only connector lifecycle;
- COH-E12-02 / CYB-84: mandatory UTC scope, bounds, limits, policy, approval,
  revocation, audit, and E-stop admission;
- COH-E12-03 / CYB-88: bounded tenant/source/capability schema cache;
- COH-E12-04 / CYB-87: rate-reserved paging, slicing, budgets, explicit
  completeness, cancellation, backoff, replay, and recovery; and
- COH-E12-05 / CYB-92: encrypted native-query evidence plus redacted,
  append-only query provenance and durable idempotency recovery.

## Integration findings closed

The parent audit found that the initial CYB-87 signed session omitted `case_id`,
which prevented a production evidence recorder from reconstructing an exact
case-scoped persistence key. Commit `1ad19d5` added the field to signed runtime
state and both public contracts. The audit also found that the runtime's genesis
callback precedes query-evidence genesis. Commit `bcbc2a0` added a one-query
prepared recorder that converts revision one into encrypted evidence genesis
and subsequent revisions into expected-head transitions.

No integration blocking finding remains. Identity is continuous across query,
admission, execution, runtime, and evidence; runtime profile limits can narrow
but not widen admission; connector runtime exposes only poll/page/cancel; and a
complete result is not visible until its exact runtime revision is durably
recorded.

## Cross-leaf verification

`scripts/verify_e12_integration.sh` passed every leaf verifier, repeated and
race integration tests, vet, static analysis, architecture, and file-size gates.
The end-to-end test constructs and strictly decodes a scoped native query and
validator result, obtains a real bounds decision, starts the real runtime through
the prepared evidence recorder, polls a validated vendor completion, and reloads
the durable evidence head. It asserts exact case/query/decision/execution/
validator/native-artifact identity, cumulative statistics, explicit complete
status, two audit events, and absence of any mutation or generic transport method.

Failure integration covers invalid/empty UTC bounds and proves a trusted runtime
profile narrows the admitted row cap. Leaf adversarial suites additionally cover
denial, timeout, cancellation, partial/unknown/truncated results, vendor overrun,
page withholding, rate races, replay, outages, lost responses, chain forks,
concurrency, tampering, plaintext leakage, and strict decoding.

The clean full baseline passed format, file-size, workflow, secret worktree and
history scans, architecture, quality contract, vet, static analysis, unit, race,
fuzz seeds, license, dependency/vulnerability, SBOM, supply-chain, evidence
secret scan, and provenance stages.

## Compatibility, migration, recovery, rollback, privacy, and limits

The complete operational contract is in
`docs/design/query-broker-integration.md`. In summary: incompatible identity or
semantic changes require a new major contract; production registers the
`query_evidence` record migration before enabling queries; recovery reloads the
last signed state and never infers lost outcomes; rollback stops new work and
preserves immutable incomplete outcomes; query/result content stays in COH-E10
encrypted evidence; and every document, query, schema, budget, rate, wait,
session, and repository boundary is finite.

## Residual release condition

No COH-E12 blocking finding remains. The product-level non-blocking follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
