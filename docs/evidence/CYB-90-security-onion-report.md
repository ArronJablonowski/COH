# CYB-90 Security Onion Connect and structured OQL report

| Field | Value |
|---|---|
| Issue | COH-E13-04 / CYB-90 |
| Parent | COH-E13 / CYB-20 |
| Requirements | FR-046, FR-050 |
| Implementation baseline | `d150e101ebe3eb71115f97b71e2decb36ff31d68` |
| Focused verification | `scripts/verify_security_onion.sh` passed |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.RjHSpp` |
| CI outcome | 18/18 stages passed; promotable; VCS clean |
| CI report digest | `0ce803e569574e6da4b5e1278a1b0d3657c44fbfa4c44b08305f3acff6b04b80` |
| CI report SHA-256 | `c689c647d819d7f06a548ba888e5ed514f6021f73c15c06d971e0cd44e338763` |

## Delivered boundary

- Live OpenAPI qualification exposes only token exchange, manager info, and
  bounded event queries. The deployment contract requires canonical HTTPS,
  pinned trust and SPKI identity, a broker reference, and exactly `events/read`.
- Strict caller JSON compiles into a typed filter AST and deterministic OQL.
  COH owns mandatory scope filters, UTC range parameters, projections,
  grouping, stable sort, and all row/byte/time/rate/cost ceilings.
- Each operation borrows a credential, obtains a fresh short-lived token, pins
  TLS identity, bounds response bytes/time, and emits only digest receipts.
- The response decoder binds criteria back to the immutable plan, rejects
  errors/ambiguity/drift, releases only typed logical projection, and recognizes
  only bounded standard terms aggregations.
- The common Connector/query-runtime lifecycle supplies opaque handles,
  concurrent replay coalescing, bounded statistics, bounds/rate decisions,
  durable session transitions, cancellation records, and lost-state recovery.

## Completeness decision

Security Onion documents no stable continuation and may return fewer results
than requested because of a backend maximum. Cap-filled event or metric output
is partial and truncated. Event output is vendor-confirmed complete only when
`totalEvents` equals released rows and all other checks pass. Aggregations with
unproven bucket completion are terminal partial—not hidden success. V1 does not
claim slicing/bisection completeness because pinned evidence does not yet prove
half-open boundaries and deduplication across adjacent Connect queries.

## Adversarial and recovery evidence

Coverage includes OpenAPI/auth/media drift; forbidden route observation;
endpoint and method confinement; raw OQL/pipeline/script injection; logical
field, schema, scope, range, and limit substitution; duplicate/unknown/multiple
JSON; embedded errors; type/projection leakage; backend cap signals; OAuth
authentication versus recoverable outage; TLS substitution; deadlines and
cancellation; response overflow; exact and concurrent replay; retry after
outage; and uncertain poll/cancel after process-local state loss.

Sanitized Security Onion 3.x OpenAPI, info, event, metric, and error fixtures
are versioned with a manifest. The capability snapshot, valid secret-free
configuration, denial corpus, redacted trace, public schemas, design record,
verifier, and this report are checksum-bound by `CYB-90-artifacts.sha256`.

## Unsupported behavior and operations

No case/detection/config/grid/client/job/packet/PCAP/stream/user endpoint,
mutation, generic HTTP request, raw Lucene/OQL, caller pipe/projection/sort,
wildcard field, script, response widening, stable continuation, or proven export
slicing is supported. Rollout, migration, recovery, and rollback are defined in
the public README and design record.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Qualified Connect, structured OQL, limits, forbidden routes unreachable | Qualifier, compiler, typed transport, design | Pass |
| Typed operations, capability/resource bounds, cancellation, redaction, partial reporting | Adapter/runtime/receipts/completeness tests | Pass |
| Invalid input, denial, timeout/cancel, recovery retain policy and provenance | Adversarial and shared-runtime suites | Pass |
| Applicable test/race/architecture/secret/license/dependency/size gates | Focused verifier and clean 18/18 full CI | Pass |
| Vendor fixtures, capability, conformance report, redacted trace, checksums | Versioned contract and evidence manifest | Pass |

## Residual release condition

No implementation blocker is known. Obtain an independent security architecture
review before the first production release, as approved in the COH-E01 packet.
