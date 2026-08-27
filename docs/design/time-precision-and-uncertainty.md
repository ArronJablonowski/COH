# Time precision and uncertainty design freeze

Status: frozen for implementation  
Stable key: COH-E11-02  
Linear: CYB-82  
Requirements: FR-024, EVAL-017  
Depends on: COH-E10, COH-E11-01 / CYB-80

## Purpose

COH must preserve what a source actually said about time without converting an
imprecise, ambiguous, skewed, missing, or conflicting observation into a
precise UTC claim. Temporal normalization therefore produces a durable record
containing the exact source text, its interpretation inputs, a conservative
inclusive interval when one can be established, and an explicit unresolved
state when one cannot.

The temporal record is a projection of immutable evidence. It never replaces
the COH-E10 artifact or the CYB-80 normalized-event envelope and never grants
access to their bytes.

## Frozen compatibility bindings

| Existing contract | Retained input | CYB-82 rule |
| --- | --- | --- |
| COH-E10 immutable evidence | organization, tenant, case, artifact, manifest, ingest receipt, and source provenance digests | Resolve and compare the complete binding before parsing; never accept only an artifact digest. |
| `coh.evidence-ingestion/v1` `observed_time` | normalized value, original numeric offset, precision, uncertainty | Import through an explicit compatibility adapter. The old value is retained as source text; its offset becomes `numeric_offset`; its uncertainty becomes a bounded calibration radius. Unknown precision remains unknown. |
| `coh.normalized-event-envelope/v1` | envelope ID and digest, source identity/digest, collection method/version, raw lineage, OCSF event time, original vendor fields | Bind the exact envelope digest and source identity. Select time only by a versioned field selector; never search arbitrary fields or silently prefer OCSF over original data. |
| `coh.context-compaction/v1` source | source/normalized time, timezone, precision, clock uncertainty, order confidence, result/completeness/uncertainty | Export only from a validated temporal record. Existing coarse enums are lossy projections; they are not valid CYB-82 normalization inputs. |

CYB-82 does not change any of those contracts in place. A later version may
reference the temporal-record digest. Until then, adapters must preserve the
CYB-82 record as separately resolvable provenance.

## State and invariant matrix

| Concern | Closed states | Required invariant | Fail-closed result |
| --- | --- | --- | --- |
| Source text | non-empty UTF-8 string | Exact bytes after JSON string decoding are retained; no trimming or rewriting. | `invalid_source_text` |
| Format | registered parser identity | Parser name, semantic version, implementation digest, and selected format are immutable inputs. | `parser_not_registered`, `format_not_supported` |
| Timezone | `explicit_offset`, `iana`, `missing` | An explicit offset is authoritative. An IANA result is bound to tzdata version/digest. Missing timezone never produces normalized UTC. | `timezone_unresolved`, `timezone_mismatch` |
| DST | `exact`, `fold`, `gap`, `not_applicable`, `unresolved` | A fold retains every candidate instant and widens the interval; a gap has no invented instant. | `dst_gap`, `timezone_unresolved` |
| Precision | `nanosecond`, `microsecond`, `millisecond`, `second`, `minute`, `hour`, `day`, `unknown` | Precision describes the entire source unit, not formatting digits inferred after parsing. Unknown precision is unbounded unless the source supplies explicit bounds. | `precision_unknown` |
| Clock | `source`, `collector`, `server`, `device`, `unknown` | Calibration identity and signed skew convention are retained. `skew = source_clock - reference_clock`; corrected UTC subtracts skew. | `calibration_unresolved` |
| Skew | exact signed estimate plus non-negative radius, or unknown | True time uses `[source lower - (estimate + radius), source upper - (estimate - radius)]`; all arithmetic is overflow checked. | `arithmetic_overflow`, `calibration_unresolved` |
| Interval | `bounded`, `unbounded` | Bounds are inclusive UTC nanoseconds and `earliest <= latest`; no sentinel timestamp represents infinity or unknown. | `interval_invalid` |
| Normalization | `normalized`, `unresolved`, `denied`, `canceled`, `timeout`, `dependency_unavailable` | Only `normalized` selects a normalized UTC instant. A fold may be unresolved with bounded candidates; missing/gap/unknown states are unbounded. All terminal states retain command and provenance digests. | Closed reason code matching the state. |
| Comparison | `before`, `after`, `equal`, `overlap`, `duplicate`, `conflicting`, `unknown` | Strict order is emitted only for disjoint bounded intervals. Overlap never becomes before/after. | `unknown` with rationale. |
| Gap/negative evidence | `observed`, `negative`, `gap`, `partial`, `conflicting` | These are evidence facts, not absence inferred from missing rows. Completeness and evidence bindings are retained. | `evidence_state_invalid` |
| Replay | first, exact replay, changed replay | Idempotency key binds the canonical command digest. Exact replay returns the stored receipt; changed replay is denied. | `idempotency_conflict` |

## Temporal normalization semantics

### Parsing and timezone resolution

Only an injected parser selected by an exact immutable identity may interpret
source text. A parser returns civil components and declared precision; it does
not load timezone data or choose a UTC instant.

Timezone inputs are closed:

- `explicit_offset` carries minutes in `[-840, 840]`. It produces one mapping
  and does not consult host timezone data.
- `iana` carries a zone name and exact tzdata version/digest. The resolver
  returns zero, one, or two candidate mappings for the civil value. Zero is a
  DST gap, one is exact, and two is a DST fold. More than two is invalid.
- `missing` carries no name or offset. The result remains unresolved and its UTC
  interval is unbounded.

When both a source offset and an IANA assertion are present, the selected
candidate must have that offset. No match is `timezone_mismatch`; one match is
exact; multiple matches remain a fold. Host-local timezone and an unversioned
host tzdata database are never implicit inputs.

### Precision bounds

For a candidate civil value, precision denotes the inclusive interval covering
the represented unit. Nanosecond precision is a singleton. Microsecond through
hour precision end one unit minus one nanosecond later. Day precision ends one
nanosecond before the next local civil day, so a DST transition may make it 23
or 25 hours. Bounds for every timezone candidate are resolved, and the safe
record interval is the minimum lower bound through maximum upper bound.

Unknown precision cannot be narrowed from the number of displayed fractional
digits. It remains unbounded unless an upstream contract supplies explicit,
independently verified inclusive bounds.

### Clock correction and uncertainty

The signed calibration estimate uses:

`skew = source clock - reference clock`

For source interval `[Smin, Smax]`, skew estimate `E`, and non-negative radius
`R`, the conservative corrected interval is:

`[Smin - (E + R), Smax - (E - R)]`

Every add/subtract is checked before it is performed. Overflow denies
normalization; values are never clamped. Unknown calibration makes the interval
unbounded unless the command explicitly declares the clock authoritative with
zero skew and an immutable clock-source identity.

### Comparison precedence

Comparison is symmetric and deterministic:

1. A matching deduplication binding and matching temporal-record digest is
   `duplicate`.
2. A matching deduplication binding with disjoint normalized intervals or
   incompatible source facts is `conflicting`.
3. Any unbounded or unresolved interval is `unknown`.
4. `A.latest < B.earliest` is `before`; the inverse is `after`.
5. Equal singleton instants are `equal`.
6. Every remaining intersection is `overlap`.

Confidence is `exact` only for singleton, non-ambiguous, zero-radius values;
`bounded` for other bounded results; `ambiguous` for DST folds or conflicting
source assertions; and `unknown` for unresolved results. The comparison stores
the exact rationale and input record digests. A non-negative uncovered gap (the
distance between inclusive bounds minus one nanosecond) is reported only for
`before` or `after`; whether it represents missing evidence
depends on separately bound completeness and `gap` evidence facts.

## EVAL-017 fixture matrix

| Fixture | Expected proof |
| --- | --- |
| Explicit UTC nanoseconds | Singleton normalized interval and exact comparison confidence. |
| Numeric offset | UTC conversion retains original text and offset. |
| DST spring gap | No UTC invention; `unresolved/dst_gap`. |
| DST fall fold | Two candidates retained and conservative bounded interval. |
| Missing timezone | Unbounded UTC and `unresolved/timezone_unresolved`. |
| Low precision day | Full local civil-day interval, including DST day width. |
| Positive and negative skew | Corrected bounds follow the signed convention and radius. |
| Arithmetic edge | Overflow is denied, never clamped or wrapped. |
| Duplicate | Same deduplication binding and record digest returns `duplicate`. |
| Uncertain order | Intersecting intervals return `overlap`, never strict order. |
| Source conflict | Same binding with incompatible time facts returns `conflicting`. |
| Partial data | Completeness survives normalization and comparison. |
| Negative evidence and explicit gap | Evidence state survives; no absence is inferred. |
| Cancellation and timeout | Typed terminal result retains command/provenance identity. |
| Lost response and restart | Exact replay returns the durable receipt once. |
| Changed replay | Same idempotency key with a changed command is denied. |

## Boundary and privacy freeze

Public ports may exchange only typed civil values, immutable identities,
calibration values, temporal records, receipts, audit entries, and digests.
They must not expose evidence bytes, raw vendor fields, credentials, secrets,
filesystem paths, URLs, SQL, network clients, connectors, executors, policy
source, or generic callbacks. Cancellation is propagated through `context`.

Source time text is classified event data. Audit and error values use closed
reason codes and digests; they do not copy source text. Stored records retain
source text because FR-024 requires it, under the classification and case scope
of the bound evidence.

## Migration, recovery, and rollback

The initial schema is `coh.time-normalization/v1`, contract `1.0.0`. Additive
or semantic changes require a new contract version and compatibility tests.
Persistence writes the command before dependency calls and atomically commits
the record, receipt, audit entry, and provenance link. Recovery loads by
idempotency key and command digest. Rollback stops new v1 writes but retains the
reader and records; temporal evidence is never rewritten or deleted as part of
application rollback.
