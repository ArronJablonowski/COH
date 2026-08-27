# Deterministic investigation projections design freeze

Status: frozen for implementation
Stable key: COH-E11-05
Linear: CYB-86
Requirements: FR-024, FR-025, FR-067, EVAL-017
Depends on: COH-E10, CYB-80, CYB-82, CYB-81, CYB-83

## Purpose and authority boundary

COH projects immutable, committed investigation facts into three reproducible
views: correlation, bounded hypotheses, and uncertainty-preserving timelines.
Each result explains its claims, supporting and refuting evidence, unknowns,
confidence, order, duplicates, gaps, and completeness at one exact common
sequence watermark.

Projection state is derived and disposable. Case, evidence, custody, audit,
provenance, normalized-event, mapping, entity, and time stores remain
authoritative. A projection, checkpoint, cache hit, confidence score, or model
output grants no policy authority, approval, credential, connector access, or
action authority. The package accepts only narrow verification and storage
ports and contains no provider, model, network, filesystem, shell, SQL,
connector, executor, policy-source, evidence-byte, or generic callback surface.

## Requirement trace

| Requirement | Frozen behavior |
|---|---|
| FR-024 | Timeline entries bind original CYB-82 time-record and comparison digests and retain uncertainty, ordering confidence, duplicates, and gap evidence. |
| FR-025 | Correlation is exact-case scoped, evidence-backed, confidence-labeled, and reversible by replaying the immutable fact log under a pinned reducer version. |
| FR-067 | Claims and hypotheses carry explicit supporting evidence, counterevidence, unknowns, conflicts, negative evidence, telemetry gaps, and query completeness. |
| EVAL-017 | Reducer fixtures cover DST, skew, missing timezone, low precision, duplicates, uncertain order, source conflicts, partial data, and negative evidence without inventing certainty. |

## Closed records

The v1 schema validates six records.

1. A `fact` is an immutable committed event at one case-local sequence. It
   links the previous fact digest and binds exact authoritative identities.
2. A `projection` is a complete immutable correlation, hypothesis, or timeline
   value at one watermark and state version.
3. A `checkpoint` binds a projection digest, fact-set digest, watermark, state
   version, predecessor checkpoint, audit, and provenance.
4. A `watermark` identifies the greatest contiguous committed sequence, its
   head fact digest, commit time, and authoritative state digest.
5. A `query` requests `current` or one exact watermark with strict fact and
   output bounds plus a caller deadline.
6. A `cache_entry` binds the exact query, state version, watermark, checkpoint,
   and projection digests verified for a zero-I/O current read.

Unknown fields, null arrays, duplicate keys, noncanonical order, floating point,
unbounded maps, raw evidence, raw identifiers, and executable content are
invalid. Digests use lowercase `sha256:` identities over COH-CJ-1 canonical
JSON. Self-digest fields are omitted while calculating their record digest.

## Exact input and version binding

Every fact binds:

- organization, tenant, and case UUIDv7 identities plus case revision/digest;
- immutable artifact, manifest, ingest-receipt, custody-head, audit-head, and
  source-provenance digests from COH-E10;
- CYB-80 normalized-event digest and schema version;
- CYB-81 mapping outcome, manifest, and revision;
- zero or more exact CYB-83 entity revision references;
- zero or more exact CYB-82 time-record/comparison digests; and
- an authoritative-state digest covering the committed source heads.

`state_version` separately freezes the reducer version, projection schema,
normalized-event schema, mapping contract/manifest/revision, entity contract
and head, time contract/method, and authoritative-state digest. Equality is
exact. Additive or semantically compatible-looking changes do not reuse a
checkpoint or cache entry.

## Ordered facts and common watermark

Facts form a case-local digest chain beginning at sequence one. A reducer
accepts only the complete contiguous prefix from sequence one through a single
watermark. It never mixes facts from different head sequences or authoritative
state versions. A sequence gap, duplicate, reorder, fork, changed digest,
shrunk log, mismatched scope, or head/watermark mismatch is an integrity denial.

Facts are ordered by sequence, never arrival order, wall-clock order, map
iteration, database row order, or model preference. Time uncertainty affects
the timeline relation but cannot reorder the authoritative fact chain.

## Pure synchronous reducers

Each reducer is a pure synchronous function of:

`(previous immutable projection, ordered committed fact, exact state version)`

It performs no I/O, calls no clock, generates no identity, and reads no global
state. Output is deterministic canonical data. Reducers use integer arithmetic
only and keep input ordering rules explicit. The service performs verification,
loading, checkpointing, and caching outside the reducer.

When a valid fact causes no semantic projection change, the reducer returns the
same immutable value reference. This identity guarantee is observable only
inside the Go process and lets downstream reducers safely skip work. A changed
watermark still advances through the service/checkpoint state; semantic value
identity does not erase or hide the committed fact.

## Correlation projection

Correlation groups exact claim, evidence, entity-revision, and time identities.
Each claim carries its digest, supporting evidence, counterevidence, unknowns,
entity references, confidence method/value/label, and completeness. Shared
identifiers or temporal proximity alone never prove identity. Counterevidence
and conflicts are retained, not averaged away. Rebuild under the same inputs
must be byte-identical.

## Hypothesis projection

A hypothesis is bounded to canonical claim IDs and has one disposition:
`open`, `supported`, `refuted`, or `inconclusive`. It independently records
supporting evidence, counterevidence, unknowns, confidence, and completeness.
No confidence threshold silently changes disposition. Disposition changes are
new facts and remain reversible by replay to an earlier watermark.

## Timeline projection

Timeline entries bind fact sequence and exact CYB-82 time identities. Ordering
is `before`, `after`, `overlap`, `equal`, or `uncertain`, with integer confidence
and the time-comparison digest that proves it. Duplicate groups, source
conflicts, uncovered-gap digests, negative evidence, partial collection, and
unknown timezone/precision remain explicit. Wall-clock sorting cannot replace
uncertain order with a total order.

## Completeness and negative evidence

Completeness is `complete`, `partial`, or `unknown`. It binds queried and
completed source digests, gap digests, negative-evidence digests, and conflict
digests. Empty search results are not negative evidence unless an authoritative
fact explicitly binds the query, source coverage, and result. Missing telemetry
is not evidence that an event did not occur.

## Checkpoint, replay, and recovery

The service verifies facts through the requested watermark, runs the reducer,
canonicalizes the projection, and atomically persists the projection and
checkpoint. A checkpoint binds the fact-set digest, watermark, state version,
previous checkpoint, audit digest, and provenance digest.

Restart loads the greatest verified compatible checkpoint and replays only the
contiguous forward tail. An absent checkpoint rebuilds from genesis. A stale
version or cache entry is discarded. Integrity failure does not fall back to a
possibly stale view: a fork, gap, reorder, tamper, shrink, invalid predecessor,
or divergent rebuild fails closed. A missing or stale checkpoint may rebuild
only from independently verified authoritative facts.

## First-read persistence and zero-I/O current reads

The first read for an exact state version and watermark verifies authoritative
heads, loads/replays facts, persists a checkpoint, and publishes a cache entry.
A subsequent `current` read may perform zero storage I/O only when its in-memory
cache key already binds the exact query digest, state version, watermark,
checkpoint digest, and projection digest most recently verified by that service
instance. Any current-head notification, state-version change, restart, cache
miss, expiry, or uncertainty forces verification before reuse.

## Concurrency and idempotency

Checkpoint commit uses optimistic comparison against the exact prior checkpoint
and watermark. Concurrent builders of the same canonical result converge on
one checkpoint; a changed result for the same idempotency identity is denied.
An indeterminate commit response is reconciled by loading and verifying the
stored checkpoint before retry. Cancellation and timeout stop reduction and
persist no partial projection.

## Failure matrix

| Concern | Closed result |
|---|---|
| Invalid canonical record, bound, enum, version, or digest | `invalid_input` |
| Cross-case or cross-tenant fact or result | `scope_mismatch` |
| Missing fact, gap, reorder, fork, shrink, or tamper | `integrity_failure` |
| Stale state/checkpoint/cache version | invalidate and rebuild from verified facts |
| Divergent deterministic rebuild | `projection_divergent` |
| Authority-bearing or unverified source input | `authority_denied` |
| Fact/checkpoint/cache dependency unavailable | `dependency_unavailable` |
| Caller cancellation | `context_canceled` |
| Caller deadline | `context_deadline` |
| Changed idempotent checkpoint commit | `idempotency_conflict` |

No failure returns a newly derived projection as current. Safe error and audit
records contain only scope-safe UUIDs, versions, sequences, enums, bounds, and
digests; they do not copy claim text, raw events, raw identifiers, or evidence.

## Migration, rollback, privacy, and extensions

The initial schema, contract, and reducer method are version `1.0.0`. A schema,
reducer, fact meaning, ordering rule, completeness rule, confidence rule,
upstream binding, or canonicalization change requires a new state version,
migration assessment, and byte-identical corpus replay. Checkpoints and caches
from another version are never silently upgraded.

Rollback disables new writes and rebuilds with the prior supported reader and
reducer over immutable facts. It never deletes authoritative data or treats a
cache as authoritative. Projection caches may be dropped at any time.

Projection content inherits the highest classification of its bound facts.
Cross-case correlation, fuzzy/model matching, broader source access, action
authority, mutable hypotheses, or executable projection extensions require a
new reviewed boundary and cannot silently reuse v1.
