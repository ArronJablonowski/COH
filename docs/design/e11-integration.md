# COH-E11 normalization, correlation, and timeline integration

Status: implemented and verified
Linear: CYB-15
Requirements: FR-021, FR-022, FR-024, FR-025, FR-067, EVAL-017
Depends on: COH-E10, CYB-80, CYB-81, CYB-82, CYB-83, CYB-86

## Purpose and end-to-end boundary

COH-E11 turns one immutable COH-E10 evidence identity into reproducible,
OCSF-first analytical views without losing the original vendor record or
inventing temporal, entity, or investigative certainty. The integrated chain
is:

1. CYB-80 validates a closed normalized-event envelope containing the exact
   original vendor fields, pinned OCSF/ECS compatibility, lineage, and bounded
   dataset coordinates.
2. CYB-81 applies one exact signed mapping revision. Its outcome binds the
   input and output envelope digests, mapping manifest, reverse checks, entity
   hints, coverage, unmapped paths, and lossy paths.
3. CYB-82 derives conservative time records and comparisons from the exact
   envelope and source field. Timezone, precision, skew, ambiguity, duplicate,
   conflict, gap, partial, and negative-evidence states remain explicit.
4. CYB-83 converts case-keyed mapping hints into immutable entity observations
   and revisions with evidence-linked confidence and reversible history.
5. CYB-86 reduces the exact envelope, mapping outcome, entity revision, and
   time identities into deterministic correlation, hypothesis, and timeline
   projections at one contiguous watermark and state version.

The `internal/domain/e11integration` verifier independently recomputes every
leaf digest and denies drift at any boundary. It receives canonical records and
digests only. It has no policy, credential, connector, executor, provider,
model, network, filesystem, SQL, shell, or raw-evidence access.

## Recoverable vendor fields

Every accepted normalized envelope retains `original.fields` as canonical
vendor JSON and binds `original.fields_digest`. Mapping never rewrites this
section. OCSF and optional ECS records are derived siblings, not replacements.
Every mapping output also binds its input envelope as a parent, its signed
mapping manifest, transformation digest, coverage, unmapped vendor paths, and
loss state. A consumer can therefore recover the exact accepted vendor fields
and determine how each mapped value was produced or why it was omitted.

The original section is immutable through the validated-envelope API: callers
receive defensive copies. A changed vendor field, OCSF event, ECS field,
mapping revision, coverage result, or lineage identity changes the canonical
envelope or transformation digest.

## Temporal uncertainty

Time normalization never turns a missing timezone, DST gap/fold, coarse
precision, calibration radius, source conflict, partial collection, or
unbounded interval into a single authoritative instant. Comparisons emit
`before`, `after`, `equal`, `overlap`, `duplicate`, `conflicting`, or `unknown`
with explicit confidence and rationale. Investigation timeline entries bind
the exact time-record and comparison digests and retain precision,
uncertainty, duplicate identity, gaps, conflicts, unknown codes, and integer
ordering confidence.

Fact sequence orders the immutable analytical log. Temporal comparison never
reorders that log or converts an uncertain relation into a total wall-clock
order.

## Entity and projection reproducibility

Entity observations bind the normalized envelope, transformation, raw
artifact, manifest, ingest receipt, source provenance, mapping manifest,
mapping revision, mapping outcome, rule, output path, and source-field digest.
Entity revision identity hashes an immutable core containing its exact member
observation digests and confidence calculation. Lifecycle, audit, history, and
provenance bindings cannot change that core identity.

Investigation facts bind the same COH-E10 and CYB-80/CYB-81 identities plus
exact CYB-83 entity revisions and CYB-82 time records/comparisons. Reducers are
pure functions of the prior immutable value, next contiguous fact, and pinned
state version. Replaying pinned inputs produces byte-identical correlation,
hypothesis, and timeline values. A schema, mapping, entity head, time method,
reducer, or authoritative-state change invalidates the checkpoint and cache.

## Compatibility and migration

The initial integration supports normalized-event, mapping, time, entity, and
projection contracts at version `1.0.0`, OCSF `1.9.0`, and ECS `9.5.0` with
their pinned schema commits. Compatibility is exact, not inferred from
apparently additive JSON changes.

A change to a leaf schema, canonicalization rule, mapping language, target
schema, confidence method, time method, entity identity, reducer meaning,
ordering rule, or evidence binding requires:

- a new explicit contract or method version;
- a migration and privacy assessment;
- replay of the leaf and COH-E11 integration corpora;
- byte-level comparison of old and new outputs;
- checkpoint and cache invalidation; and
- a reviewed rollback path before promotion.

Existing immutable evidence and prior-version records remain readable. They
are never silently rewritten into the new version.

## Recovery and restart

Authoritative case, evidence, custody, audit, provenance, mapping, entity, and
time stores are verified before derived state is published. Restart discards
the in-memory projection cache, loads only a canonical compatible checkpoint,
and replays the contiguous authoritative fact tail. A missing or stale
checkpoint rebuilds from genesis or a verified compatible predecessor.

Gap, fork, reorder, shrink, tamper, mismatched scope, changed state version,
or divergent deterministic result fails closed. An indeterminate checkpoint
commit is reconciled by loading and verifying the stored canonical result.
Cancellation or deadline returns no partial current projection.

## Rollback

Rollback stops new writes for the affected version, selects the prior
supported readers and reducers, drops disposable caches, and rebuilds derived
views from immutable facts. It does not delete or reinterpret raw artifacts,
normalized envelopes, mapping outcomes, time records, entity history, audit,
or provenance. Cross-version checkpoints are never reused.

## Privacy and authority

Each derived record inherits the highest classification of its bound evidence.
Original vendor fields remain inside the normalized envelope and bounded
dataset interfaces; entity resolution receives typed case-keyed digests rather
than raw identifiers. Projections carry digests and canonical analytical
records, not raw evidence bytes.

No normalized event, mapping hint, time comparison, entity confidence,
hypothesis, projection, checkpoint, cache entry, or model output grants policy,
approval, credential, connector, or action authority. Cross-case correlation,
fuzzy identity, model-based matching, broader source access, or executable
extensions require a new reviewed boundary.

## Bounded dataset assumptions

Large normalized collections remain immutable, manifest-bound datasets. A
dataset reference binds format, artifact, manifest, schema, partition keys and
values, row group, row index, and an access profile limiting rows, bytes,
pages, and duration. Integration assumes:

- every returned page is independently bound to the requested dataset and
  case;
- paging cannot exceed the stored access profile;
- dataset order cannot replace fact-sequence or conservative time order;
- truncation and incomplete collection remain explicit completeness states;
- empty query results become negative evidence only when a committed fact
  binds the query and completed source coverage; and
- raw dataset access cannot be smuggled through an integration callback,
  filesystem path, URL, SQL string, connector, or generic client.

## Integration findings and release follow-up

The CYB-86 contract audit added explicit timeline-entry unknown codes so
missing timezone and related uncertainty survive into the final timeline.
No unresolved blocking integration finding remains.

Per the approved COH-E01 follow-up, an independent security architecture
review remains required before the first production release.
