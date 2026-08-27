# COH deterministic investigation projection contract v1

`investigation-projection.schema.json` freezes the public data contract for
CYB-86 / COH-E11-05, FR-024, FR-025, FR-067, and EVAL-017. It validates six
closed records:

- ordered committed facts;
- immutable correlation, hypothesis, or timeline projections;
- verified projection checkpoints;
- common-sequence watermarks;
- bounded projection queries; and
- disposable verified cache entries.

Every fact binds its exact case, evidence, custody, audit, provenance,
normalized-event, mapping, entity-revision, and time-record identities. A state
version additionally binds the reducer, schema, mapping, entity, time, and
authoritative-state versions used for a projection. Projections expose claims,
supporting evidence, counterevidence, unknowns, confidence, temporal order,
duplicates, gaps, hypotheses, and completeness without copying raw evidence or
granting action or policy authority.

All arrays are present and canonically ordered. Digests use SHA-256 over
COH-CJ-1 canonical JSON. A projection/checkpoint digest excludes only its own
digest field. Any reducer, schema, mapping, entity, time, or authoritative-state
change invalidates a checkpoint and cache key; compatibility is never inferred.

Recovery, cache, migration, rollback, privacy, and extension semantics are
frozen in the
[projection design](../../../docs/design/deterministic-investigation-projections.md).
