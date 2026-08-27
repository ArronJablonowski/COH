# COH evidence-linked entity resolution contract v1

`entity-resolution.schema.json` freezes the public data contract for CYB-83 /
COH-E11-04 and FR-025. It validates eight closed durable records:

- case-local, evidence-bound typed identifier observations;
- deterministic entity candidates with complete confidence and counterevidence;
- immutable-revision entity records;
- explicit resolution, merge, split, rejection, and reindex decisions;
- append-only merge/split and correction history;
- exact idempotent commands;
- closed terminal outcomes; and
- audit/provenance-bound durable receipts.

Raw identifiers are forbidden. Matching uses an opaque case-keyed HMAC digest,
identifier type, normalization method, and key revision. Every observation
binds the complete COH-E10, CYB-80, and CYB-81 evidence chain. Confidence is
integer millionths with ordered components and an explicit ceiling. Merge and
split never rewrite observations or historical entities.
An `entity_ref.record_digest` identifies the canonical immutable entity-revision
core; decision, history, audit, and provenance digests are layered onto the
full record afterward to avoid cyclic self-reference.
The frozen v1 weights, counterevidence effects, source-independence rule,
arithmetic, and label thresholds are executable in
`fixtures/confidence-method-v1.json`; changing them requires a new method
version rather than an in-place tuning change.

Compatibility, privacy, authority, confidence, counterevidence, recovery,
rollback, and extension semantics are frozen in the
[entity-resolution design](../../../docs/design/evidence-linked-entity-resolution.md).
