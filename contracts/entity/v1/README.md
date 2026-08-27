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

Compatibility, privacy, authority, confidence, counterevidence, recovery,
rollback, and extension semantics are frozen in the
[entity-resolution design](../../../docs/design/evidence-linked-entity-resolution.md).
