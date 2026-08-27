# COH normalization mapping registry contract v1

`normalization-mapping.schema.json` freezes the public data contract for
CYB-81 / COH-E11-03, FR-021, and FR-025. It validates four durable records:

- `coh.signed-normalization-mapping/v1` contains a canonical, source-specific,
  ordered mapping manifest and its exact Ed25519 publisher signature;
- `coh.mapping-registry-command/v1` binds case/evidence/envelope/source,
  registry revision, mapping digest, operation, idempotency, and deadline;
- `coh.mapping-registry-outcome/v1` records the closed decision, selected
  manifest, normalized-envelope reference, coverage, applied/unmapped/lossy
  paths, entity hints, and reverse-validation results; and
- `coh.mapping-registry-receipt/v1` makes audit, provenance, replay, restart,
  and lost-response recovery durable.

Every object is closed. Paths and operations are data-only. Unknown input leaf
paths must be explicitly mapped, ignored, or listed unmapped. The contract
contains no executable expression, wildcard, private key, evidence byte,
credential, storage location, network, connector, executor, shell, or policy
surface.

Compatibility, signature, selection, mapping-language, reversibility,
coverage, migration, recovery, rollback, and privacy semantics are frozen in
`docs/design/normalization-mapping-registry.md`.

