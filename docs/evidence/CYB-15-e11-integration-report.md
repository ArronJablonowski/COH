# CYB-15 COH-E11 integration verification

| Field | Value |
|---|---|
| Stable key | COH-E11 |
| Requirements | FR-021, FR-022, FR-024, FR-025, FR-067, EVAL-017 |
| Child issues | CYB-80, CYB-81, CYB-82, CYB-83, CYB-86 |
| Integration commits | `df92fc5` through `0036d5d` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `81cdd260ebd4ae33f0e9f79c489e80c46dbad81288bd6b1e6585a4e592acb64a` |
| CI report file SHA-256 | `b64ecfd5a01a01da1c455110920fb9e4eeb318da53c9450a76775ec29fe25b22` |
| Focused verifier log SHA-256 | `635b6fab67211968ee1c04fd30fd64ce6c2eb77fdafd1a564c8250fd329d32e0` |

## Evidence locations

- Focused integration bundle: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB15.4geFQB`
- Focused verifier log: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB15.4geFQB/e11-integration.log`
- Focused checksums: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB15.4geFQB/SHA256SUMS`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.WCieYB/quality-report.json`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.WCieYB/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.WCieYB/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.WCieYB/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.WCieYB/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.WCieYB/ci-provenance.json`

The hashes retained in [`CYB-15-artifacts.sha256`](CYB-15-artifacts.sha256)
identify the focused and baseline evidence files.

## Child evidence packets

- [CYB-80 normalized event envelope](CYB-80-normalized-event-envelope-report.md)
- [CYB-81 normalization mapping registry](CYB-81-mapping-registry-report.md)
- [CYB-82 time precision and uncertainty](CYB-82-time-precision-report.md)
- [CYB-83 evidence-linked entity resolution](CYB-83-entity-resolution-report.md)
- [CYB-86 deterministic investigation projections](CYB-86-investigation-projection-report.md)

The parent audit found that CYB-81's focused checksum manifest and baseline
report were attached in Linear but its repository report and manifest were
missing. Commit `0036d5d` repaired that packaging gap using the retained
focused artifacts and clean baseline evidence. No mapping behavior changed.

## Integration acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Original vendor fields remain recoverable from every OCSF-first normalized event. | The CYB-80 closed envelope contract requires canonical `original.fields` and `original.fields_digest`; mappings preserve that section and lineage. The integration trace decodes the pinned vendor fixture, recovers event code, hostname, message, and vendor event ID, then proves the validated API returns defensive copies. |
| Timeline ordering exposes timezone, precision, skew, duplicates, and uncertainty instead of inventing certainty. | CYB-82's EVAL-017 corpus covers timezone, DST, precision, signed skew, duplicate, conflict, partial, gap, and negative-evidence states. The cross-leaf trace builds two missing-timezone records, obtains an `unknown` comparison, and verifies the CYB-86 timeline retains the exact record/comparison digests, unknown precision, missing-timezone code, uncertain relation, and bounded integer confidence. |
| Entity, correlation, hypothesis, and timeline projections reproduce from pinned inputs and transformations. | The integration verifier canonicalizes the mapping outcome and entity observation, validates the immutable entity revision, binds its exact reference plus time identities into projection facts, and replays all three reducers twice under one pinned state version with structurally identical results. |

## Boundary and denial evidence

`internal/domain/e11integration.Verify` independently canonicalizes and binds:

- the CYB-80 normalized envelope and immutable COH-E10 lineage;
- the CYB-81 mapping outcome, manifest, revision, coverage, and output envelope;
- the CYB-83 observation and immutable entity revision;
- the CYB-82 time record and conservative comparison; and
- the CYB-86 fact chain, state version, and three reducer watermarks.

The adversarial integration table mutates mapping-to-envelope,
entity-to-mapping, entity revision, time-to-envelope, time comparison,
projection-to-envelope, projection-to-entity, projection-to-time, and state
mapping bindings. Every mutation is denied. Cancellation propagates as
`context.Canceled`. Architecture verification reports 96 packages and zero
violations.

The verifier exposes no policy, grant, credential, secret, connector,
executor, provider, model, network, filesystem, SQL, shell, raw-evidence, or
generic callback authority.

## Compatibility, migration, and bounded operation

The integrated chain pins leaf contract/method versions, OCSF/ECS versions and
schema commits, mapping manifest/revision, entity head, time method, projection
reducer, and authoritative-state digest. Compatibility is exact. A leaf schema,
canonicalization, mapping, confidence, time, entity, reducer, ordering, or
evidence-binding change requires an explicit new version, migration/privacy
assessment, integration corpus replay, byte comparison, cache invalidation,
and reviewed rollback.

Restart discards in-memory caches, verifies compatible checkpoints, and
replays only a contiguous authoritative tail. Gap, fork, reorder, shrink,
tamper, scope drift, version drift, or divergent result fails closed. Rollback
uses prior supported readers/reducers over immutable evidence and never
rewrites vendor fields, mapping outcomes, time records, entity history, audit,
or provenance.

Large collections remain immutable manifest-bound datasets with row, byte,
page, and duration limits. Paging cannot replace fact order or conservative
time order. Truncation, telemetry gaps, partial collection, and query coverage
remain explicit. Empty results become negative evidence only through a
committed fact that binds the query and completed source coverage.

## Findings and release follow-up

The CYB-86 integration audit added explicit timeline unknown codes. The CYB-15
audit repaired the missing CYB-81 repository evidence packet. Both findings are
closed, and no unresolved blocking finding remains.

Per the approved COH-E01 follow-up, an independent security architecture
review remains required before the first production release.

## Verification summary

The clean focused and 18-stage baseline evidence proves all CYB-15 integration
acceptance criteria at unmodified commit
`0036d5d62586fdba533140bd301d44de52d880e9`.
