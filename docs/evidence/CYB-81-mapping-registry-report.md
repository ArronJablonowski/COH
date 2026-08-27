# CYB-81 normalization mapping registry verification

| Field | Value |
|---|---|
| Stable key | COH-E11-03 |
| Requirements | FR-021, FR-025 |
| Implementation commits | `171c15d` through `e33ab23` |
| Focused artifact root | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81` |
| Clean baseline root | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.zEKaGo` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during clean CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `3c57a11a9757d7b7ae2dc7ec16bf28f59caa8a001786e2a8065bd7b4274b4504` |
| CI report file SHA-256 | `56d742f3d7edbe919c24f537fe6b1e749caebf9f004810b1c469cfb4d49fe356` |

This repository report was added during the CYB-15 integration audit. CYB-81
already retained its focused checksum manifest and baseline report as Linear
attachments, but the matching in-repository report and manifest had been
omitted. The hashes in [`CYB-81-artifacts.sha256`](CYB-81-artifacts.sha256)
close that evidence-packaging gap without changing mapping behavior.

## Evidence locations

- Focused unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81/unit.log`
- Executable vendor corpus: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81/vendor.log`
- Focused repeat output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81/repeat.log`
- Focused race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81/race.log`
- Focused architecture output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81/architecture.log`
- Focused checksums: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/CYB-81/SHA256SUMS`
- Clean baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.zEKaGo/quality-report.json`
- Clean architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.zEKaGo/architecture-report.json`
- Clean race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.zEKaGo/race.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.zEKaGo/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.zEKaGo/ci-provenance.json`

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Mappings are versioned, signed, source-specific, reversible where possible, fixture-tested, and explicit about unmapped fields. | The closed [mapping schema](../../contracts/mapping/v1/normalization-mapping.schema.json), [design](../design/normalization-mapping-registry.md), executable vendor corpus, manifest/signature tests, selection tests, application tests, and lifecycle tests cover exact source matching, revisions, signatures, rule order, reverse results, loss state, and unmapped policy. |
| The Go boundary is narrow, typed, cancellable, idempotent, and has no policy or executor bypass. | Boundary tests restrict signature, source-schema, registry, audit, provenance, and clock ports. Production imports contain no private key, raw evidence, network client, connector, executor, shell, policy source, filesystem path, SQL, or generic callback surface. |
| Invalid input, denial, cancellation/deadline, and recovery preserve provenance and fail closed. | Tests cover malformed and duplicate input, source mismatch, target incompatibility, signature and revocation drift, mapping ambiguity/downgrade, collision, conversion loss, reverse failure, changed replay, timeout/cancellation, restart, lost response, and concurrency. |
| Applicable automated and repository gates pass. | Focused unit/vendor/repeat/race/architecture/file-size artifacts are retained. The clean `b5e4ffa` baseline passed format, size, workflow, worktree/history/evidence secrets, architecture, quality contract, vet, all-check static analysis, unit, race, fuzz seed, license, dependency/vulnerability, SBOM, supply chain, and provenance stages. |
| Evidence cross-references COH-E11-03, FR-021, and FR-025. | The schema, contract README, design, focused verifier, retained artifacts, checksum manifest, Linear attachments, and this report form the evidence packet. |

## Determinism, compatibility, and recovery

The registry selects one exact signed mapping manifest by source identity,
schema, version, target compatibility, revision, validity, and revocation
state. Its data-only language has closed operations, ordered rules, typed
inputs and outputs, bounded values, explicit reversibility/loss metadata, and
no expression or executable extension surface.

Application preserves the complete CYB-80 original vendor section and COH-E10
lineage while emitting deterministic OCSF/ECS siblings, applied rules,
unmapped and lossy paths, reverse-validation results, and typed entity hints.
Exact replay returns the stored canonical result. Changed replay, stale state,
ambiguous selection, substitution, downgrade, or tamper fails closed.

Schema, mapping-language, source-matcher, target OCSF/ECS, signature, key,
revocation, or reverse-semantics changes require an explicit version and
migration assessment. Rollback selects a prior verified manifest and never
rewrites immutable envelopes or evidence. Raw identifiers and evidence remain
outside the registry boundary.

No unresolved blocking finding remains. Per the approved COH-E01 follow-up, an
independent security architecture review remains required before the first
production release.

## Verification summary

The focused mapping corpus and the clean 18-stage baseline prove the CYB-81
acceptance criteria and retain the evidence required by COH-E11 integration.
