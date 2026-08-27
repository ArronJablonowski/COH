# CYB-86 deterministic investigation projection verification

| Field | Value |
|---|---|
| Stable key | COH-E11-05 |
| Requirements | FR-024, FR-025, FR-067, EVAL-017 |
| Implementation commits | `d9c581b` through `b7b70e2` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `e0b19ece9e8a51774fb722f87deff4f028cc210b71095afee42b4000344e3382` |
| CI report file SHA-256 | `522f28bb69ad2f4b0e20eb38d105c809de0c57bf85fa0f70132215a0e22dc651` |
| Focused verifier log SHA-256 | `502c00ef5bcaa676926aeddfe6971b00eaecee0290f4fa29f3b63f2856e8e058` |
| Cached current read | `645.5 ns/op`, `368 B/op`, `2 allocs/op` |

## Evidence locations

- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB86.jjrS76/investigation-projection.log`
- Focused checksums: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB86.jjrS76/SHA256SUMS`
- Focused benchmark: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB86.jjrS76/benchmark.log`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KBLtZx/quality-report.json`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KBLtZx/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KBLtZx/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KBLtZx/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KBLtZx/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KBLtZx/ci-provenance.json`

The retained hashes in [`CYB-86-artifacts.sha256`](CYB-86-artifacts.sha256)
identify the focused and baseline evidence files.

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Projections are deterministic and expose claims, support, counterevidence, unknowns, order, confidence, and completeness. | The closed [projection schema](../../contracts/projection/v1/investigation-projection.schema.json), [design](../design/deterministic-investigation-projections.md), pure reducer suite, and EVAL-017 corpus prove byte-identical correlation, hypothesis, and timeline results at one common watermark. |
| The Go boundary is narrow, typed, cancellable, and grants no policy or execution authority. | `TestProjectionPortsExposeOnlyNarrowDigestBoundRecords` and `TestProjectionProductionImportsNoAuthorityOrDirectIO` prohibit raw content, policy/grant, credential/secret, model, connector, executor, network, filesystem, SQL, shell, and generic callback surfaces. |
| Invalid input, denial, timeout/cancellation, and recovery fail safely. | Tests cover strict decoding, scope/version denial, cancellation, deadline, restart, exact replay, tail replay, lost commit response, concurrency, cache invalidation, missing facts, shrink, fork/gap/reorder, tamper, and divergent results. No failure publishes a newly derived current projection. |
| Automated tests and applicable gates pass. | The focused verifier ran verbose unit/corpus, 10-repeat, race, benchmark, vet, static analysis, architecture, file-size, documentation-link, schema, forbidden-surface, and clean-diff checks. The clean `b7b70e2` baseline passed all 18 stages, including secrets, licenses, vulnerabilities, SBOM, supply chain, and provenance. |
| Evidence cross-references CYB-86 and its requirements. | The schema, design, focused verifier, retained logs, checksum manifest, CI report, and this report reference COH-E11-05, CYB-86, FR-024, FR-025, FR-067, and EVAL-017. |

## Determinism, replay, and zero-I/O cache

Reducers accept only an immutable prior value, one ordered committed fact, and
an exact state version. They use no clock, identity generation, I/O, provider,
model, or hidden mutable state. Semantic no-ops retain the identical value
pointer while the service advances the fact watermark.

The service independently verifies every loaded projection and checkpoint,
then replays only the contiguous forward tail. A first current read verifies
authoritative heads and persists a canonical checkpoint. A repeated read uses
the in-memory path only when the previously validated query, state version,
trusted watermark, checkpoint digest, and projection digest still match.
Trusted head notification invalidates stale entries. The retained benchmark
measured this defensively cloned cache path at 645.5 ns/op and two allocations.

## Uncertainty and adversarial trace

The EVAL-017 corpus preserves DST/clock-skew uncertainty, missing timezone,
low precision, uncertain order, duplicates, gaps, source conflicts, partial
collection, counterevidence, and bounded negative evidence. Timeline entries
retain explicit uncertainty codes plus exact CYB-82 time-record, comparison,
precision, and uncertainty digests. No empty result or telemetry gap is
silently converted into negative evidence or certainty.

The adversarial suite also covers malformed, unknown, duplicate, and oversized
records; missing confidence; scope and state drift; log gap, fork, reorder, and
shrink; checkpoint and projection tamper; concurrent builders; lost commit
responses; caller mutation; cache invalidation; and divergent rebuilds.

## Migration, rollback, privacy, and release follow-up

The initial schema, contract, and reducer are version `1.0.0`. Any schema,
meaning, ordering, confidence, completeness, upstream binding, or canonical
change requires a new state version and corpus replay. Rollback rebuilds from
immutable authoritative facts and may discard every projection cache; it does
not rewrite evidence. Projection data inherits the highest bound fact
classification, and v1 cannot silently add cross-case matching, raw evidence,
model authority, connector access, or action authority.

No unresolved blocking finding remains. Per the approved COH-E01 follow-up, an
independent security architecture review remains required before the first
production release.

## Verification summary

The clean focused and baseline evidence proves all CYB-86 acceptance criteria
at unmodified commit `b7b70e2467f16fff6cce650878000db7fc789e24`.
