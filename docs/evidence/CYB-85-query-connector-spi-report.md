# CYB-85 query connector SPI verification

| Field | Value |
|---|---|
| Stable key | COH-E12-01 |
| Requirements | FR-045, FR-054 |
| Implementation commits | `3cd3236`, `fcb9412`, `996ea7f` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `dfaadaf10b5bc2cbc8019c7fdc16ebc4ac3275720f0fe092564221c9080f007a` |
| CI report file SHA-256 | `e25a4f5ec7b8938fb338e365e6ed4ee6cd284499b792f7f2b13be7899af5f66f` |
| Canonical query digest | `sha256:ff6772b072314987ca4e6b001e4f4e38968d7c7599f1c883e81feadfd01df259` |

## Evidence locations

- Contract schema: `contracts/query/v1/query-connector.schema.json`
- Canonical fixture: `contracts/query/v1/fixtures/valid/query.canonical.json`
- Denial corpus: `contracts/query/v1/fixtures/denial-corpus.json`
- Compatibility matrix: `contracts/query/v1/compatibility-matrix.md`
- Focused evidence: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB85.CInBtv`
- Focused checksum manifest: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB85.CInBtv/SHA256SUMS`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.5pbbXY/quality-report.json`
- Baseline architecture, race, unit, fuzz, vulnerability, and provenance artifacts are retained beside that report.

The hashes in [`CYB-85-artifacts.sha256`](CYB-85-artifacts.sha256) identify the
contract bundle plus focused and baseline evidence.

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| The SPI defines every required lifecycle operation and typed record. | `internal/domain/queryconnector` defines capability probe, schema discovery, validation, execute, poll, next page, cancel, nonzero typed limits, completeness, statistics, and digest-only opaque handle references. The interface accepts and returns immutable validated documents. |
| Canonical serialization, schema validation, examples, versioning, and compatibility are explicit. | The draft 2020-12 bundle rejects unknown fields and pins eight record schemas. COH-CJ-1 decoding, domain-separated SHA-256, the pinned canonical fixture, ten-case denial corpus, README, and compatibility matrix cover exact-reader and migration behavior. |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance and cannot bypass policy. | Strict decoder and lifecycle tests reject missing authority/scope/limits/capability, reversed ranges, version drift, mutation surfaces, mutable capability, hidden partial results, raw vendor handles, reasonless denial, validator substitution, and canceled admission. `AdmitExecution` requires an accepted decision bound to the exact query ID and canonical digest. |
| Automated and repository gates pass. | Focused verbose, 10-repeat, race, vet, static analysis, architecture, file-size, quality-contract, schema/corpus, and fuzz-seed checks passed. The clean `996ea7f` baseline passed all 18 stages, including secrets, licenses, vulnerabilities, SBOM, supply-chain, and provenance. |
| Required verification evidence cross-references the leaf and requirements. | This report, schema bundle, fixture, compatibility matrix, contract tests, retained logs, checksum manifest, and clean CI report identify COH-E12-01, CYB-85, FR-045, and FR-054. |

## Read-only and authority boundary

The shared surface has no generic HTTP, headers, credentials, API keys, vendor
tokens, mutation methods, URL, passthrough object, or untyped option map. Every
capability must assert `read_only: true`. Authority is represented only by
actor, authorization, policy-decision, and audit-reservation digests supplied
by the trusted COH-E05 boundary. The contract does not mint or widen them.

Opaque vendor job and paging values stay inside adapters. Shared records carry
only a scoped UUIDv7 handle identity, kind, source, domain digest, issue time,
and expiry. Query execution cannot be admitted from a denied validation or a
validation bound to different canonical query bytes.

## Completeness and recovery

Complete, partial, truncated, unknown, and vendor-confirmed state are explicit;
row count cannot manufacture completeness. Statistics retain scanned/returned
rows, bytes, duration, page, slice, and cost values. Timeout or cancellation
publishes no partially decoded document. Revalidation of the same immutable
query recovers the identical canonical digest.

The first full baseline correctly denied completion because the new fuzz target
was absent from `ci/fuzz-targets.txt`. Commit `996ea7f` registered the target;
the focused quality-contract test and subsequent clean 18-stage baseline both
passed. The failed run is diagnostic history, not acceptance evidence.

## Migration, rollback, and release follow-up

Unknown versions and fields fail closed. Even an optional field requires
mixed-reader proof. Removed, renamed, retyped, reinterpreted, canonical, digest,
or opaque-handle changes require a new major contract and lineage-bearing
migration. Rollback restores the prior reader, schema, and adapter together and
never rewrites query evidence.

No unresolved blocking finding remains. An independent security architecture
review remains required before the first production release.

## Verification summary

The focused and baseline evidence proves all CYB-85 acceptance criteria at
clean commit `996ea7f0dd71e2fa13d8f2438494b9445493f257`.
