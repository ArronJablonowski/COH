# CYB-80 normalized event envelope verification

| Field | Value |
|---|---|
| Stable key | COH-E11-01 |
| Requirements | FR-021, FR-022 |
| Implementation commits | `147678c607ea2078ceb6289382be50c547241a84`, `3dc64c0d75da1686598384bc832d3c342cda7894` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `7abfd2dbd0e0710c415d79e5d1fa0a62c5f78d6d1b4e8a0e5b3b6663c88a3f78` |
| CI report file SHA-256 | `f4b9c0898d61b0e4e8dc5ad29be9137f068d47c2fa0bd7b0e76d1816030b439a` |
| Focused verifier log SHA-256 | `b7f516e1873b76a1a9a2020ed92e59d74e827b8e10bf19e907a3030331d49194` |

## Evidence locations

- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB80.tRe5B9/normalized-event-envelope.log`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/quality-report.json`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/unit.log`
- Fuzz-seed output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/fuzz-seed.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.18vwCl/ci-provenance.json`

The checksums retained in [`CYB-80-artifacts.sha256`](CYB-80-artifacts.sha256)
identify the uploaded log/report and the supporting baseline artifacts.

## Required contract evidence

| Evidence | Retained artifact |
|---|---|
| Schema bundle | [`normalized-event-envelope.schema.json`](../../contracts/normalization/v1/normalized-event-envelope.schema.json), [`compatibility-targets.json`](../../contracts/normalization/v1/compatibility-targets.json), and the executable Go contract under `internal/domain/normalizedevent` |
| Canonical fixture | [`event.canonical.json`](../../contracts/normalization/v1/fixtures/valid/event.canonical.json) and [`dataset-event.canonical.json`](../../contracts/normalization/v1/fixtures/valid/dataset-event.canonical.json) |
| Compatibility matrix | [`compatibility-matrix.md`](../../contracts/normalization/v1/compatibility-matrix.md) |
| Contract-test report | This report, the focused verifier log, and the clean baseline quality report |

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| The versioned envelope retains original bytes and fields, normalized OCSF values, vendor ECS mappings, source, classification, lineage, and schema version. | The closed envelope requires the exact case and source, immutable COH-E10 raw artifact/manifest/receipt/provenance bindings, canonical original vendor fields and digest, OCSF event and digest, explicit nullable ECS projection and digest, classification, pinned compatibility targets, mapping/normalizer identities, transformation digest, and parent lineage. `TestCanonicalFixturesPreserveSourceOCSFAndECS`, `TestChangedFieldsRequireNewSectionAndTransformationDigests`, `TestFixedDecimalValuesRemainLossless`, and `TestEvidenceResolverBindsExactCOHE10Identity` exercise those bindings. |
| Canonical serialization, schema validation, positive/negative examples, versioning rules, and explicit compatibility behavior. | `COH-NJ-1` provides duplicate-key-safe, bounded, exact fixed-decimal canonical JSON. The schema bundle closes COH-owned fields; two positive canonical fixtures cover direct and Parquet-backed records. The eleven-case corpus covers malformed, unsupported, mutated, downgraded, substituted, unsorted, direct-path, and noncanonical-decimal inputs. The compatibility matrix preserves old readers and denies floating upstream compatibility. |
| Invalid input, denial, timeout/cancellation, and recovery do not lose provenance or bypass policy. | Typed contract errors distinguish invalid input, cancellation, timeout, unavailable resolution, and binding conflict. Validation is context-aware. Recovery revalidates exact canonical bytes and COH-E10 bindings. No policy source or grant exists in this package; the evidence resolver verifies identity without releasing bytes. Named tests cover cancellation, expired deadlines, exact recovery, unavailable evidence, cross-tenant substitution, changed transformation, and dataset record substitution. |
| Automated success/failure tests and all applicable CI, race, architecture, secret, license, and size gates pass. | The focused verifier ran unit, 10 repeated, race, vet, architecture, file-size, link, canonical-fixture, schema, target-manifest, and clean-diff checks. The exact unmodified checkpoint `3dc64c0` passed all 18 baseline stages, including static analysis, fuzz seeds, secrets, licenses, dependencies, SBOM, supply chain, and provenance. |
| Required evidence is attached and cross-references CYB-80, COH-E11-01, FR-021, and FR-022. | The schema bundle, canonical fixture, compatibility matrix, focused output, baseline report, checksum manifest, and this report are retained. The requirement trace below names the enforced boundaries. |

## Canonical and schema boundary

The contract pins OCSF `1.9.0` at
`856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba` and ECS `9.5.0` at
`401807e0547301525acd28c4fb667203fec66d59`. The compatibility manifest also
records the downloaded source-archive hashes. Development branches, floating
versions, and implicit additive compatibility are denied.

`COH-NJ-1` preserves exact fixed-decimal telemetry without binary-float
conversion. It retains `COH-CJ-1` ordering, string, array, integer, boolean,
null, duplicate-key, depth, and size rules. Exponents, negative zero,
insignificant leading zeroes, and insignificant fractional zeroes are rejected,
so every accepted number has one representation.

The original, OCSF, and ECS sections have independent canonical digests. The
transformation digest binds those section digests to the target manifest,
mapping set, normalizer, raw artifact, manifest, ingestion receipt, and source
provenance. Changed replay cannot silently rebind one representation.

## Immutable evidence and dataset boundaries

`EvidenceResolver` receives only the exact case, artifact identity, manifest,
receipt, and provenance digest. It exposes no raw bytes, storage locator,
decryption key, policy source, or authorization surface. A mismatched resolved
binding is a conflict, and resolver failure cannot yield a verified envelope.

Partitioned Parquet is referenced only by immutable artifact and manifest
identity, schema digest, bounded partition metadata, logical row position, and
access profile. `ReadDatasetPage` requires a caller deadline and enforces page,
row, byte, case, collection, cursor, completion, and per-record envelope
bindings around the injected `DatasetReader`. Public types expose no path, URL,
SQL, HTTP client, connector, credential, secret, or key reference.

## Adversarial trace

`TestStrictDenialCorpus` maps every retained negative example to its exact
reason: duplicate key, unknown envelope field, unsupported OCSF target, missing
raw manifest, original-field mutation, invalid OCSF type identity,
classification downgrade, changed transformation, unsorted lineage, direct
dataset path, and noncanonical decimal. Additional tests cover mutable-copy
escape, stale section digests, explicit null ECS with partial coverage,
fixed-decimal round trip, cancellation, timeout, recovery, unavailable evidence,
cross-tenant evidence substitution, page-limit overflow, wrong dataset record,
and missing dataset deadline. The registered fuzz seed proves accepted bytes
always recover to the same digest.

## Baseline denial and resolution

The first clean baseline attempt retained at `run.41QOyY` denied the
quality-contract stage because the new fuzz function was not yet present in
the closed `ci/fuzz-targets.txt` inventory. Commit `3dc64c0` registered the
exact package and target. Direct manifest verification passed, the focused
verifier passed from the new clean checkpoint, and the subsequent baseline
passed its fuzz-seed stage and all other stages. The denial was not waived or
discarded.

## Requirement trace

- **FR-021:** OCSF is the required primary normalized event body. Original
  vendor fields, an explicit ECS projection state, immutable raw evidence,
  exact case/source/classification, mapping and normalizer versions, and full
  lineage remain recoverable and independently digest-bound.
- **FR-022:** partitioned Parquet collections are represented by immutable,
  pathless artifact identity and accessed only through a context-aware bounded
  dataset port that enforces row, byte, page, duration, scope, and completeness
  constraints.

## Migration, rollback, and privacy

Target upgrades require a new compatibility decision, corpus replay, migration
assessment, and target-manifest digest. Existing records retain their original
target identities and reader. Rollback disables rejected writers but never
rewrites, relabels, weakens classification, drops vendor fields, or fabricates
a mapping. The envelope contains sensitive metadata and inherits at least the
raw evidence classification. It contains no credentials, key material,
authorization grant, raw evidence bytes, storage path, URL, shell, network
client, or generic callback.

## Verification summary

The clean focused and baseline evidence proves all five CYB-80 acceptance
criteria at unmodified commit `3dc64c0d75da1686598384bc832d3c342cda7894`.
No unresolved blocking finding remains. Independent security architecture
review remains a non-blocking follow-up required before the first production
release under CYB-173.
