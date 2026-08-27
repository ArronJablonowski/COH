# CYB-83 evidence-linked entity resolution verification

| Field | Value |
|---|---|
| Stable key | COH-E11-04 |
| Requirement | FR-025 |
| Implementation commits | `7e380a1` through `849f83e` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `039e561f4533ef7ae15ac2b89cdc4d6ef90ef7fe26a49334b98510a53efa9372` |
| CI report file SHA-256 | `72c0ca7add1d96c906f0cefda3286528440a29b69f7ba2d09bfe0a2a6119d4e5` |
| Focused verifier log SHA-256 | `eb2ad24491c00e6f46d6dc6801463bfb0755fee5fb6f65cfa10e827809b1c92a` |

## Evidence locations

- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB83.9L4RPi/entity-resolution.log`
- Focused artifact checksums: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB83.9L4RPi/SHA256SUMS`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/quality-report.json`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/unit.log`
- Fuzz-seed output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/fuzz-seed.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.3ZD96r/ci-provenance.json`

The checksums retained in [`CYB-83-artifacts.sha256`](CYB-83-artifacts.sha256)
identify the focused log, quality report, and supporting baseline artifacts.

## Required contract evidence

| Evidence | Retained artifact |
|---|---|
| Closed schema bundle | [`entity-resolution.schema.json`](../../contracts/entity/v1/entity-resolution.schema.json) and [`README.md`](../../contracts/entity/v1/README.md) |
| Executable identity fixture | [`identity-method-v1.json`](../../contracts/entity/v1/fixtures/identity-method-v1.json), canonical digest `sha256:2ba2c987ef57b7edc98650985727890fe69224be794a7a1095375fe4d052132c` |
| Executable confidence fixture | [`confidence-method-v1.json`](../../contracts/entity/v1/fixtures/confidence-method-v1.json), canonical digest `sha256:8d23a955b9dbe1421912110420558383bf903112aa56e3c4e231fef94c09e2d6` |
| Design and recovery contract | [`evidence-linked-entity-resolution.md`](../design/evidence-linked-entity-resolution.md) |
| Focused verifier | [`verify_entity_resolution.sh`](../../scripts/verify_entity_resolution.sh) |

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Entity candidates use typed identifiers, provenance, confidence, merge and split history, counterevidence, and case-local scope. | The closed schema and executable Go records bind exact typed identity, case-keyed match digest, CYB-80/CYB-81/COH-E10 evidence identities, integer confidence components, counterevidence, immutable entity revisions, multi-parent provenance, and digest-linked merge/split history. Service tests execute observe, resolve, merge, and reversal by split. |
| The Go implementation uses a narrow interface, typed errors, context cancellation, idempotent boundaries, and no direct policy or executor bypass. | `TestNarrowPortsExposeNoUnsafeSurface` and `TestProductionPackageImportsNoAuthorityOrDirectIO` prove the ports expose no raw identifier, evidence byte, policy source, connector, executor, model, filesystem, network, SQL, shell, or generic callback. Error codes and cancellation/deadline paths are closed and typed. |
| Invalid input, denial, timeout/cancellation, and recovery do not lose provenance or bypass policy. | Invalid commands fail before durable begin. Merge/split require exact current revisions and a narrow current authorization decision. Cancellation, timeout, and unavailable dependencies atomically persist terminal outcomes. Restart, stale begin, concurrent execution, lost response, exact replay, changed replay, and tampered replay are exercised without duplicate mutation. |
| Automated success/failure tests and all applicable gates pass. | The focused verifier ran verbose unit, fixture, 10-repeat, race, vet, static-analysis, architecture, file-size, documentation-link, schema, fixture-digest, forbidden-surface, and clean-diff checks. The exact clean checkpoint `849f83e` passed all 18 baseline stages, including repository-wide unit/race, secrets, licenses, dependencies/vulnerabilities, SBOM, supply chain, and provenance. |
| Verification evidence cross-references CYB-83, COH-E11-04, and FR-025. | The schema, design, fixtures, focused verifier, retained logs, clean baseline report, checksum manifest, and this report form the evidence packet. |

## Identity, confidence, and privacy boundary

The resolver receives no raw identifier. The case-scoped derivation boundary
owns a non-exportable key and verifies the pinned HMAC-SHA-256 construction.
The executable identity fixture freezes all nine allowed role, identifier-type,
and normalization pairs. Cross-case, cross-tenant, type-confused, malformed,
unbound, downgraded, and ambiguous returned records fail closed.

Confidence uses ordered signed integer-millionth components, never floating
point. The method fixture freezes exact-match, source-independence, quality,
recency, ambiguity, counterevidence, ceiling, clamping, and label behavior.
Durable confidence assessments make every accepted score recomputable after a
restart; a caller cannot silently submit an upgraded score.

## Immutable history, provenance, and recovery

An entity reference hashes an immutable entity-revision core. Lifecycle
decision, history, audit, and provenance bindings are layered onto the stored
record without a cryptographic cycle. Merge creates one new active entity,
supersedes every input, binds every distinct input history and provenance head,
and never rewrites an observation. Split partitions every member and alias
exactly once, supersedes the input, creates new entities, and persists the exact
history event being reversed or corrected.

The durable boundary atomically commits the canonical command, generated
identities, observation/candidate or decision/history, entity revisions,
outcome, receipt, audit, and provenance. Exact replay revalidates the complete
stored commit. Changed replay is durably denied. Lost-response recovery loads
the committed result instead of blindly retrying a merge or split. A stale
begun record resumes only from identities already frozen in the command.

## Adversarial trace

The retained suite covers invalid generated identities, nil durable arrays,
scope and confidence-assessment drift, unknown/duplicate/oversized canonical
input, case and tenant mismatch, type confusion, weak classification,
ambiguous matching, confidence ceilings, source double-counting, mutated
counterevidence, blocking counterevidence, stale revisions, denied authority,
output collisions, cyclic aliases, incomplete/overlapping split partitions,
unknown reversals, dependency failure, cancellation, timeout, concurrency,
restart, lost responses, changed replay, and mutation of stored command,
candidate, outcome, receipt, audit, and provenance records.

## Migration, rollback, extension, and release follow-up

The initial contract and identity/confidence methods are version `1.0.0`.
Changing identifier types, normalization, key derivation, confidence weights,
counterevidence, state transitions, or cross-case behavior requires a new
compatibility decision, migration, and complete corpus replay. Rollback stops
new mutation but never deletes or reinterprets immutable observations, entity
revisions, history, audit, or provenance. Extensions cannot add raw identifier,
model matching, direct access, or wider authority to v1.

No unresolved blocking finding remains. Per the approved COH-E01 follow-up, an
independent security architecture review remains required before the first
production release.

## Verification summary

The clean focused and baseline evidence proves all CYB-83 acceptance criteria
at unmodified commit `849f83e1ad4b0e099f8080cc27de8bca6ba932c4`.
