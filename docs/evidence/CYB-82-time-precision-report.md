# CYB-82 time precision and uncertainty verification

| Field | Value |
|---|---|
| Stable key | COH-E11-02 |
| Requirements | FR-024, EVAL-017 |
| Implementation commits | `72a498d`, `34f1a88`, `69b1d0f`, `46e783d`, `956e66c`, `5f9bacf` |
| Verified checkpoint | `5f9bacfafd70425f9ae85c1aa3f3d4e97eee4211` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `bc394b847c3e8cc7d24251de391d29aa85081ec6a0b363db1fb64a2789fc1193` |
| CI report file SHA-256 | `332a91728f892d2a047da5faf4103dbb1d1dd0142cf64a38f01e95e006b4cfe2` |
| Focused unit SHA-256 | `a60f3778732a203c1b8d3ba556370378cd331ed174318850fa0eebdd78447371` |
| Focused race SHA-256 | `99f151e3bf6f5e31cc88f3acbecf4cd6a75fdf4c4be393e751ad2d5545ec2096` |
| Service trace SHA-256 | `4ac7394576a5d3fdd7ba87a3c9c771b6f8d960ff74fda459ebaef3e51cf057be` |
| Focused architecture SHA-256 | `eb2612b7a068f3ab0bc2baa280369926dd26889a3900b693bb1dc51ed498eb96` |

## Evidence locations

- Focused unit, repeat, race, architecture, size, and service trace:
  `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB82.929B3A/`
- Baseline report and all 18 stage artifacts:
  `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.naNvY3/`
- Public schema: [`time-normalization.schema.json`](../../contracts/time/v1/time-normalization.schema.json)
- EVAL-017 fixture corpus: [`eval-017.json`](../../contracts/time/v1/fixtures/eval-017.json)
- Design freeze: [`time-precision-and-uncertainty.md`](../design/time-precision-and-uncertainty.md)
- Checksums: [`CYB-82-artifacts.sha256`](CYB-82-artifacts.sha256)

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Retain original string, timezone, normalized UTC, precision, clock source, skew estimate, uncertainty interval, and parser version. | The command and record schemas require the exact original text, closed format and precision, immutable parser identity, timezone assertion and tzdata identity, DST result and candidates, normalized UTC or explicit null, inclusive bounded/unbounded interval, calibration clock identity, signed estimate, and radius. `TestCanonicalCommandRetainsExactBindingsAndSourceText`, `TestBuildRecordAppliesPrecisionSkewAndRadius`, `TestMissingTimezoneAndDSTGapNeverInventUTC`, and `TestDSTFoldRetainsBothCandidatesWithoutSelectingOne` exercise the retained values. |
| Narrow Go interfaces, typed errors, context cancellation, idempotent boundaries, and no policy/executor bypass. | `ports.go` limits evidence verification, parser lookup, timezone resolution, calibration verification, atomic record storage, audit/provenance construction, and clock access. Reflection tests deny unsafe public names. No path, URL, SQL, HTTP client, connector, executor, credential, secret, policy source, shell, callback, or evidence-byte surface exists. `DomainError` exposes closed codes/reasons and cancellation/timeout are preserved. |
| Invalid input, denial, cancellation/timeout, and recovery retain provenance without bypass. | Duplicate JSON keys and unknown fields are denied; parser/tzdata identities and formats are exact; offset mismatch and overflow fail closed. The service writes the canonical command before dependencies, atomically commits record/receipt/audit/provenance, returns the stored receipt on exact replay, resumes a stale begun command, recovers a lost response, and durably records changed replay denial. Cancellation and timeout persist only a terminal receipt through a short non-cancelled recording context. |
| Automated success and failure tests pass all applicable gates. | Focused unit, 10-repeat, race, vet, architecture, file-size, schema, fixture, fuzz-registration, and documentation checks passed. A two-second mutation fuzz run passed. The unmodified checkpoint passed all 18 baseline stages: format, size, vet, static analysis, unit, race, fuzz seed, architecture, quality contract, workflow, worktree/history/evidence secret scans, license, dependency/vulnerability, SBOM, supply chain, and provenance. |
| Required evidence is attached and cross-references CYB-82, COH-E11-02, FR-024, and EVAL-017. | This report, schema, fixture corpus, focused unit/race/architecture outputs, verbose service trace, full quality report, and checksum manifest provide the required unit/integration output, race report, relevant trace, and architecture-boundary proof. |

## Temporal semantics

The source value remains a location-free civil value until an exact timezone
assertion is resolved. Explicit numeric offsets require no tzdata. IANA zones
must match the configured tzdata version and digest; the resolver receives only
locations loaded by trusted assembly code from a verified bundle. Host-local
timezone and dynamic layout parsing are not fallback inputs.

DST gaps produce no UTC candidate. DST folds retain the fold fact and every
candidate unless a source-carried offset is also bound; a selected fold still
retains `dst_state=fold`. Missing timezone and unknown precision/calibration do
not use timestamp sentinels or fabricated UTC. Day precision follows local
civil boundaries, including the exercised 23-hour DST day.

Clock skew is defined as `source clock - reference clock`. For source interval
`[Smin,Smax]`, estimate `E`, and radius `R`, the corrected inclusive interval is
`[Smin-(E+R), Smax-(E-R)]`. Every signed operation is overflow checked and is
denied rather than wrapped or clamped.

Comparison precedence is duplicate, conflicting, unknown, before/after, equal,
then overlap. Strict order is possible only for disjoint bounded intervals.
Intersecting intervals never receive strict order. The comparison binds both
record digests, deduplication identities, confidence, exact rationale, audit,
and provenance.

## EVAL-017 and adversarial trace

The checked-in 15-case executable corpus covers explicit UTC, numeric offset,
DST gap, DST fold, missing timezone, low-precision day, positive and negative
skew, overflow denial, duplicates, uncertain overlap, source conflict, partial
data, negative evidence, and explicit gap evidence. Additional unit/service
tests cover closed parser formats, tzdata mismatch, source-offset mismatch,
canonical mutation, cancellation, timeout, exact replay, changed replay,
concurrency, restart, lost response, comparison persistence, and unsafe public
surface inspection. `FuzzDecodeCommandRoundTrip` is registered in the closed CI
fuzz inventory and proves every accepted mutation recovers identical canonical
bytes and digest.

## Migration, recovery, rollback, and privacy

The initial public schemas use contract `1.0.0`; semantic changes require a new
version, compatibility decision, corpus replay, and migration assessment.
Rollback stops new writers while retaining the v1 reader and all temporal
records. It never rewrites source evidence or normalized history.

The exact source time is classified case evidence and remains in the temporal
record because FR-024 requires it. Audit and error paths contain only immutable
identities, digests, and closed reason codes. Cancellation does not authorize
continued parsing or normalization; only the terminal provenance record is
written. The package contains no credentials, evidence bytes, raw vendor event,
authorization grant, policy source, storage location, or execution surface.

## Verification summary

The focused verifier and clean full baseline prove all five CYB-82 acceptance
criteria at unmodified checkpoint `5f9bacfafd70425f9ae85c1aa3f3d4e97eee4211`.
No unresolved blocking finding remains. Independent security architecture
review remains the approved non-blocking follow-up required before the first
production release under CYB-173.

