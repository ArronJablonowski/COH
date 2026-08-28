# CYB-186 durable model-surface provenance verification report

| Field | Value |
|---|---|
| Issue | COH-E25-04 / CYB-186 |
| Requirements | FR-014, FR-027, FR-038, FR-044, SEC-011, SEC-015, SEC-016, SEC-020 |
| Verification date | 2026-08-28 |
| Verified checkpoint | `e30a65d9fd260169e5fa10a1cc604dacfe7c49d3` |
| Aggregate result | Pass |

## Outcome

COH now constructs every model-visible message, prompt section, tool schema,
retrieved item, compaction replacement, and policy notice as a deterministic
projection of durable typed records or immutable artifacts. The exact ordered
sources, artifact set, vocabulary, composition, rendered surface, provider
route, and current authorization, policy, approval, and audit decisions are
sealed into each inference request before dispatch.

Streaming output retains source lineage and an exact assembled-output digest
for success, empty output, interruption, cancellation, timeout, failure, and
uncertainty. Compaction expands prior replacements to original leaves and
preserves evidence, time/order, negative results, completeness, and uncertainty.
Recovery uses a durable CAS transition chain and reprojects immutable inputs
before replay, resume, fork, fallback, or crash recovery.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Versioned vocabulary distinguishes model surface, log-only, and live coordination | Closed v1 vocabulary schema, compatibility matrix, strict decoder, positive fixture, and denial corpus | Pass |
| Every inference records ordered sources, artifacts, projection/composition, and surface digest | Projection, binding, provider-request schemas; deterministic projector; opaque admitted inference; provider surface gateway | Pass |
| Admission denies missing, mutable, cross-scope, unsupported, hostile, noncanonical, stale, or tampered inputs | Exact resolver ports, trust-disposition rules, reprojection, byte-mutation suite, and adversarial admission tests | Pass |
| Streaming preserves lineage and explicit terminal state | Serialized durable stream session, contiguous sequence, chunk/assembled digests, all eight terminal-state tests, and fallback lineage validator | Pass |
| Compaction is source-covering and metadata-preserving | Authoritative coverage reader, contiguous selection, leaf expansion, immutable summary payload, pressure/overlap/tamper tests | Pass |
| Replay, fork, resume, crash, cancellation, fallback, hostile retrieval, and cross-scope cases pass | CAS recovery controller, exact replay/fork/fallback tests, cancellation tests, reprojected recovery, concurrent CAS, and resolver/projector denials | Pass |
| No production raw-provider bypass exists | `check_model_surface_boundary.sh` and architecture gate: 119 packages, zero dependency violations, zero concrete-adapter imports, zero raw-request bypasses | Pass |
| Required controls are cross-referenced with checksummed evidence | Contract README, design record, this report, focused log, baseline report, and checksum manifest | Pass |

## Integrity and authority boundary

The payload union mirrors the provider-neutral typed content contract without
vendor passthrough, credentials, callbacks, executable authority, or generic
maps. Untrusted retrieval and model content can only become data-role content;
trusted user instructions are distinct from trusted system/control
instructions. Tool definitions remain descriptions and schema digests, never
execution authority.

Production provider dispatch accepts only the opaque result of model-surface
admission. The architecture gate forbids production code outside the provider
boundary from importing concrete adapters or handling raw validated provider
requests. Provider adapters translate an already admitted request but cannot
authorize tools, broker actions, policy, approval, credentials, or E-stop state.

The exhaustive single-byte mutation suite found and closed a dual-digest gap:
compaction decoding now independently verifies both the coverage digest and
replacement digest. Mutating any byte of every positive durable fixture now
either denies or produces a different canonical identity.

## Focused verification

`scripts/verify_model_surface_evidence.sh` passed from a clean checkpoint. It
ran model-surface and provider contract verification, verbose focused suites,
20 repeated runs, race, vet, static analysis, architecture and bypass gates,
worktree secrets, licenses, size, all registered fuzz seeds, two-build release
reproducibility, links, and diff hygiene.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/model-surface.6L7VkI/model-surface.log
SHA-256 e61f072e0c06de49005d3efb7e7d7ce6694abeba1acd9999491c47ced45e91c9
```

The focused gate reported 119 packages and zero architecture violations, 183
Go modules with zero license denials, approximately 12.48 MB scanned with no
secret leak, and all 15 registered fuzz targets executed. A separate bounded
live fuzz run exercised 707,669 generated model-surface decoder inputs without
failure. Release assembly and verification ran twice with byte-identical file
sets; the manifest digest was
`4fca27b30b7a97cd2ec1c0cd1a252dd12828e2eea670d07fa9736b93dd0259a7`
and archive digest was
`6e5c955fc26c69fa03f8b446a10f05338f4692bd0b498a2a79e9e062195c36d3`.

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`: format, file size,
workflow policy, worktree/history secrets, architecture, quality contract, vet,
static analysis, unit, race, fuzz seeds, license, dependencies, SBOM,
supply-chain reproducibility, evidence secrets, and provenance.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.oZog8r/quality-report.json
```

Embedded report digest:
`1ebacdc9b32e7c37889d07984166130ffd3940792625fe0e5d7346fe4ceaa8ba`.
Report-file SHA-256:
`c0266fd484b27e9ceb9b3a5d2742cb5aa6ba635a9135bab4b024b885322da702`.
Provenance records 2,254 source files, source digest
`80e47352a94f73f8a0524b7b430db5ebf963edac7d644755c5d573c260467369`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_model_surface_evidence.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- CYB-185 consumes the completed vocabulary to generate and gate architecture
  catalogs; it must not create a parallel model-surface or provider path.
- Deployment packaging and local Ollama integration remain subsequent leaves
  and must enter providers only through the admitted surface gateway.
- Independent security architecture review remains required before the first
  production release under the approved COH-E01 follow-up.
