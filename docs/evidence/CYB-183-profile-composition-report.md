# CYB-183 signed profile-composition verification report

| Field | Value |
|---|---|
| Issue | COH-E25-02 / CYB-183 |
| Requirements | NFR-003, NFR-019, SEC-018, SEC-033, SEC-034, EVAL-029 |
| Verification date | 2026-08-28 |
| Verified checkpoint | `3ce94719c3e2401e949024f25b66202195d054ee` |
| Aggregate result | Pass |

## Outcome

COH now composes signed, ordered, data-only profile layers into one exact,
immutable resolved profile, one closed capability graph, and one redacted
inspection record. Native workstation, native server, Compose, connected,
restricted, air-gap, Web, CLI, API, headless, and test operation share the same
versioned v1 contract and command-root implementation.

Activation is a separately sealed, durable startup or maintenance transition.
It stops admissions, proves quiescence, atomically publishes the active profile,
and only then resumes admissions. Live hot reload and every alternate authority
path deny closed.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Native workstation/server and Compose, including air-gap and Web/CLI/API/headless/test, use one versioned contract | Five v1 schemas, contract README, compatibility matrix, and `TestProfileCompositionDeploymentAndSurfaceParityMatrix` | Pass |
| Canonical output is deterministic and byte-identical across supported targets and input order | Stable topological ordering, COH-CJ-1 digests, sequential replay, concurrent replay, and parity matrix | Pass |
| Unknown members, cycles, ambiguity, unsigned/untrusted/revoked input, rollback, widening, secrets, cancellation, and alternate entry points deny publication | Strict decoders, 15-case denial corpus, resolver/command denials, rollback tests, architecture gate, and forbidden-field verifier | Pass |
| Inspection exposes exact nodes, edges, lineage, versions, qualifications, limits, and digests without secrets, raw evidence, prompts, or private paths | Closed inspection schema, owned canonical projection, malformed-projection tests, and forbidden-field verifier | Pass |
| Security-critical activation is quiescent and durable; hot reload is denied | Sealed phase controller, SQLite CAS store, false-quiescence/cancellation/hot-reload/tamper tests | Pass |
| First install, startup, interruption, restart, upgrade, authorized rollback, air-gap, and cross-surface parity pass | Fresh SQLite migration, five lost-response restart boundaries, upgrade/replay tests, end-to-end rollback, and target matrix | Pass |
| Evidence cross-references COH-E25-02 and all required controls | Contract README, design, this report, and checksum manifest | Pass |

## Determinism, trust, and authority boundary

Each layer is Ed25519-signed over a domain-separated canonical digest. Publisher
and reviewer signatures bind exact signer identity, key revision, purpose,
validity, trust environment, and revocation revision. Trust snapshots older than
five minutes, scope mismatch, unknown or revoked keys, signature drift, or
unsigned input deny composition. Provenance is never activation authority.

The resolver requires one baseline and a closed acyclic parent graph. Its stable
total order and field-specific narrowing rules make input permutation irrelevant:
references are exact and canonically sorted, endpoint and permission sets can
only intersect, numeric limits can only decrease, features can only turn off,
and air-gap operation requires one exact offline-bundle digest. Capability
qualification is revalidated against the current trust and revocation state.

The command root accepts only validated resolved-profile, graph, and inspection
values. Architecture checker v0.3.0 examined 117 packages with zero violations.
At the clean focused checkpoint it recorded `vcs_modified=false` and bound the
result to `3ce94719c3e2401e949024f25b66202195d054ee`.

## Activation, recovery, and rollback proof

The activation record advances through `prepared`, `quiescent`, `published`,
and `active` phases. The SQLite store persists intent before quiescence and
atomically publishes the active pointer with the transition. Exact replay is
idempotent; competing exact activations converge; a changed or tampered request
denies. Tests close and reopen SQLite after a lost response at create, quiescent
advance, publish, admissions release, and active advance.

Normal upgrades require the active predecessor and monotonic revision. The
end-to-end rollback test activates revisions 1, 2, and 3, then re-verifies and
publishes revision 1 only with a current scope-exact signed rollback decision.
Earlier successful verification is never reused as current authority.

## Focused verification

`scripts/verify_profile_composition.sh` passed from the clean verified
checkpoint. It validates all schemas and fixtures, rejects forbidden payload and
authority fields, runs focused tests, 20 repeated runs, race, vet, static
analysis, architecture, worktree secrets, licenses, size, links, all registered
fuzz seeds, and diff hygiene.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/profile-composition.TuSQ86/profile-composition.log
SHA-256 3943167346da5089dce5484199d50c0afbd87dfbfb895e58010d518018847339
```

The focused license inventory covered 183 Go modules, two module notices, and
two shipped inputs with zero denials. The secret scan covered approximately
11.97 MB and found no leaks. All 12 registered fuzz targets executed their seed
callbacks, including three profile-activation and two profile-composition seeds.
Separate live fuzz sessions exercised approximately 15,000 activation and
46,000 composition inputs without a failure.

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`: format, file size,
workflow policy, worktree and history secrets, architecture, quality contract,
vet, static analysis, unit, race, fuzz seeds, license, dependencies, SBOM,
supply chain, evidence secrets, and provenance.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.ZVy0Lv/quality-report.json
```

Embedded report digest:
`8b9c12be19d34c95356a2acbe6dd322321c0b31fafffb4a59c08bf492788d4fd`.
Report-file SHA-256:
`0a05b922d1126e2992c40a4ba546f96aeec960542431f13aa5930dd23f3939bf`.
Provenance records 2,171 source files, source digest
`2d3ea690b6ad882121528674b8986f2b39e4b339423c3f3fd25276ec1aeeca2e`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_profile_composition.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- CYB-184 owns transactional extension activation and reverse unwind; it must
  consume this profile only through the validated command-root boundary.
- Deployment packaging and local Ollama model integration remain subsequent
  leaves; they must preserve this exact composition and activation contract.
- Independent security architecture review remains required before the first
  production release under the approved COH-E01 follow-up.
