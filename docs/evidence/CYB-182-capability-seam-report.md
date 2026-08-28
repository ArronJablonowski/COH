# CYB-182 typed capability-seam verification report

| Field | Value |
|---|---|
| Issue | COH-E25-01 / CYB-182 |
| Requirements | NFR-019, NFR-026, FR-018, FR-031, SEC-001, SEC-002 |
| Verification date | 2026-08-28 |
| Verified checkpoint | `fab140323a0ed4c99638258edbfa8a41e4783c7b` |
| Aggregate result | Pass |

## Outcome

COH now has a strict v1 composition boundary with distinct service-definition,
qualified-provider, and consumer roles. The resolver closes exact identities,
dependencies, scopes, permissions, lifecycle, qualification, and revocation
state into one deterministic immutable graph or publishes no graph.

Registration and resolution return no implementation, callback, credential,
lease, runner, connector, approval, or execution capability. Model-originated
operations remain typed broker intents. Ten compiled authority services remain
non-replaceable: broker, policy, approval, audit, credential, evidence, E-stop,
runner, connector, and validator.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Typed schemas and Go records cover identity, version, owner, provider artifact, consumer, scope, permissions, dependencies, lifecycle, compatibility, qualification, and graph digests | v1 bundle/graph schemas, fixtures, `internal/domain/capabilityseam` strict records and validators | Pass |
| Missing/duplicate providers, undeclared consumers/edges, cycles, incompatible versions, widening, stale/revoked qualification, and unknown members deny publication | Strict decoder, closed-graph resolver, denial corpus, resolution and qualification denial tests | Pass |
| Registration grants no action authority; model operations remain broker intents | Schema-closed access policy, immutable redacted graph, reserved broker test, forbidden-field verifier | Pass |
| Ten authority services are compiled and non-replaceable | Reserved authority catalog and exhaustive catalog/alias/owner/provider denial tests | Pass |
| Positive/negative fixtures, fuzz, race, architecture, replay/tamper/revocation, migration, and rollback evidence pass | Focused verifier log and clean baseline report listed below | Pass |
| Evidence cross-references COH-E25-01 and required NFR/FR/SEC controls | Contract README, design, this report, and checksum manifest | Pass |

## Determinism and authority boundary

The v1 resolver uses exact capability versions and stable lexical topological
ordering. One hundred sequential trials and 64 concurrent workers produce
byte-identical canonical graphs and digests. Missing dependencies, provider
ambiguity, dependency cycles, permission or scope widening, lifecycle widening,
and broker-route drift fail closed.

Every selected provider is bound to a maximum-five-minute trusted live snapshot:
bundle digest, composition revision, profile digest, provider identity/version/
artifact, capability identity/version, qualification record identity/digest and
validity, registry revision, qualification-authority revision, current revocation
revision, and active state. The snapshot is an in-memory composition-root value,
not JSON or provider/model input, and contains no executable authority.

Architecture checker v0.2.0 enforces `ARCH-003`: only command composition roots
and broker roots may import the capability-seam package. The inactive-build-tag
negative fixture proves workflow, provider, transport, and helper bypasses are
denied. At the verified checkpoint the architecture gate examined 115 packages,
reported zero violations, and recorded `vcs_modified=false`.

## Adversarial and recovery proof

Named tests cover duplicate and unknown JSON members, missing fields, unsupported
versions, unsorted/duplicate sets, graph-digest tamper, provider/profile/artifact
drift, stale/future/expired authority snapshots, missing/reordered/duplicated live
records, inactive and revoked providers, exact authority-revision drift, prior
success followed by revocation, cancellation with no graph, forward migration,
stale-revision rollback denial, and explicitly reauthorized rollback.

The registered fuzz target accepts valid bundle and graph seeds, canonicalizes
accepted inputs, and requires their replay digests to remain identical. The
repository fuzz-seed gate executed all ten registered targets, including the two
capability-seam seeds.

## Focused verification

`scripts/verify_capability_seams.sh` passed from the clean verified checkpoint.
It runs schema/fixture/forbidden-field checks, verbose focused tests, 20 repeated
runs, race, vet, static analysis, architecture, worktree secret scanning,
license inventory, size, links, fuzz seeds, and diff hygiene.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/capability-seam.FRywbh/capability-seam.log
SHA-256 c3bae05e3c5479e9c6c314e33fbfa1412f93df1b0bc96998d828c37587ad37ec
```

The focused license inventory covered 183 Go modules, two module notices, and
two shipped inputs with zero denials. The secret scan covered approximately
11.72 MB and found no leaks.

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`: format, file size,
workflow policy, worktree and history secrets, architecture, quality contract,
vet, static analysis, unit, race, fuzz seeds, license, dependencies, SBOM,
supply chain, evidence secrets, and provenance.

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.ARxezG/quality-report.json
```

Embedded report digest:
`c610dc4dbcd0b2a6cc29371bf6a4e0b65044c224c9265918e2ea6f5670a88132`.
Report-file SHA-256:
`4627af956fe6791e6b603fb67c0e70ec18b6d3fdbf8eb4866443b3ba5a380877`.
Provenance records 2,127 source files, source digest
`30c42a22ffd3d975d1406395c8a2168210743e3b0c76006c35321e96824c714c`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_capability_seams.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This leaf defines and enforces composition; signed profile composition,
  transactional extension lifecycle, model-surface provenance, and generated
  catalogs remain the subsequent COH-E25 leaves.
- Transactional activation cannot use this graph as action authority and must
  repeat current qualification/revocation and broker-routing checks.
- Independent security architecture review remains required before the first
  production release under the approved COH-E01 follow-up.
