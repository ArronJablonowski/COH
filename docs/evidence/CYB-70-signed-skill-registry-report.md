# CYB-70 signed and reviewed skill registry verification

| Field | Value |
|---|---|
| Issue | COH-E09-01 / CYB-70 |
| Requirements | FR-042, FR-043, SEC-018 |
| Implementation commit | `b8e4b52cd1e3285c647182165f771ec78b21ae36` |
| Deadline-control prerequisite fix | `bf90267fd57717d73b1a1aa4d6386fc7c8434d18` |
| Verification date | 2026-08-26 |
| Result | Pass |

## Delivered boundary

The implementation adds a strict signed skill package contract, independently
signed review, owner-signed promotion/rollback/revocation commands, exact
policy and access decision digests, durable optimistic registry state,
immutable version storage, fail-closed tamper-evident audit projection, and a
narrow read-only agent lookup activity.

Production availability requires this complete chain:

1. canonical bounded v1 manifest and command decoding;
2. exact content, resource, permission, test, threat-model, validity, owner,
   review, and predecessor bindings;
3. domain-separated Ed25519 publisher, reviewer, and owner signatures against
   current active approved authority and key/approval revisions;
4. recomputed policy decision digest and exact actor/organization/tenant/case/
   task/action/skill/manifest binding;
5. current optimistic state and predecessor binding;
6. durable audit success and exact receipt;
7. chained canonical provenance; and
8. one atomic guarded-repository commit of state and any new immutable version.

Resolution recomputes the access decision digest, requires the exact current
promoted manifest and permission, re-verifies current publisher and reviewer
authority, appends audit, and returns copied digests and bounded resource
metadata only. No content bytes, writable path, URL, credential, connector,
executor, model, policy evaluator, filesystem capability, or generic callback
is present in the result.

## Public contracts and documentation

- `contracts/skill/v1/skill-manifest.schema.json`
- `contracts/skill/v1/signed-skill-manifest.schema.json`
- `contracts/skill/v1/skill-registry.schema.json`
- `contracts/skill/v1/README.md`
- `contracts/skill/v1/compatibility-matrix.md`
- `docs/design/signed-skill-registry.md`

The Go implementation is in `internal/workflow/skillregistry`. The durable
SQLite close/reopen integration test is in
`internal/persistence/sqlite/skillregistry_integration_test.go`. Agent
orchestration consumes only
`internal/workflow/agentloop/skill_lookup.go`.

## Adversarial and recovery verification

| Control | Evidence | Result |
|---|---|---|
| Strict decode | Unknown, duplicate, trailing, malformed, unsupported, oversized, and semantic byte-drift checks | Pass |
| Manifest integrity | Manifest/content/resource digest change and signature tamper | Pass |
| Publisher authority | Revoked publisher and approval-revision rollback | Pass |
| Independent review | Exact reviewer set, active authority, distinct identities, review evidence, and reviewer signatures | Pass |
| Owner change authority | Domain-separated signed promotion, rollback, and revocation command | Pass |
| Policy | Recomputed decision digest plus exact scope/action/manifest; mismatch and digest tamper denied before audit/state | Pass |
| Promotion audit | Audit unavailable or invalid receipt prevents durable visibility | Pass |
| Durable state | Optimistic revision, canonical provenance, state-result validation, and guarded repository transaction | Pass |
| Immutable versions | Digest-addressed version collision denied; later promotion, rollback, and revocation never rewrite bytes | Pass |
| Resolution scope | Exact actor, organization, tenant, case, task, manifest, permission, policy, and deadline | Pass |
| Read-only result | Owned copies and surface reflection deny content and authority-bearing handles | Pass |
| Live revocation | Revoked registry state and revoked current publisher/reviewer authority stop new resolution | Pass |
| Replay | Exact replay returns identical provenance; changed replay and stale state denied | Pass |
| Crash/restart | Lost commit response recovers without another transition; SQLite close/reopen preserves exact state and envelope bytes | Pass |
| Cancellation/timeout | Typed cancellation, timeout, expired command, and audit/store dependency failure remain fail-closed | Pass |
| Agent integration | Lookup forwards exact bindings and exposes no action, broker, connector, executor, filesystem-write, model, or generic callback port | Pass |

The focused trace is retained at:

`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/skill-registry/run.ZmEZ3j/skill-registry.log`

SHA-256:
`2aa5690bc1e04801a6a3e1abe9e9b5bc3b8e3e24a852a2d42dd02611b96f1c0c`

The trace includes focused verbose tests, ten repeated package runs, race
tests, vet, architecture enforcement, file-size enforcement, and the durable
SQLite restart test.

## Full baseline gate

The clean baseline report is retained at:

`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.yWbDr0/quality-report.json`

| Property | Value |
|---|---|
| File SHA-256 | `30f70a9f54cbe5bf4218b5b32f3195995b3043baa27201038428dd3ee7d9c8e1` |
| Embedded report digest | `55aa8567376d4153b1af2b389e7896d756720e798e2e644017e0ebf2eb6a804c` |
| Source digest | `fcb90854e4006ac83fc6e34bfa989e13376737e6fb68747892d0cc8e4fd97864` |
| VCS revision | `b8e4b52cd1e3285c647182165f771ec78b21ae36` |
| VCS modified | `false` |
| Outcome | `passed` |
| Quality-gate promotable | `true` |

All 18 required stages passed: format, file size, workflow policy,
worktree/history/evidence secret scans, architecture, quality contract, vet,
static analysis, unit, race, fuzz seeds, license, dependency/vulnerability,
SBOM, supply chain, and provenance.

## Acceptance criteria

| Criterion | Evidence | Result |
|---|---|---|
| Immutable versions, signatures, owners, permissions, tests, promotion state, rollback, and read-only production consumption | Frozen schemas; controller; repository adapter; lookup activity; success/rollback/revocation tests | Pass |
| Default deny, actor/scope binding, secret redaction, fail-closed audit, replay/tamper/stale/revocation handling | Validation/signature/audit adapters; denial suite; surface tests; durable restart | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance and policy | Typed errors; cancellation/timeout tests; lost-response and SQLite restart recovery | Pass |
| Applicable automated CI, race, architecture, secret, license, dependency, and size gates | Focused trace and clean 18-stage baseline | Pass |
| Adversarial trace, policy decision, approval/audit proof, and denial/revocation evidence cross-reference COH-E09-01 and FR-042/FR-043/SEC-018 | This report, focused trace, source manifest, and artifact hash manifest | Pass |

## Follow-up gate

CYB-173 remains the independent security architecture review required before
the first production release. It is not an unresolved CYB-70 implementation
finding.
