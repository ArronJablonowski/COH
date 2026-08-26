# CYB-53 signed tool registry contract-test report

| Field | Value |
|---|---|
| Issue | COH-E06-01 / CYB-53 |
| Requirements | SEC-005, SEC-018 |
| Verification date | 2026-08-26 |
| Implementation checkpoint | `2f49ddaceedcfb179892b1619d5f18b83472800f` |
| Manifest contract | `coh.tool-manifest/v1` / `1.0.0` |
| Envelope contract | `coh.signed-tool-manifest/v1` / `1.0.0` |
| Aggregate result | Pass |

## Outcome

The registry admits only current, schema-valid, reviewed tool manifests signed
by a current active approved publisher. It binds exact tool/version/artifact
identity, typed inputs, operation baseline and maximum tiers, isolation and
credential classes, finite resource limits, restrictive network policy,
cancellation, retry, threat-model review, and validity into one canonical
SHA-256 identity.

Exact name/version admission is immutable. Exact retry recovers the original
entry; changed canonical bytes conflict and cannot replace it. Every lookup
re-verifies the stored signed bytes, current publisher authority, publisher
approval revision, validity, and requested artifact digest. Revocation, key
rotation, approval rollback, expiry, or digest mismatch therefore takes effect
without restart.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Admit only signed, reviewed manifests with typed inputs, tiers, isolation, resources, network policy, and immutable digest | Strict schemas; `Decode`, `Validate`, and `Verify`; deterministic signed fixture; `TestCanonicalSignedManifestAndOwnedCopies`; `TestManifestControlDenials` | Pass |
| Canonical serialization, schema validation, positive and negative examples, versioning, and explicit compatibility | Two Draft 2020-12 schemas, COH-CJ-1 decoder, canonical manifest and envelope fixtures, 12-case denial corpus, and `compatibility-matrix.md` | Pass |
| Invalid input, denial, timeout, cancellation, and recovery preserve provenance and policy | Typed errors; immutable snapshots; admission provenance result; `TestRegistryCancellationTimeoutAndConcurrentReplay`; collision/expiry recovery; live publisher revalidation; tier-ceiling tests | Pass |
| Automated success/failure tests and applicable quality gates | Focused, race, vet, static analysis, all unit packages, architecture, size, secret, license, dependency, SBOM, and supply-chain stages passed | Pass |
| Required evidence attached and cross-referenced | This report identifies the schema bundle, canonical fixtures, compatibility matrix, verifier log, exact clean commit, and baseline report | Pass |

## Schema bundle and canonical fixtures

The public schema bundle is:

- `contracts/tool/v1/tool-manifest.schema.json`;
- `contracts/tool/v1/signed-tool-manifest.schema.json`;
- `contracts/tool/v1/fixtures/valid/query-tool.manifest.json`;
- `contracts/tool/v1/fixtures/valid/query-tool.signed.json`; and
- `contracts/tool/v1/fixtures/denial-corpus.json`.

The manifest and signed envelope fixtures are byte-for-byte COH-CJ-1
canonical. Their manifest digest is
`sha256:f2c5e4239f4484dc92258196a61bdeb1026d4ec4b19b3e3e6d2b9555589519a3`.
The envelope signature uses deterministic test-only Ed25519 material and the
domain `COH-SIGNED-TOOL-MANIFEST-V1\0`. Private key material is not a contract,
fixture, registry, decision, or evidence field.

## Typed operation and sandbox contract

The v1 input vocabulary is finite: boolean; bounded integer and duration;
bounded string; UUID; digest; timestamp; and bounded string/digest lists.
Unknown generic JSON, missing nested names, null arrays, duplicate or unsorted
fields, invalid enum constraints, and unknown capability types are rejected.

Every operation declares bounded wall time, CPU, memory, output, ephemeral
storage, processes, open files, and connections. Public Internet and metadata
access are unconditionally false. Network mode is none, exact target, or target
plus required control endpoints; protocols and DNS behavior are explicit.

Native-restricted operations are capped at T2. OCI and ordinary remote
isolation are capped at T3. T4 requires dedicated isolation, cooperative
cancellation, `never` retry, and target/control network behavior. Later E06 and
E19 issues must enforce these signed declarations at the execution boundary.

## Tier-ceiling proof

`ResolveOperation` enforces:

```text
signed baseline <= required tier <= min(tool ceiling, operation ceiling, runtime ceiling)
```

An operation cannot be requested below its reviewed baseline. Runtime policy
may narrow the ceiling but cannot present a value above either signed ceiling.
Policy narrowing below the deterministic required tier denies execution. A
higher signed ceiling, new operation, or changed artifact requires a new tool
version, review, and signature.

## Revocation, replay, and recovery

The registry stores owned canonical bytes and returns owned copies. An exact
concurrent admission has one fresh winner and exact replays; no alternate bytes
can win or replace it. A higher current publisher approval revision raises the
minimum accepted revision atomically, so later rollback is denied.

Resolution cryptographically re-verifies the stored envelope using the fresh
authority. Publisher revocation, unapproval, key rotation, stale approval,
manifest expiry, artifact mismatch, and unknown operation return no capability.
Cancellation or timeout before admission leaves no entry. Invalid admission,
collision, or expired resolution leaves the last valid snapshot intact and
fresh valid authority/time recovers normally.

## Focused verification

The clean checkpoint passed the dedicated verifier with summary:

```text
tool-registry summary: schemas=2 fixtures=2 denials=12 canonical=COH-CJ-1 signature=ed25519 publishers=current-approved review=required tiers=baseline-and-ceiling policy=narrow-only snapshots=immutable replay=exact revocation=live failures=0
```

The verifier log is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/tool-registry/run.fMw2lp/tool-registry.log`
with SHA-256
`e16f54a5bbd9e66da666ae7f0a9bb3b4750121efdfeb4f954442862931cc83dd`.
It includes schema/fixture assertions, focused tests, race, vet, 43-package
architecture verification with zero violations, and file-size enforcement.

## Clean baseline

The exact clean checkpoint `2f49ddaceedcfb179892b1619d5f18b83472800f`
passed all 18 required baseline stages with `quality_gate_promotable=true` and
`vcs_modified=false`. The evidence directory is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.LT2b6l`.

The embedded report digest is
`3355dcb2d73b3e44d4b8e11883f2a56000bbf6231405cfb8d1d174568d47b06a`;
the report-file SHA-256 is
`96322690e9a2b92d14a07ebbbf33c6849e55e2027ca83058b3b99982e7c4bf71`.
Provenance records 605 source files, source digest
`8de9f9cd9ae740f9c276ccd2fdc251e18c35d342a739b0c139077403ff28a2b2`,
Go 1.26.7 on darwin/arm64, 43 architecture packages with zero violations, and
183 approved modules with zero vulnerabilities.

## Reproduction

```sh
./scripts/verify_tool_registry.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- COH-E06-02 through COH-E06-04 implement native, OCI, and remote execution and
  must enforce these signed capabilities independently at runtime.
- COH-E06-05 implements independent containment and E-stop revocation.
- Vendor-specific adapters and silent compatibility are intentionally outside
  this contract.
- Independent security architecture review remains required before the first
  production release.
