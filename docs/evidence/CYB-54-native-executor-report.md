# CYB-54 low-risk native executor verification report

| Field | Value |
|---|---|
| Issue | COH-E06-02 / CYB-54 |
| Requirements | SEC-017, NFR-002 |
| Verification date | 2026-08-26 |
| Feature commit | `59274f87ea04ca776bd02294a756f95277a31817` |
| Verified checkpoint | `cab49d75f4bc3c5009e0eece14399a3517f640e0` |
| Native execution class | `native_restricted`, T0/T1 only |
| Aggregate result | Pass |

## Outcome

The low-risk native executor accepts only typed requests bound to a fresh
authorization decision and a currently valid operation from the signed tool
registry. The executor independently resolves that operation, admits only the
`native_restricted` isolation class at T0 or T1, and maps the exact reviewed
tool/version/artifact/operation identity to a trusted immutable registration.
Callers cannot supply an executable, shell command, argument vector,
environment, URL, runtime ceiling, capability, or generic payload.

Before launch, the executor opens and verifies an absolute regular executable,
rejects symlinks and unstable file identity, copies it into a private staging
directory, and verifies its SHA-256 digest again at the sandbox boundary. It
uses literal registered arguments, canonical typed JSON on standard input, a
clean allowlisted environment, and a disposable working directory. No shell or
generic network client is present.

The parent and helper enforce bounded wall time, CPU, memory, output,
ephemeral storage, process count, open files, and connections. Native network
access is denied. Cancellation and limit failures terminate the process group,
output capture is bounded, and staging/work directories are cleaned before
finalization. Every outcome carries redacted provenance, and exact attempt
replay returns the immutable prior result without executing again.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Permit only T0/T1 registered binaries with fixed argv, clean environment, bounded resources, cancellation, and provenance | Signed-registry resolution and tier/isolation checks in `executor.go`; immutable registration validation; staged artifact verifier; helper and process sandbox; `TestExecutorDenialsNeverReachSandbox`; live `TestProcessSandboxExecutesWithoutDockerOrAmbientEnvironment`; provenance contract test | Pass |
| Narrow Go interface, typed errors, context cancellation, idempotent boundaries, and no policy/executor bypass | Public request/registration contracts; typed error codes and reasons; mandatory `Authorizer`; exact-attempt owner/replay state machine; `TestNarrowPublicContractsExcludeCallerControlledExecution`; `TestProductionSurfaceHasNoGenericExecutionOrNetworkPrimitive`; architecture verifier | Pass |
| Invalid input, denial, timeout/cancellation, and recovery retain provenance without bypass | Validation and fail-closed stage results; denial-before-sandbox assertions; distinct-attempt timeout recovery; cancellation-before-authority; artifact drift denial; cleanup finalization; exact and concurrent replay tests | Pass |
| Automated success and failure tests pass applicable CI, race, architecture, secret, license, dependency, and size gates | Dedicated verifier plus all 18 clean baseline stages at checkpoint `cab49d75f4bc3c5009e0eece14399a3517f640e0` | Pass |
| Unit/integration, race, trace, and architecture evidence is attached and cross-references COH-E06-02, SEC-017, and NFR-002 | This report, retained verifier log, provenance graph digests, clean baseline report, and artifact checksum manifest | Pass |

## Authority and signed-registry binding

Every new attempt calls the required `Authorizer` before registry resolution,
artifact preparation, or sandbox execution. The returned authority is finite,
scoped to the exact organization, tenant, case, actor, tool, operation, and
canonical input digest, and includes the policy-decision digest and T0/T1
runtime ceiling. Expired, malformed, mismatched, elevated, or denied authority
fails before any execution-side effect.

The executor then calls `ResolveOperation` on the signed registry using current
publisher authority. The resolved capability must match the request and
authorization exactly, have `native_restricted` isolation, an effective T0/T1
tier, and network mode `none`. Registry denial, publisher revocation, artifact
drift, tier expansion, or changed binding returns no executable capability.

## Process and artifact boundary

The registration table is constructed from trusted configuration and binds the
exact tool/version/artifact/operation tuple to:

- one absolute executable path;
- a literal fixed argument vector; and
- fixed environment variables restricted to `LANG`, `LC_ALL`, and `TZ`.

Inputs are validated against the signed typed schema, canonicalized, hashed,
and sent on standard input. They are never interpolated into arguments or the
environment. Ambient environment variables are discarded.

The artifact preparer rejects relative paths, symlinks, non-regular files,
missing execute bits, oversized files, digest mismatch, and file identity that
changes while copying. The executable is copied from the verified open file to
a mode-0500 private staging directory. The sandbox re-hashes that staged copy
before launch.

On Darwin, the helper runs under a fixed `/usr/bin/sandbox-exec` profile that
denies all network activity and writes outside the disposable work directory.
On Linux, launch requires the fixed `/usr/bin/unshare --net` path and fails
closed when the required isolation cannot be established. The helper reads a
bounded execution plan from inherited descriptor 3, changes to the disposable
directory, applies rlimits, and executes the exact staged binary without a
shell.

## Limits, cancellation, cleanup, and replay

The helper applies CPU, file-size, open-file, and core-dump rlimits. The parent
independently enforces the signed wall-time ceiling, combined output bound,
resident-memory ceiling, descendant-process ceiling, and aggregate ephemeral
storage ceiling. Network isolation makes the allowed connection count zero.
Monitor failure is itself a denial.

Cancellation, timeout, and resource denial kill the complete process group.
Captured output contains only a bounded prefix and records digest, observed
length, and truncation. Cleanup of the sandbox work directory and staged
artifact is part of finalization; cleanup failure cannot be reported as a
successful execution.

An attempt identifier has one owner. Concurrent or later replay of the exact
canonical request receives the immutable stored result with `replayed=true`;
the sandbox runs once. Reuse of the attempt identifier with different request
bytes conflicts. A failed attempt does not prevent recovery through a new
attempt identifier.

## Provenance and trace evidence

Every finalized result records the organization, tenant, case, actor,
authorization identifier, policy-decision digest, manifest digest,
tool/artifact/operation identity, argument/environment/input digests, effective
tier, start/end time, outcome and reason, exit or signal state, and bounded
stream digests, lengths, and truncation flags. Sensitive input and environment
values are not copied into provenance.

`TestProvenanceContainsAuthorityAndExecutionBindings` proves the public trace
shape. `TestExecutorResolvesStagesAndReplaysExactlyOnce`,
`TestExecutorConcurrentReplayRunsSandboxOnce`, and
`TestExecutorTimeoutAndRecoveryUseDistinctAttempts` prove deterministic stage,
replay, and recovery traces. The architecture graph digest at the verified
checkpoint is
`dd4562435df2f902e4fbd6ac205a531fa6dd1b3cda42fe6e31db69458f3379ea`.

## Automated test coverage

The focused package contains these top-level tests:

- artifact copy, digest, symlink, executable, identity, and storage bounds;
- public contract exclusion of caller-controlled execution fields;
- complete redacted provenance;
- exact and concurrent replay with one sandbox invocation;
- authorization, registry, isolation, tier, input, and artifact denials;
- timeout, cancellation, cleanup, new-attempt recovery, and drift denial;
- immutable executable/argument/environment registration;
- typed input vocabulary and bounds;
- source-surface exclusion of generic execution and network primitives; and
- live Darwin sandbox execution, environment isolation, network denial,
  filesystem denial, output bound, process-group cancellation, process/memory/
  storage bounds, signed-registry execution, publisher revocation, and artifact
  drift.

The dedicated verifier also runs repeated package tests, the race detector,
vet, static analysis, Linux amd64 compilation and helper build, Windows amd64
core compilation, architecture verification, file-size enforcement, worktree
secret scanning, and diff checks.

## Focused verification

The exact clean checkpoint passed `scripts/verify_native_executor.sh` with:

```text
native-executor summary: tiers=T0/T1 isolation=native_restricted authorization=fresh registry=signed argv=fixed stdin=typed environment=clean network=none artifact=staged+verified resources=bounded cancellation=process-group provenance=complete replay=exact docker=absent failures=0
```

The retained log is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/native-executor.td8uX3/native-executor.log`
with SHA-256
`0676ef40926682ff93bc03090c7e7fbd22e6a9b0da9f87a904a82efa3373c868`.
Its provenance identifies revision
`cab49d75f4bc3c5009e0eece14399a3517f640e0`, `modified:false`, Go 1.26.7,
darwin/arm64, 46 architecture packages, and zero violations.

## Clean baseline

The exact clean checkpoint `cab49d75f4bc3c5009e0eece14399a3517f640e0`
passed all 18 required baseline stages with `quality_gate_promotable=true` and
`vcs_modified=false`. The evidence directory is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.tAK2Mq`.

The embedded report digest is
`b8682862d01fd2de789336f1c28d43d2e3c31594a51cba91ca2db8543302e9f0`;
the report-file SHA-256 is
`3ea366c25b0610b203219c27c2145a2b8c33badf3e7647ddabbc147b7726cf90`.
Provenance records 627 source files, source digest
`28492bc81a71da6241ba8458ae74c51c4fc43a4cc976ec1cba42a72a941afd01`,
Go 1.26.7 on darwin/arm64, 46 architecture packages with zero violations, and
183 approved modules with zero vulnerabilities.

## Reproduction

```sh
./scripts/verify_native_executor.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- COH-E06-03 / CYB-55 implements the OCI executor for stronger containment.
- COH-E06-04 / CYB-58 implements remote-worker enrollment, attestation, and
  short-lived runner leases outside this native boundary.
- COH-E06-05 / CYB-57 implements independent containment and E-stop controls.
- Independent security architecture review remains required before the first
  production release under CYB-173.
