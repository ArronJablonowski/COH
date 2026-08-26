# CYB-55 optional OCI executor verification report

| Field | Value |
|---|---|
| Issue | COH-E06-03 / CYB-55 |
| Requirements | SEC-031, SEC-032 |
| Verification date | 2026-08-26 |
| Implementation checkpoint | `c138c7be7279eaa2fac25d797899203942cab13a` |
| Isolation class | `oci_sandbox`, T0 through T3 |
| Aggregate result | Pass |

## Outcome

The optional OCI executor admits only requests bound to fresh scoped
authorization, a current signed-registry capability, trusted digest-pinned
image registration, and a current broker-enforced network lease. Callers cannot
supply an image, tag, command, entrypoint, argument vector, environment, user,
group, mount, network name, runtime ceiling, authorization, or capability.

Every health and execution container uses a numeric non-root UID/GID, read-only
root, all capabilities dropped, no-new-privileges, no host namespace, device,
host path, named volume, port publication, or socket mount, bounded resources,
tmpfs-only writable paths, disabled daemon logging, fixed entrypoint and
arguments, typed canonical JSON on standard input, and a broker-attested
network profile. Floating images are unrepresentable and runtime pulling is
disabled.

The Docker-compatible CLI is optional, digest-bound, copied into a private
mode-0500 runtime path, and invoked over a configured local Unix socket with a
clean host environment and no shell. Runtime, socket, image, health, network,
limit, cancellation, removal, or lease-cleanup failure is fail closed. Native
COH remains Docker-independent.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Pinned images, non-root users, read-only roots, dropped capabilities, bounded mounts, no Docker socket, and explicit egress policy | Registration and plan validation; `dockerCreateArguments`; runtime process integration fixture; `TestDockerCreateArgumentsAreLeastPrivilegeAndDeterministic`; `TestExecutorUsesBrokerAttestedExplicitEgressProfile`; production source-surface test | Pass |
| Narrow Go interface, typed errors, context cancellation, idempotent boundaries, and no policy/executor bypass | Public request/authority/runtime contracts; mandatory `Authorizer`, signed `Resolver`, `NetworkBroker`, and `Runtime`; exact-attempt owner/replay state machine; `TestPublicContractsExcludeCallerControlledContainerExecution`; architecture verifier | Pass |
| Invalid input, denial, timeout/cancellation, and recovery retain provenance without bypass | Typed input and capability denials; image/health/runtime contract failures; live fixture cancellation and cleanup; timeout/new-attempt recovery; exact/collision/concurrent replay; complete provenance tests | Pass |
| Automated success and failure tests pass applicable CI, race, architecture, secret, license, dependency, and size gates | Dedicated verifier plus all 18 clean baseline stages at checkpoint `c138c7be7279eaa2fac25d797899203942cab13a` | Pass |
| Unit/integration, race, trace, and architecture evidence is attached and cross-references COH-E06-03, SEC-031, and SEC-032 | This report, retained verifier log, architecture/provenance digests, clean baseline report, and artifact checksum manifest | Pass |

## Authorization and signed capability

Each new attempt first computes the bounded raw-input digest and obtains fresh
broker authorization for the exact attempt, organization, tenant, case, actor,
tool, operation, required tier, and input digest. Authority includes the policy
decision digest, T0-through-T3 runtime ceiling, and an exclusive validity window
of at most five minutes. Missing, expired, elevated, changed, or opaque
authority fails before registry, network, or runtime access.

The executor then calls `ResolveOperation` with a cloned current publisher
authority. The returned capability must match the complete request and
authority, use `oci_sandbox`, remain within T0 through T3, carry valid finite
resource and network policy, and require only credential class `none`.
Credential-bearing operations fail closed until a separate non-environment
credential injection boundary exists. Publisher revocation is re-evaluated by
the real signed registry on every new attempt.

## Image and process-runtime boundary

Trusted registration binds the exact tool/version/artifact/operation tuple to:

- one fully qualified lowercase repository and the signed SHA-256 image
  manifest digest;
- one absolute non-shell entrypoint;
- literal fixed execution and health arguments;
- safe fixed `LANG`, `LC_ALL`, or `TZ` values only;
- one numeric non-zero UID and GID; and
- non-overlapping bounded tmpfs destinations below `/work` or `/tmp`, including
  `/work`.

The only generated image reference is `repository@sha256:...`. The runtime uses
`--pull never`, inspects the local image, and requires its reported digest set
to contain that exact reference before creating a container.

The configured Docker-compatible CLI must be an absolute executable regular
file with the configured digest. It is copied from a verified open file to a
digest-named mode-0500 path inside a private directory and re-hashed before
every engine operation. The engine endpoint must be an absolute local Unix
socket. CLI commands use the exact private binary, literal arguments, a fixed
working directory, bounded control output, and a clean host environment. The
engine socket is never supplied to the tool container.

## Least-privilege container specification

The deterministic create arguments enforce:

- non-root numeric user and group;
- read-only root filesystem;
- `cap-drop ALL` and `no-new-privileges`;
- no privileged flag, host PID/IPC/network namespace, device, host mount, named
  volume, or published port;
- process, memory, memory-plus-swap, CPU-quota, and open-file limits;
- daemon log driver `none` and bounded attached stdout/stderr;
- working directory `/work`;
- tmpfs-only writable mounts with `noexec`, `nosuid`, `nodev`, and exact size;
- exact registered entrypoint, image digest, and literal arguments; and
- only the broker-returned network name, with no default-bridge fallback.

Aggregate tmpfs capacity cannot exceed the signed ephemeral-storage ceiling.
CPU quota is derived downward from signed CPU and wall ceilings and capped by
the process count; an unenforceably small ratio is denied instead of rounded
up. Typed inputs are canonical JSON on standard input and are not interpolated
into image, command, arguments, mounts, or environment.

## Network, health, cancellation, and cleanup

Signed network mode `none` is handled only by `NoNetworkBroker` and maps to
engine network `none`. Connected modes require a separately configured network
enforcer. Its lease binds the complete actor/scope/authorization, exact signed
network policy and digest, protocols, DNS behavior, and maximum connections to
an opaque pre-provisioned network and enforcement digest. The lease cannot
predate or outlive dispatch authority. Mutation, default bridge, stale lease,
or missing cleanup is denied.

Before execution, a separate container runs the fixed health arguments under
the same image, identity, filesystem, mounts, resources, entrypoint, and
network. Health is bounded to five seconds inside the operation wall-time
budget. Only exit zero permits execution.

Cancellation, deadline, and output overflow request engine KILL, bound the CLI
wait, force-remove the container, and retain only bounded output. Container
removal and network release run on independent bounded cleanup contexts so a
canceled caller cannot skip them. Any cleanup failure prevents success.

## Replay and provenance trace

One exact attempt has one owner. Concurrent and later byte-exact replay returns
the immutable stored result without re-authorizing, re-resolving, reacquiring
network, or re-running the container. Reusing the attempt identity with changed
request bytes conflicts. Failure recovery uses a new attempt identity.

Every terminal result records scope and actor identity, authorization and
policy-decision digests, manifest/tool/operation/tier bindings, registered and
resolved image digest, entrypoint/argument/environment/input/mount digests,
network-policy and enforcement digests, full container-plan digest,
health-command and runtime-binary digests, health result, times, outcome and
reason, exit/signal, bounded stream evidence, cleanup, and replay state. Raw
inputs, environment values, arguments, credentials, and engine diagnostics are
not copied into provenance.

The verified architecture graph digest is
`5ae80af5456b2ceafdb0d0e0726377706ae4ca19ccf99e057001dc6a15466a69`.

## Integration strategy

The process-runtime integration test builds a purpose-specific
Docker-compatible executable and exercises the production `DockerRuntime`
through real OS process boundaries. It verifies digest staging, exact image
inspection, health-before-run, clean environment, typed stdin, bounded output,
cancellation/KILL, exit inspection, forced removal, and runtime-binary drift
denial. Contract tests inspect the exact create arguments and reject every
generic or host-expanding flag.

Docker is absent on this native verification host. The executor therefore does
not download an image or create an undeclared external dependency. Actual
engine/version and OCI-image qualification remains a deployment gate for
COH-E22-05 / CYB-151; the optional runtime fails closed until those exact local
artifacts are configured. This absence does not alter native APIs or policy
semantics.

## Focused verification

The exact clean checkpoint passed `scripts/verify_oci_executor.sh` with:

```text
oci-executor summary: tiers=T0-T3 isolation=oci_sandbox authorization=fresh registry=signed image=digest-only pull=never user=non-root rootfs=read-only capabilities=dropped mounts=tmpfs-bounded socket=not-mounted network=broker-attested health=fixed resources=bounded cancellation=kill+remove provenance=complete replay=exact fixture=integrated runtime=absent failures=0
```

The retained log is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/oci-executor.4NvvTe/oci-executor.log`
with SHA-256
`a77afe95814f060f80a37df92df5c9f62cb89f6c8a82a80170b87640b6a88a15`.
It includes unit, three repeated integration runs, race, vet, Linux amd64 and
Windows amd64 test compilation, 48-package architecture verification with zero
violations, file-size enforcement, and diff checks. Provenance identifies exact
revision `c138c7be7279eaa2fac25d797899203942cab13a`, `modified:false`, Go 1.26.7,
and darwin/arm64.

## Clean baseline

The exact clean checkpoint `c138c7be7279eaa2fac25d797899203942cab13a`
passed all 18 required baseline stages with `quality_gate_promotable=true` and
`vcs_modified=false`. The evidence directory is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.VVDuvF`.

The embedded report digest is
`d3e1fe755795ece294c460ca4e7b4d75aca1287cbd859bdde89b83ea775a575c`;
the report-file SHA-256 is
`7183e093cc693e82d2f716f63f1ff8ab4051fc440748c58e481a18cff75deb89`.
Provenance records 647 source files, source digest
`581faeb40ee231077e8da0168bc646928b8837d68b59c621cd0e6b3c2115d514`,
Go 1.26.7 on darwin/arm64, 48 architecture packages with zero violations, and
183 approved modules with zero vulnerabilities.

## Reproduction

```sh
./scripts/verify_oci_executor.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- COH-E06-04 / CYB-58 implements remote-worker enrollment, attestation, and
  short-lived runner leases.
- COH-E06-05 / CYB-57 implements independent containment and E-stop controls
  after native, OCI, and remote boundaries are complete.
- COH-E22-05 / CYB-151 qualifies signed multi-architecture OCI images and exact
  supported container-engine profiles.
- Independent security architecture review remains required before the first
  production release under CYB-173.
