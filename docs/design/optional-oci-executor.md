# Optional OCI executor

| Field | Value |
|---|---|
| Issue | COH-E06-03 / CYB-55 |
| Requirements | SEC-031, SEC-032 |
| Isolation class | `oci_sandbox` |
| Maximum tier | T3 |
| Runtime | Optional digest-bound Docker-compatible CLI over a local Unix socket |

## Purpose

The OCI executor is the stronger optional execution boundary for reviewed T0
through T3 tools. It does not make Docker a dependency of native COH, expose a
generic container API, or treat a shared container engine as a T4 boundary. If
the configured runtime binary, local engine socket, image, network enforcer, or
required containment feature is unavailable, execution fails closed.

Every new attempt must pass four independent bindings before a container can be
created:

1. fresh broker-owned authorization for the exact actor, scope, tool,
   operation, tier, and input digest;
2. current resolution of the exact operation from the signed tool registry;
3. trusted deployment registration of the exact image digest, entrypoint,
   arguments, non-root identity, environment, health command, and writable
   tmpfs mounts; and
4. a broker-issued egress lease for the exact signed network-policy digest.

Callers cannot provide an image, tag, command, entrypoint, arguments,
environment, user, group, mount, network name, runtime ceiling, authorization,
or prebuilt capability.

## Image and runtime identity

The tool artifact digest is the OCI image manifest digest. Registration binds a
fully qualified lowercase repository and that exact digest; the runtime
receives only `repository@sha256:...`. Floating tags and implicit registry
names are invalid. Image pulling is disabled during execution. Before creating
a container, the runtime inspects the locally available image and requires its
reported repository-digest set to contain the exact registered reference.

The Docker-compatible CLI path, SHA-256 digest, private state directory, and
local Unix engine socket are trusted configuration. The verified CLI is copied
to a mode-0500 digest-named file inside the private state directory and that
private copy is re-verified before every engine operation. The runtime rejects
relative paths, symlinks, changed binary identity or digest, non-private state,
non-socket endpoints, and TCP engine endpoints. It re-verifies the binary and
socket before runtime operations. Runtime commands use an absolute binary,
literal argument vectors, a clean fixed host environment, bounded control
output, and no shell.

The engine socket is a host-side control channel used by the broker process. It
is never mounted into a tool container.

## Container specification

Every health and execution container is created with the following fixed
controls:

- a numeric non-zero UID and GID;
- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- no privileged mode, host PID/IPC/network namespace, device, host path, named
  volume, or socket mount;
- exact process, memory, memory-plus-swap, CPU-quota, and open-file limits;
- daemon logging disabled in favor of bounded attached output;
- fixed working directory `/work`;
- only reviewed `LANG`, `LC_ALL`, and `TZ` values in the container environment;
- tmpfs-only writable paths below `/work` or `/tmp`, each with an explicit size,
  `noexec`, `nosuid`, and `nodev`; and
- an exact registered entrypoint and literal argument vector.

At least `/work` must be mounted. Mounts cannot overlap, and their aggregate
size cannot exceed the signed ephemeral-storage ceiling. Root and image layers
therefore remain immutable and tool-controlled persistent host paths are
unrepresentable. Typed canonical JSON is passed on standard input and is never
interpolated into a command or environment variable. Shell entrypoints are
rejected. The v1 executor admits only the signed credential class `none`;
operations requiring a credential class fail closed until a separately scoped
file-descriptor or file-mount credential broker is implemented. Secrets are
never transported in environment variables.

The CPU quota is derived from the signed CPU-millisecond and wall-time ceilings
and capped by the signed process count. Combined with the parent wall timeout,
it bounds aggregate CPU opportunity. A requested ratio below the engine's
minimum enforceable quota is denied rather than rounded up. The engine enforces memory, swap, process,
and file-descriptor ceilings. Output is accepted through a shared bounded
stdout/stderr capture; reaching the bound kills the container and records a
truncated prefix.

## Explicit egress policy

The runtime never falls back to the default bridge. Signed mode `none` maps
only to engine network `none` through `NoNetworkBroker`. Connected modes
require a separately configured broker-owned network enforcer. That enforcer
receives the exact attempt, actor, scope, authorization, signed network policy,
policy digest, protocol set, DNS mode, and connection ceiling. It returns a
short-lived opaque engine network plus an enforcement digest and cleanup
boundary.

The executor verifies that the lease matches the complete request, is current,
does not outlive dispatch authority, and carries a valid enforcement digest.
The Docker runtime can attach only to the returned opaque network. It does not
construct a permissive bridge or infer destinations. Exact targets and control
endpoints remain the responsibility of the separately authorized action and
network broker. Public Internet and metadata access are forbidden by the
signed-registry contract.

## Health, cancellation, and cleanup

Before tool execution, the runtime creates a separate container with the same
image, identity, filesystem, mounts, resources, network, and entrypoint and
runs the fixed registered health arguments. Health has a five-second maximum
within the operation's overall signed wall-time budget. Only exit zero is
healthy. Health timeout, denial, or non-zero exit prevents the tool container.

The execution container is created separately and started attached with typed
input. Parent cancellation, deadline, or output overflow requests an engine
`KILL`, bounds the client wait, and force-removes the container. Cleanup uses an
independent bounded context so a canceled caller cannot skip removal. The
network lease is released after runtime completion. Runtime or network cleanup
failure cannot be reported as successful execution.

Deterministic attempt identity provides one owner. Exact concurrent or later
replay receives the immutable stored result without calling authorization,
registry, network, or runtime again. Reusing an attempt identifier with changed
request bytes conflicts. Recovery after failure requires a new attempt.

## Provenance

Every result records redacted bindings for:

- attempt, organization, tenant, case, actor, authorization, and policy
  decision;
- signed manifest, tool, operation, requested tier, and effective ceiling;
- registered and engine-resolved image digest;
- entrypoint, argument, environment, typed-input, and mount digests;
- signed network-policy and broker-enforcement digests;
- complete container-plan, health-command, and runtime-binary digests;
- health outcome, start/end time, terminal outcome and reason, exit/signal,
  bounded stream evidence, cleanup completion, and replay state.

Raw inputs, arguments, environment values, credentials, runtime diagnostics,
and engine configuration are not copied into provenance.

## Assurance boundary

Unit and integration tests use a purpose-built Docker-compatible fixture to
exercise the real process runtime without requiring Docker or a network. They
prove image inspection, health-before-run, typed stdin, bounded output,
cancellation, forced cleanup, and binary-drift denial. Separate contract tests
assert the exact least-privilege create arguments and absence of generic shell,
network-client, host-mount, device, privileged, and socket-mount surfaces.

An actual supported Docker-compatible engine remains optional. Deployment
qualification must bind its exact binary and engine version and repeat the live
containment suite. This executor is not a T4 dedicated-isolation claim. Remote
worker leases and independent E-stop revocation remain COH-E06-04 and
COH-E06-05. Independent security architecture review remains required before
the first production release.
