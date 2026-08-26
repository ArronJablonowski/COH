# Low-risk native executor

| Field | Value |
|---|---|
| Issue | COH-E06-02 / CYB-54 |
| Requirements | SEC-017, NFR-002 |
| Execution tiers | T0 and T1 only |
| Isolation class | `native_restricted` |
| Network | None |
| Docker dependency | None |

## Purpose and boundary

The native executor runs a finite set of reviewed low-risk binaries without a
shell, generic HTTP client, Docker executable, daemon, socket, or VM. It is a
broker-owned boundary. A workflow, provider, transport, model, or arbitrary
caller cannot supply an executable, arguments, environment, policy ceiling, or
preconstructed registry capability.

Every new attempt follows this fail-closed sequence:

1. validate exact organization, tenant, case, actor, attempt, tool, operation,
   tier, publisher, and typed-input fields;
2. locate immutable deployment registration for the exact
   tool/version/digest/operation;
3. ask the broker authorizer for fresh authority bound to scope, actor, attempt,
   requested tier, tool, operation, and input-request digest;
4. validate the authority's decision digest, maximum five-minute validity, and
   T0/T1 runtime ceiling;
5. resolve the operation from the signed registry using that ceiling and fresh
   publisher authority;
6. independently require `native_restricted`, T0/T1 effective authority, finite
   controls, and a no-network profile;
7. validate typed inputs and encode their canonical JSON object on stdin;
8. copy the executable from an already-open regular executable file into a
   private directory, verify its SHA-256 digest, and reverify it at the sandbox;
9. execute through the digest-pinned limit helper with fixed argv, a finite
   clean environment, a disposable working directory, and every reviewed
   limit; and
10. return bounded output plus terminal provenance.

No registry, authorization, artifact, or sandbox denial has a fallback. A new
attempt is required after denial, timeout, or cancellation.

## Request and authority contract

`Request` contains four UUID-scoped identities, an attempt UUID, an exact tool
reference, operation, required T0/T1 tier, fresh publisher authority, and typed
input values. It deliberately has no executable path, argv, environment,
runtime ceiling, raw command, URL, shell text, credential, or generic payload.

The authorizer receives an `AuthorizationRequest` containing only safe bounded
identity and digest fields. `DispatchAuthority` must exactly repeat that
request, identify its policy decision by SHA-256 digest, supply a T0/T1 ceiling,
and be current in a canonical validity window of at most five minutes. Invalid,
expired, widened, stale, or mismatched authority is denied before registry
resolution, artifact access, or process creation.

The executor then invokes the signed registry itself. It rejects a resolver
result whose tool, operation, tier, isolation, resource, or network values do
not exactly match the request and dispatch authority. This prevents callers
from bypassing policy by constructing a `toolregistry.Capability`.

## Registration and input contract

Trusted deployment registration maps one exact tool/version/artifact digest and
operation to one absolute executable path, an immutable literal argv, and an
optional finite environment. Only `LANG`, `LC_ALL`, and `TZ` may be registered;
ambient process environment is discarded. Loader injection, path lookup,
credentials, tokens, passwords, and arbitrary configuration cannot enter the
environment.

Operation values use the signed registry's finite input vocabulary. Required,
type, numeric, byte, item, enum, UUID, digest, timestamp, sorted-list, and
uniqueness constraints are rechecked at execution. Inputs become a canonical
JSON object on stdin and never undergo argv interpolation. Consequently, a
hostile input value cannot select another binary, add a flag, invoke a shell,
or alter the environment.

## Artifact and process controls

The file preparer rejects relative paths, symlinks, non-regular files,
non-executable files, changed file identities, empty or oversized files,
digest mismatch, and storage overflow. It copies bytes from the verified open
file into a mode-0500 private directory. The sandbox verifies that staged file
again immediately before launch. Exact helper bytes are independently staged
and checked against their configured digest.

The helper reads one bounded plan on inherited descriptor 3, changes into the
disposable working directory, applies limits, and replaces itself with the
exact staged executable. It never starts a shell. CPU, output-file, open-file,
and core-dump bounds use OS rlimits. The parent enforces wall time, resident
memory, process count, a combined stdout/stderr limit, process-group
termination, and a monitored aggregate ephemeral-storage bound.

Darwin executes the helper under `/usr/bin/sandbox-exec` with all network
access denied and writes permitted only below the disposable working directory.
Linux launches the helper through fixed `/usr/bin/unshare --net` arguments to
create a private network namespace before limit setup. If
the platform primitive or privilege is unavailable, execution is denied. Other
platforms are unsupported by this native sandbox and fail closed. None of these
paths detect, invoke, or depend on Docker.

## Output, cancellation, and idempotency

Stdout and stderr share the signed output-byte budget. The boundary retains only
the permitted prefix, marks it truncated, kills the process group, and reports
`output_limit` when the budget is exceeded. Cancellation and wall timeout kill
the entire owned process group; the result records exit status or termination
signal, stream digests and lengths, and the terminal reason.

Attempt identity is immutable. The first exact request owns execution;
concurrent and later exact calls wait for or recover the same result with
`Replayed=true`. Changed bytes under the same attempt ID conflict and cannot
replace the result. A failed attempt remains attributable; recovery uses a new
attempt and repeats current authorization, registry, artifact, and sandbox
checks.

## Provenance

Every started attempt returns scope and actor IDs; authorization and policy
decision IDs; manifest, tool, artifact, argv, environment, and input digests;
requested and effective tiers; start and finish times; outcome and typed
reason; exit code or signal; and stdout/stderr digests, lengths, and truncation.
Raw environment values other than the finite public locale/timezone set,
publisher keys, authorization internals, and unbounded output are not emitted.

## Verification and residual scope

`scripts/verify_native_executor.sh` runs unit, live Darwin sandbox integration,
race, vet, Darwin/Linux/Windows compile, architecture, and file-size checks. The
live integration proves clean environment, denied loopback connection, denied
filesystem escape, bounded output, process-group cancellation, staged artifact
verification, fixed argv/stdin, authorization, registry resolution, and
provenance.

This executor is not a hostile-code containment claim. It admits only reviewed
T0/T1 binaries with no network. OCI, remote workers, leases, and E-stop remain
COH-E06-03 through COH-E06-05. Packaging must install the exact helper and bind
its digest. Independent security architecture review remains required before
the first production release.
