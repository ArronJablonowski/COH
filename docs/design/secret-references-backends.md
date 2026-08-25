# Secret references and credential backends

## Purpose

CYB-43 implements COH-E04-03 and SEC-010/SEC-011. Configuration and durable
workflow inputs may contain only an opaque `coh.secret-reference/v1` object.
Only the broker boundary can exchange that reference for bytes, and only after
authenticated authority, backend metadata, current version, exact scope,
replay state, and required audit all pass.

This control resolves a credential for later broker use. It does not issue a
lease or authorize connector/runner dispatch; CYB-45 owns task-scoped leases,
rotation/revocation checks before every dispatch, and final value injection.

## Reference and request contracts

A reference contains exactly:

- `schema_version` and `contract_version`;
- an approved backend name;
- an opaque bounded entry ID; and
- a positive expected value version.

It has no field for a secret, password, token, credential value, environment
variable, command, URL, path, backend address, or authentication material.
Inline, environment, command, and URL backends are forbidden. Entry IDs cannot
contain path separators or URL syntax.

The broker-internal resolution request adds a UUIDv7 request and idempotency
key, organization, tenant, case, actor, canonical action digest, credential
class, and the reference. These fields bind provenance but do not manufacture
authority. `Resolver.Resolve` separately requires an authenticated
`AuthoritySnapshot` containing the exact same four-part context, active actor
state, positive actor revision, and the digest of the prior authorization
decision. Mismatch, invalid authority, or revocation denies before backend
access.

## Broker-only resolution

The resolver is under `internal/broker/secretresolver`. A source-surface test
scans production Go imports and denies any importer outside `internal/broker`.
Architecture rules independently prevent workflow, provider, connector,
transport, UI, policy, domain, persistence, and helper code from importing the
broker package.

Resolution proceeds in this order:

1. Validate the complete request and authenticated authority snapshot.
2. Require exact authority/request organization, tenant, case, and actor.
3. Select an explicitly registered backend; no fallback or implicit backend.
4. Fetch current trusted backend metadata and a bounded value.
5. Validate backend/entry identity, metadata structure, active state, expected
   value version, organization, tenant, case grant, and credential class.
6. Atomically bind `(organization, actor, idempotency key)` to the complete
   request digest. Exact retry is marked; changed reuse is a conflict.
7. Durably append the redacted decision.
8. Only then return an owned `Secret` to broker code.

Every failure path overwrites fetched bytes before returning. On success the
resolver copies into the owned `Secret` and overwrites the backend-return
buffer. `Secret.Use` supplies a temporary copy that is overwritten immediately
after the callback, and `Destroy` idempotently overwrites the owned bytes.
Callers can intentionally copy bytes while using them—required for controlled
dispatch—but accidental retention of the callback slice yields zeroed bytes.

## Protected-file native backend

The native `protected-file` backend receives its trusted root and entry metadata
only at process composition. The public reference never contains a path. Each
opaque entry ID deterministically maps to `<entry-id>.secret` inside an
`os.Root` descriptor, which remains attached to the original directory across
renames and prevents escape from that root.

The root must be a real owner-readable/searchable directory with no group or
other permissions. Each entry must exist during backend construction as a real,
bounded, nonempty regular file with owner read permission, no owner execute
permission, and no group/other permissions. Symlinks, missing files, devices,
oversize values, unstable identity/mode/size/modification time, and short or
changed reads fail closed.

Construction seals an internal SHA-256 fingerprint of each file and immediately
overwrites the read buffer. The fingerprint never enters configuration, audit,
errors, diagnostics, or evidence. A later byte change under the same reference
version is denied. Legitimate rotation therefore constructs trusted metadata
with the next value version; old references become stale.

## Sealed-memory test backend

`sealed-memory` exists only for deterministic tests and local development. It
is not an approved production store. Construction takes ownership of input
buffers and overwrites them. Fetch returns copies. Replacement requires the
exact next metadata revision; unchanged versions require constant-time equal
bytes, while changed bytes require `version+1`. Replaced values and close-time
state are overwritten. Active-state revocation is visible immediately.

Server and vendor credential stores implement the same narrow `Backend` port
without changing configuration or workflow contracts.

## Audit and redaction

A resolution decision contains safe outcome/reason codes, validated authority
context, request/action/reference digests, credential class, backend name,
expected value version, actor and backend-record revisions, and replay state.
It intentionally excludes the entry ID, secret bytes, any secret-derived value
fingerprint, backend path/address, and backend error.

Malformed requests do not copy any request-controlled field into audit. Valid
requests bind the authority decision digest and full scope. Audit failure
overwrites any fetched value and returns `unavailable`; a secret cannot cross
the boundary without a committed decision.

## Failure and recovery

| Condition | Result |
|---|---|
| Secret-bearing/unknown field, forbidden backend, path/URL entry, absent context | `invalid_input` or `denied`; no backend value |
| Invalid/mismatched authority or inactive actor | `invalid_input` or `denied` before backend read |
| Unapproved backend or unknown entry | `denied`; no fallback |
| Crossed organization/tenant/case/class, stale version, revoked record | `denied`; fetched buffer overwritten |
| Changed idempotent replay | `conflict`; fetched buffer overwritten |
| Backend, replay store, or audit failure | `unavailable`; private detail discarded |
| Canceled or expired context | `canceled` or `timeout`; fresh context may recover |
| Exact retry | Allowed with `replayed=true`; same scope and current state rechecked |

## Verification and residual scope

The frozen contract includes two references, two fully scoped broker requests,
and 18 adversarial mutations. Tests cover reference redaction, authority
substitution, scope denial, stale/revoked state, exact/changed replay,
protected-file permissions/symlinks/size/material tamper, sealed-memory rotation,
zeroization, audit/backend/replay failure, cancellation, timeout, recovery, and
concurrent replay atomicity under the race detector.

Run:

```sh
./scripts/verify_secret_backends.sh
```

CYB-45 consumes this resolver to issue target/action/actor/time-scoped leases
and enforce live rotation/revocation before dispatch. Tamper-evident audit
storage and signed checkpoints belong to CYB-49; this resolver supplies and
fail-closes on its durable audit port. Platform keychain/Vault selection,
packaging, and operator provisioning guidance remain later deployment leaves.
Independent security architecture review remains required before the first
production release.
