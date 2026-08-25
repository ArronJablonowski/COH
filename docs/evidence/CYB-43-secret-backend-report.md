# CYB-43 secret references and backends report

| Field | Value |
|---|---|
| Issue | COH-E04-03 / CYB-43 |
| Requirements | SEC-010, SEC-011 |
| Verification date | 2026-08-25 |
| Contract | `coh.secret-reference/v1` / `1.0.0` |
| Implementation checkpoints | `60587e5`, `f306a71`, `711e5ec`, `dd62892`, `4f34ac1` |
| Qualified implementation checkpoint | `4f34ac191cc358fa95ff6edcc8d20c9e72f6bb5d` |
| Review status | Local technical evidence complete |

## Outcome

COH now has a strict opaque secret-reference contract and a broker-only resolver
that releases bytes only after authenticated authority, backend metadata,
current version, exact organization/tenant/case/credential-class scope, replay
state, and required audit pass. Configuration and resolution requests have no
field capable of carrying a secret value, path, URL, environment variable, or
command.

The native protected-file backend uses descriptor-rooted entry mapping, locked
permissions, bounded stable reads, symlink denial, and construction-time
material fingerprints. A deterministic sealed-memory backend exercises atomic
rotation/revocation and zeroization but is explicitly non-production. The
clean 18-stage baseline is promotable. No unresolved blocking finding remains.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Opaque configuration references; scoped values only to credential broker; derived errors redacted | Versioned strict schemas, forbidden backend semantics, `internal/broker/secretresolver`, import-surface enforcement, exact authority/backend scope, safe typed errors | Pass |
| Default deny, actor/scope binding, redaction, fail-closed audit, replay/tamper/stale/revocation | Authenticated `AuthoritySnapshot`, current record/version checks, atomic replay store, protected-file fingerprint, active record checks, audit-before-release, buffer overwrite tests | Pass |
| Invalid input, denial, timeout/cancellation, recovery | Frozen denial corpus and runtime tests cover malformed/forbidden input, scope/authority denial, expired contexts, backend/audit/replay failure, and fresh-context recovery | Pass |
| Applicable automated and quality gates | Focused unit/race/vet/architecture verifier plus clean promotable 18-stage baseline | Pass |
| Required evidence | Frozen adversarial corpus, policy/scope decisions, authority/audit proof, stale/revocation denial, tamper and zeroization traces, focused log, baseline report, design, checksum ledger | Pass |

## Opaque-reference and scope proof

The reference contains only contract identity, approved backend, opaque entry
ID, and positive expected version. Strict decoding rejects unknown fields and
trailing JSON. Semantic validation forbids inline, environment, command, and
URL backends and rejects path/URL syntax in entry IDs.

The broker request binds UUIDv7 request, organization, tenant, case, actor,
idempotency key, canonical action digest, credential class, and the reference.
Before backend access the resolver separately validates an authenticated
authority snapshot and requires exact four-part context, active state, positive
actor revision, and prior authorization-decision digest. Tests prove every
organization/tenant/case/actor substitution denies with zero backend fetches.

Trusted backend metadata independently binds organization, tenant, exact/all
case grant, credential class, current value version, metadata revision, and
active state. Request fields never establish that authority. Stale version,
revoked record, crossed scope/class, unknown entry/backend, and malformed record
all deny.

## Broker-only and redaction proof

Only code under `internal/broker` may import the resolver; the source-surface
test scans all production Go imports. The architecture gate independently
prevents model/workflow/provider/connector/transport and other boundaries from
importing broker code.

Decisions contain only validated authority context, request/action/reference
digests, credential class, backend name, expected version, actor/backend
revisions, replay state, and safe outcome/reason. They exclude entry ID, bytes,
value fingerprint, file root/path, backend address, and private backend error.
Malformed requests contribute no request-controlled decision fields. Missing
or failing audit overwrites fetched bytes and returns `unavailable`.

## Backend, tamper, replay, and revocation trace

- Protected roots are real owner-readable/searchable directories with no
  group/other permissions; secret files are real bounded owner-readable,
  non-executable files with no group/other permissions.
- `os.Root` descriptor operations and before/opened/after identity, mode, size,
  and modification-time checks deny symlink, escape, replacement, short read,
  and unstable file behavior.
- An internal construction-time SHA-256 material fingerprint denies any byte
  change under an old reference version and is never exported.
- Sealed-memory input, replaced state, backend-return buffers, resolver failure
  buffers, callback temporaries, and destroyed secrets are overwritten.
- Exact replay is marked `replayed=true`; changed reuse of the same
  organization/actor/idempotency tuple returns `idempotency_conflict`.
- Value rotation requires `version+1` and exact next metadata revision. Active
  revocation is immediately visible; stale references and revoked records deny.

## Baseline evidence

Clean checkpoint `4f34ac191cc358fa95ff6edcc8d20c9e72f6bb5d`
passed all 18 required stages with `quality_gate_promotable=true`. The report
digest is
`7b0465cbd765fdd5825e27b4fbdb26c203d0fc987618f1cd8c61b0f1c0de75aa`;
the report-file SHA-256 is
`a36e40092a246bffacc37dc2c6ac11a018196c76d9cf4f16caeb1dfc2f3bd481`.
Provenance records 402 source files, Go 1.26.7 on darwin/arm64, and clean VCS
state. The focused verification-log SHA-256 is
`1edbcb299a5a9c852e28bfe9fb2274921d4e91c31911e68788caee1d9d99ee12`.

## Reproduction

```sh
./scripts/verify_secret_backends.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- CYB-45 consumes this boundary to issue target/action/actor/time-scoped leases
  and enforce current rotation/revocation before dispatch.
- Sealed memory is not a production store. Server/vendor backend selection and
  operator provisioning guidance remain later deployment work.
- Tamper-evident durable audit and signed checkpoints belong to CYB-49; this
  resolver supplies and fail-closes on the audit port.
- Independent security architecture review remains required before the first
  production release.
