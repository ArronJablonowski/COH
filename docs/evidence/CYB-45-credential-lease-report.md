# CYB-45 credential lease, rotation, and revocation report

| Field | Value |
|---|---|
| Issue | COH-E04-04 / CYB-45 |
| Requirements | SEC-012, SEC-024, SEC-040 |
| Verification date | 2026-08-25 |
| Contract | `coh.credential-lease/v1` / `1.0.0` |
| Design-freeze anchor | Product-owner approval at `8c6012d` |
| Implementation checkpoints | `b8cd1ff`, `ef23bf2`, `d91cc04`, `2998ab2`, `72c5dfb` |
| Qualified implementation checkpoint | `72c5dfb15213367a35cba7de471cd6ea180f6709` |
| Review status | Local technical evidence complete |

## Outcome

The broker now issues 256-bit, broker-owned, single-use credential capabilities
bound to exact organization, tenant, case, actor, task, canonical action,
sorted targets, operation, connector/runner audience, authenticated transport
identity, credential version, and a maximum five-minute window. The capability
has no serializable field and only its digest enters the atomic store.

Every use atomically claims the lease before resolving a credential. It then
requires unchanged actor, authorization, policy, applicable approval, audience,
and mTLS state; active task and inactive E-stop; exact dispatch scope; current
credential version and active state; and successful secret and lease audit
appends before entering the callback. Expiration, replay, rotation, revocation,
tamper, cancellation, stale authority, or audit failure cannot reach credential
use. The clean 18-stage baseline is promotable. No unresolved blocking finding
remains for this leaf.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Target-, action-, actor-, and time-scoped broker lease; rotation/revocation checked before every use | Strict issuance contract; immutable record; atomic claim; exact scope and authority comparison; live secret resolver call | Pass |
| Default deny, actor/scope binding, redaction, fail-closed audit, replay/tamper/stale/revocation handling | Trusted snapshots, closed errors, private capability, decision redaction, audit-before-callback, atomic replay store, denial tests | Pass |
| Invalid input, denial, timeout/cancellation, and applicable recovery | 24-case contract corpus; runtime denial tables; cancellation and transient preclaim recovery; postclaim new-lease rule | Pass |
| Applicable automated and quality gates | Focused unit/race/vet/architecture/secret/file-size verifier and clean promotable 18-stage baseline | Pass |
| Adversarial trace, policy decision, approval/audit proof, denial/revocation evidence | Frozen corpus, decision digests, policy/approval binding tests, dual audit digests, rotation/revocation/concurrency tests, focused log and baseline report | Pass |

## Contract and capability proof

The issuance request has 13 required fields and denies unknown fields. It binds
UUIDv7 request/task identity, four-part actor context, canonical action digest,
sorted unique bounded target digests, finite operation, connector/runner and
transport-identity digest, credential class/reference/version, idempotency, and
one-to-300-second requested lifetime. The frozen valid fixture and 24 uniquely
named denial mutations cover missing/malformed scope, ambiguous targets,
audience substitution, excessive lifetime, secret/capability-bearing fields,
and invalid or forbidden references.

`IssuanceAuthority` arrives independently from authenticated broker
composition. Issuance requires positive and digest-bound authorization and
policy, applicable approval, active actor and audience revisions, a fresh
audience observation, exact request/authority scope, and mTLS for a remote
audience. The request cannot manufacture those facts.

Successful issuance generates independent random capability and lease-ID
material. The handle exports only the lease ID; capability bytes and the stored
digest are unexported. Surface tests deny logging, network, process, runtime,
and syscall imports in the lease package. Entropy/store/audit failure returns no
usable capability. Concurrent identical issuance has exactly one winner;
exact and changed idempotency reuse return closed conflicts.

## Atomic dispatch, replay, and denial trace

The store serializes claim, revocation, expiry, and consumed state under one
lock. A claim constant-time checks capability digest, then rejects revoked,
expired, or already consumed state and marks a successful claim consumed before
any scope or resolver work. Sixteen concurrent uses produce exactly one
credential callback and one secret-resolution decision. A copied capability
replay is denied before a second resolution. Capability tamper returns no
record metadata and never reaches the resolver.

After claim, tests independently mutate action, targets, audience, transport
identity, actor revision, policy digest, task state, E-stop, actor active state,
audience active state, and mTLS state. Every mutation consumes the ambiguous
lease and enters zero callbacks. Cancellation or a transient store outage
before claim preserves the handle for a fresh-context retry; a failure after
claim requires a newly authorized lease.

The initial clean baseline at `2998ab2` correctly denied the unit stage because
the repository's broker API guard reserves an exported method named `Dispatch`
for the sole action-authority surface. The credential gate was renamed to
`Use`, accurately reflecting its narrower purpose without weakening the guard.
The broker surface unit, focused verifier, and complete baseline then passed at
`72c5dfb`. The denied report and unit log are retained as corrective evidence.

## Rotation, revocation, and mTLS proof

Each use calls the broker-only resolver with the immutable reference and the
fresh actor authority. The resolver fetches current trusted backend metadata.
A rotated version returns `credential_stale_reference`; inactive credential
state returns `credential_secret_revoked`. Both occur after lease claim but
before callback. No restart or workflow/model cooperation is needed.

Administrative revocation accepts only six closed reasons and atomically marks
the lease before audit. A later use observes `lease_revoked`. If revocation
audit fails, the operation reports unavailable but the stored revocation remains
effective. Expiration is checked inside the same atomic claim.

Remote audiences require mTLS at issuance and use. The lease binds audience
kind, ID, revision, and transport-identity digest. Certificate identity change
or revision change invalidates the old lease; revoked mTLS/audience state denies.

## Policy, approval, audit, and redaction proof

Issuance and use decisions include authorization, policy, and applicable
approval decision digests. Use decisions additionally bind the secret resolver
decision digest. They record only validated context, IDs, action/target/reference
digests, bounded operation/audience/class, revisions, time bounds, outcome, and
safe reason. They exclude capability bytes/digest, credential entry ID/value,
backend details, private callback errors, and secret-derived data.

The secret resolver appends its decision before returning an owned credential.
The lease broker then appends its dispatch authorization before invoking the
callback. Either audit failure destroys the credential and enters zero
callbacks. Mandatory lease audit uses a cancellation-independent bounded
context so client cancellation still records the decision. Invalid input clears
free-form fields; callback errors become `dispatch_failed`.

## Baseline evidence

Clean checkpoint `72c5dfb15213367a35cba7de471cd6ea180f6709`
passed all 18 required stages with `quality_gate_promotable=true`. The report
digest is
`104dd5a6a2d6e45902db0f4895b82f8394442ee2051c594a5bde69f8de7dbd12`;
the report-file SHA-256 is
`925a9126271e4ae69626854460bd02e9241e63b9164ef900a51ee7c828e1e594`.
Provenance records 427 source files, source digest
`6e4551381cb79c7bdee8a926ab754fd61d012de022d593b5f93ac397a3a95256`,
Go 1.26.7 on darwin/arm64, clean VCS state, and passed internal report
verification. The focused verification-log SHA-256 is
`3826a516861d0bd8947d8ee98a102f8ee974fc6a3f3e9df63641c5f42a62e9f2`.

For corrective traceability, denied clean checkpoint `2998ab2` produced report
digest `48b34d9fa99fba89573d8c3280b070398ce2d0bb4403170ee1e232220d4eeaa1`;
its report-file SHA-256 is
`47b6fe644c8e0fe38f07a83feb0a8e01133b910445cade4a4f83a1dcdadd2afe`,
and its unit-log SHA-256 is
`b4e60fbbc601a27813d23fc493253b9f8358cc4e8e6195a9d573e98acd8e7f29`.

## Reproduction

```sh
./scripts/verify_credential_leases.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- `MemoryStore` provides deterministic process-local atomicity for current
  local/test composition. A durable shared store is required before a
  multi-replica server deployment can claim cross-process atomicity.
- Concrete connector and runner adapters consume the callback in COH-E06.
- Tamper-evident audit persistence and signed checkpoints belong to CYB-49;
  this boundary supplies and fail-closes on its required audit port.
- Independent security architecture review remains required before the first
  production release, as recorded by the product-owner design approval.
