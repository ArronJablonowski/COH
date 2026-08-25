# CYB-41 local authentication and RBAC report

| Field | Value |
|---|---|
| Issue | COH-E04-01 / CYB-41 |
| Requirements | FR-002, FR-003, FR-004, SEC-014, SEC-015 |
| Verification date | 2026-08-25 |
| Contracts | `coh.local-identity/v1` / `1.0.0`; `coh.local-auth/v1` / `1.0.0` |
| Implementation checkpoints | `111f1b6`, `86b92a7`, `3bdd77d`, `9687660`, `273d3e9`, `2681d6b` |
| Qualified implementation checkpoint | `2681d6bdbf169c3e25d7f6d3a6390827e336c06a` |
| Review status | Local technical evidence complete |

## Outcome

COH now establishes named local actors through one-use Ed25519
challenge-response and issues short-lived opaque sessions whose bearer tokens
are stored only as SHA-256 digests. Every API and CLI authorization request
requires explicit organization, tenant, case, and actor context and is checked
against the current actor revision, exact grants, fixed role permissions,
action-tier rules, session state, and atomic idempotency state.

All nine valid actor/request fixtures and all 22 adversarial contract mutations
passed. Cryptographic, session, role/scope, replay, tamper, stale-state,
revocation, redaction, audit, cancellation, timeout, recovery, and concurrent
atomicity tests passed under the race detector. The clean 18-stage baseline is
promotable. No unresolved blocking finding remains.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Named local actor and API/CLI role, tenant, case, and action-tier enforcement | Versioned actor/request schemas; five-role matrix; both channels in frozen valid fixtures; `Service.Begin`, `Complete`, and `Authorize` | Pass |
| Default deny, actor/scope binding, redaction, fail-closed audit, replay/tamper/stale/revocation | Exact context/grant checks, actor revision on every request, digest-only session store, atomic replay binding, one-use challenge, redacted event/decision tests, mandatory audit port | Pass |
| Invalid input, denial, timeout/cancellation, recovery | Typed error/outcome tests cover malformed input, proof/session failure, crossed scope, role escalation, expired contexts, and successful fresh-context recovery | Pass |
| Applicable automated and quality gates | Focused unit/race/vet/architecture verifier plus clean promotable 18-stage baseline | Pass |
| Required evidence | Frozen adversarial corpus, cryptographic trace, RBAC policy decisions, fail-closed audit trace, denial/revocation tests, focused log, baseline report, design document, checksum ledger | Pass |

## Authentication trace

The server validates a named active actor, generates a 128-bit challenge ID and
256-bit nonce, and stores the two-minute challenge before auditing issuance.
The client signs a domain-separated message containing the challenge, exact
organization/actor, expiry, and nonce. Completion atomically consumes the
challenge before verification and rechecks its structure, public key, actor
revision, active state, expiry, and Ed25519 signature.

A valid proof creates a distinct non-secret session ID and 256-bit bearer token.
Only `sha256(token)` enters session storage; the token is returned once. The
default lifetime is eight hours and the hard maximum is 24 hours. If the
required authentication audit append fails, the stored session is revoked and
no token is returned. Invalid proofs consume their challenge, and concurrent
challenge consumers produce exactly one success.

## Authorization and policy decision trace

`localidentity.EvaluateRBAC` fixes the five independent roles and exact
permissions. Analyst action-request permission accepts T0–T4 but does not grant
execution authority. Approver decisions accept only T2–T4. Administrator does
not imply Approver, and Service cannot be combined with a human role.

`Service.Authorize` validates the complete request and token, reloads the
session and current actor, requires equal organization/actor and actor revision,
then evaluates tenant/case grants and role/tier permission. The resulting
decision binds request ID, payload digest, channel, complete context,
permission, tier, actor revision, session ID, replay state, outcome, reason,
and its deterministic SHA-256 decision digest.

The authorization audit recorder proves append-before-return behavior for
allowed, invalid, denied, conflicting, canceled, timed-out, and unavailable
decisions. A missing or failing audit sink changes the response to
`unavailable`; it cannot return allow. This RBAC boundary only permits a request
to enter its use case. Consequential-action policy, exact approval, credential
lease, and broker dispatch remain mandatory later boundaries.

## Replay, tamper, denial, and revocation evidence

- Challenge IDs are consumed atomically before proof validation; invalid proof
  and concurrent reuse cannot create a session.
- Challenge message, actor, expiry, key, and revision mutations deny.
- `(session ID, idempotency key)` is atomically bound to the complete request
  digest. Exact retry returns `replayed=true`; any changed field returns
  `idempotency_conflict`.
- Wrong organization/actor returns a session/identity mismatch; wrong tenant or
  case returns case-scope denial; permission escalation returns role denial.
- Actor key/role/grant/active updates require the exact next revision and make
  all prior sessions stale immediately.
- Explicit session revocation is atomic and idempotent; later authorization
  returns `session_revoked`.
- Expired challenges and sessions deny. Directory, session, replay, randomness,
  and audit failures return redacted `unavailable` outcomes.

## Secret-redaction proof

Authentication events deliberately have no field for public/private keys,
signatures, signing messages, session tokens, token digests, request bodies, or
backend errors. Authorization decisions likewise contain only validated
identity/scope metadata, safe enums, correlation IDs, and digests. Tests marshal
recorded evidence and search for the real proof, token, key, token digest, and
malformed caller secret. None is present. The source-surface test also denies
network, process, runtime, and logging imports in production authentication
files.

## Baseline evidence

Clean checkpoint `2681d6bdbf169c3e25d7f6d3a6390827e336c06a`
passed all 18 required stages with `quality_gate_promotable=true`. The quality
report digest is
`99e782981b5269f4bcc0b48ecbccf12b59e10392a34d069bc225f303b715629d`;
the report-file SHA-256 is
`ea2a95e5c36dcd7ddb37a4b12e91722832cf8dfd124cc1260e300390e3f84532`.
Provenance records 374 source files, Go 1.26.7 on darwin/arm64, and clean VCS
state. The focused verification-log SHA-256 is
`7cc1492b88c3e0ef039da7e75ab3e0b4e758f088c54753880b9de4ce901f5791`.

## Reproduction

```sh
./scripts/verify_local_auth.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- The workstation repository intentionally keeps challenges and sessions
  ephemeral; process restart revokes bearer authority and requires login.
- Durable audit storage must implement the mandatory `AuditSink`; append-only
  tenant hash chains and signed checkpoints are later audit-boundary work.
- CYB-43 owns opaque secret references and backends. CYB-45 owns scoped
  credential leases and dispatch-time rotation/revocation.
- OIDC and recovery-admin behavior belong to the server-mode identity leaf.
- Independent security architecture review remains required before the first
  production release.
