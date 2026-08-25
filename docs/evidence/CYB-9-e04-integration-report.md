# CYB-9 E04 identity, configuration, and secrets integration report

| Field | Value |
|---|---|
| Issue | COH-E04 / CYB-9 |
| Requirements | FR-002, FR-003, FR-004, FR-078, FR-079, FR-080, FR-082, NFR-002, SEC-010, SEC-011, SEC-012, SEC-014, SEC-015, SEC-024, SEC-040 |
| Verification date | 2026-08-25 |
| Design-freeze anchor | Product-owner approval at `8c6012d` |
| Integration checkpoint | `9b5e3fc3ee9d048d96f6515302f2ff6a16f12f27` |
| Review status | Local technical evidence complete |

## Outcome

All five E04 leaves are Done and the cross-leaf verifier passes. Native
workstation uses named local Ed25519 authentication; native-server and Compose
use pinned OIDC authentication. All three profiles feed the same deterministic
RBAC evaluator and require explicit organization, tenant, actor, case, role,
permission, and action-tier scope on every request.

Secret references remain opaque from contract through backend resolution,
audit, evidence, and credential use. Broker-owned credential leases bind exact
scope and re-read the current secret version and active state before every
single use. Expiry, rotation, revocation, replay, stale authority, crossed
transport identity, or audit failure prevents connector/runner callbacks
without process restart.

## Child completion audit

| Child | Deliverable | Linear status | Evidence |
|---|---|---|---|
| CYB-41 / COH-E04-01 | Local authentication and scoped RBAC | Done | `CYB-41-local-auth-report.md` and checksum ledger |
| CYB-42 / COH-E04-02 | Deployment-profile validation | Done | `CYB-42-deployment-profile-report.md` and checksum ledger |
| CYB-43 / COH-E04-03 | Secret references and backends | Done | `CYB-43-secret-backend-report.md` and checksum ledger |
| CYB-45 / COH-E04-04 | Credential leases, rotation, and revocation | Done | `CYB-45-credential-lease-report.md` and checksum ledger |
| CYB-174 / COH-E04-05 | Server OIDC authentication and scoped RBAC | Done | `CYB-174-server-oidc-report.md` and checksum ledger |

## Integration acceptance

| Criterion | Authoritative evidence | Result |
|---|---|---|
| Local and server profiles enforce organization, tenant, actor, case, and role scope on every request | Local and OIDC `Authorize` paths both call `localidentity.EvaluateRBAC`; shared request contract requires all four context IDs; profile fixtures bind local/loopback or OIDC/mTLS; all five focused verifiers pass | Pass |
| No secret value appears in prompts, logs, traces, workflow history, API responses, or evidence artifacts | Opaque secret-reference contract and backend decision types; owned-memory destruction; schema/source surface guards; secret worktree/history/evidence stages; local, OIDC, resolver, and lease redaction tests | Pass |
| Lease expiration and revocation prevent further connector or runner use without process restart | Atomic single-use lease claim; current credential version/active lookup on every use; expiry, rotation, credential revocation, lease revocation, replay, mTLS identity, and concurrency tests | Pass |

## Cross-profile authorization proof

The workstation and server authorization boundaries differ only in how they
establish a session. Both validate the same `localidentity.Request`, reload the
current actor, require exact organization and actor, and invoke the same RBAC
evaluator. That evaluator independently checks tenant/case grants, fixed role
permissions, and action tiers. Neither profile accepts implicit tenant/case
selection, client/model authority, or stale actor revisions.

Deployment validation prevents profile substitution: workstation requires
local authentication and loopback transport; native-server and Compose require
OIDC and mTLS. Server composition further binds the provider configuration to
the exact audited deployment decision and has no local-auth fallback.

## Secret and lease integration proof

Secret-bearing configuration accepts only versioned opaque references. The
resolver maps those references through trusted backends into callback-bounded
owned memory and records redacted decisions before return. Values, tokens,
capabilities, backend details, and private errors have no fields in the
contracts, decisions, events, or evidence schemas.

Credential lease use atomically consumes a private 256-bit capability, then
rechecks actor, task, policy, approval, audience, mTLS, exact action/target
scope, E-stop, and the current secret version/active state. It appends both the
resolver and lease decisions before invoking the callback. Rotation or
revocation therefore takes effect at the next use without restart; replay
cannot resolve a second credential.

## Verification evidence

Clean integration checkpoint `9b5e3fc3ee9d048d96f6515302f2ff6a16f12f27`
passed the E04 verifier with summary:

`children=5 profiles=local+native-server+compose request-scope=organization+tenant+actor+case+role+permission+tier rbac=shared secrets=opaque+redacted leases=expiry+rotation+revocation-live audit=fail-closed failures=0`

The integration-log SHA-256 is
`16a3affa65cd972ff3332d45cf68625000d4530a0b10f0a27c2c6ef39dfd8aab`.

The same clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`. The report digest is
`7ee6ec9b7e130881db836e92e7586b137a7d9b745be02dadc41b2cc0f4097b9d`;
the report-file SHA-256 is
`88efff0fee42af09e5aca696cd331fc19e7eb089f2c68482daa87ac635a959be`.
Provenance records 458 source files, source digest
`f85968230b21c9ada4c22ce7c6c29049de33e0258300826a9e1e40c76fb74541`,
Go 1.26.7 on darwin/arm64, and clean VCS state.

## Reproduction

```sh
./scripts/verify_e04_identity_configuration.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- Process-local memory adapters require durable shared implementations before
  multi-replica production qualification.
- Production HTTP/JWKS, platform, network, and packaging adapters remain later
  executable-server and release work; this milestone freezes and verifies the
  authority boundaries they must compose.
- Independent security architecture review remains required before the first
  production release. It is the approved non-blocking design follow-up, not an
  unresolved E04 implementation finding.
