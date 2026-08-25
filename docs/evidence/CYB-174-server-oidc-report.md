# CYB-174 server OIDC authentication and scoped RBAC report

| Field | Value |
|---|---|
| Issue | COH-E04-05 / CYB-174 |
| Requirements | FR-002, FR-003, FR-004, SEC-014, SEC-015 |
| Verification date | 2026-08-25 |
| Contract | `coh.server-oidc/v1` / `1.0.0` |
| Design-freeze anchor | Product-owner approval at `8c6012d` |
| Implementation checkpoints | `6ab0212`, `5cb6231`, `4294b4e`, `3c75579`, `cad149e` |
| Qualified implementation checkpoint | `cad149ecce4640f048a3dd10e134997af68f20cf` |
| Review status | Local technical evidence complete |

## Outcome

Native-server and Compose profiles now have a pinned, fail-closed OIDC
authentication boundary. It accepts only the configured HTTPS issuer, selected
audience, ordered algorithm allowlist, opaque JWKS source reference, mTLS
transport, and exact audited deployment-profile decision. EdDSA, ES256, and
RS256 assertions map immutable issuer/subject identity to the current COH actor
and produce short-lived opaque sessions whose bearer values are stored only as
SHA-256 digests.

Every request rechecks the session, deployment decision, current signing key,
current actor revision, exact organization/actor, tenant/case grant, role,
permission, action tier, and idempotency binding before returning an audited
decision. State replay, token substitution, stale claims, key or actor
rotation, session revocation/expiry, crossed scope, cancellation, and audit
failure deny. The clean 18-stage baseline is promotable. No unresolved blocking
finding remains for this leaf.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Pinned issuer/audience/JWKS source, algorithm allowlist, signature, nonce, and temporal validation | Strict provider/claim schemas; 24-case frozen corpus; JOSE decoder; EdDSA/ES256/RS256 tests | Pass |
| Immutable subject mapping and current actor authority | Issuer/subject directory lookup; exact organization/actor/role/tenant assertion checks; actor revision reload on every request | Pass |
| Organization, tenant, actor, case, role, permission, and tier enforcement on every server request | Opaque session lookup followed by current key/actor checks and shared `EvaluateRBAC`; crossed-scope and escalation tests | Pass |
| Replay, rotation, revocation, expiry, cancellation, audit, and redaction failure behavior | Atomic state and request replay stores; live key/actor checks; mandatory bounded audit; adversarial and race tests | Pass |
| Native-server and Compose composition | Audited deployment validator plus exact profile-kind and profile-decision binding in `ComposeServerOIDC`; three profile tests | Pass |
| Applicable automated and quality gates | Focused schema/unit/race/vet/architecture verifier plus clean promotable 18-stage baseline | Pass |

## Authentication and signature trace

`Begin` validates exact organization and configured audience, creates a 128-bit
one-time state ID and 256-bit nonce, and stores only the nonce digest with the
issuer, audience, profile kind, and profile-decision digest. The state is
atomically consumed before token parsing. Concurrent completion has one winner;
invalid completion cannot retry the state.

The compact token is bounded to 16 KiB. JOSE headers reject duplicate,
unknown, or trailing fields and require `typ=JWT`, an allowed algorithm, and a
bounded key ID. Key lookup is fixed to the configured issuer and opaque JWKS
reference. Keys require active state, positive revision, valid time, exact
algorithm/key type, and safe structural validation. EdDSA uses Ed25519; ES256
uses checked P-256 keys and raw 64-byte signatures; RS256 requires a 2048-bit or
larger modulus and exponent 65537 or greater.

Claims are decoded with the same duplicate/unknown/trailing-field rejection.
They require exact issuer, one selected audience, organization, constant-time
nonce-digest equality, bounded age/skew, and valid not-before/expiry. Immutable
issuer/subject maps to a directory actor; asserted actor, sorted roles, and
sorted tenant IDs must equal the current actor. Token claims cannot manufacture
COH grants or permissions.

## Session and per-request authority trace

Successful completion generates independent session-ID and 256-bit token
material. Only the token digest enters the session store. The issued object
serializes ID and expiry only, exposes token material through a bounded
callback, and supports destruction. Session expiry is capped by token expiry
and a fifteen-minute hard maximum.

`Authorize` validates the complete local-identity request, loads the session by
token digest, and rejects invalid, revoked, expired, or profile-mismatched
records. It requires exact organization and actor, then reloads the pinned key
and directory actor. Any missing, inactive, rotated, expired, algorithm-changed,
or revision-changed authority invalidates the session immediately.

The shared RBAC evaluator then enforces current tenant/case grants, fixed role
permissions, and action tiers. `(session ID, idempotency key)` is atomically
bound to the complete request digest. Exact retry returns `replayed=true`; any
field change returns `idempotency_conflict`. Tests cross organization, actor,
tenant, case, and permission independently and prove denial.

## Composition, audit, and redaction proof

`ComposeServerOIDC` first obtains an audited deployment-profile decision. It
returns no service for a workstation profile, wrong profile kind, changed
decision digest, non-OIDC/non-mTLS declaration, invalid provider, missing port,
or failed profile audit. Native-server, connected Compose, and air-gapped
Compose declarations all bind successfully when their exact decisions match.
There is no local-auth fallback.

Authentication events contain only safe identifiers, enums, revisions, time,
and digests. Issuer, subject, and key ID are digest-only. Raw compact token,
claims, nonce, public/private key, session token/digest, request body, and
backend errors are absent. Authorization decisions use the existing redacted
identity decision contract. Login, completion, revocation, and authorization
all require audit in a cancellation-independent bounded context. An audit
failure returns unavailable; newly stored sessions are revoked before return.

## Corrective baseline trace

The first clean baseline at `3c755793c98ef67362a5d804a9145ec4dff0dee5`
denied at static analysis because the initial ES256 key validator directly read
deprecated mutable ECDSA coordinates. Its report digest is
`b97caa33684a8e6d63990b983fb186f7968fb1d0ef48e8c50fee5d0fea62c433`;
the report-file SHA-256 is
`0aaf76eb0e6988ab6a01f0c90ef652e9d5e2d0eb07dd8d03978843412e8cab1a`,
and the static-analysis log SHA-256 is
`1dc43a3b029b4b50ad7e45721c775f1a77af25f972482f4343808560cb043ced`.

Checkpoint `cad149e` replaced coordinate access with Go 1.26's checked
`PublicKey.Bytes` validation without suppressing the analyzer. Pinned
staticcheck, the focused verifier, and the full baseline then passed.

## Baseline evidence

Clean checkpoint `cad149ecce4640f048a3dd10e134997af68f20cf` passed all
18 required stages with `quality_gate_promotable=true`. The report digest is
`37b67041191958984d118c3c75504d02bc7fa28db9f957de4199374b2a16de7b`;
the report-file SHA-256 is
`462bf04d8c883f8212dc36900cff2111a1771979df95130b75976c89cb4e2ad4`.
Provenance records 455 source files, source digest
`2c0420e172d982a4bb8b67cfa0033f4d6c22e67cb1ff58fd5deab0ec68513284`,
Go 1.26.7 on darwin/arm64, and clean VCS state. The focused verification-log
SHA-256 is
`307fa15f3ec0f338c15206e59f03f2680e0b163bba1c6a4eb9972d3eceaf386c`.

## Reproduction

```sh
./scripts/verify_server_oidc.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- `MemoryRepository` and `MemoryKeySource` are deterministic process-local
  implementations. Multi-replica production needs durable shared state,
  session, replay, and bounded JWKS-source adapters.
- Browser redirect/callback, secure cookie, and HTTP middleware integration
  belong to the future executable server transport; the composition and
  authentication services expose the required fail-closed authority boundary.
- Independent security architecture review remains required before the first
  production release, as recorded by the product-owner design approval.
