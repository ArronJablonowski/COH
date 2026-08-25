# Local authentication and RBAC

## Purpose

CYB-41 implements the native-workstation identity boundary for COH-E04-01 and
FR-002, FR-003, FR-004, SEC-014, and SEC-015. A successful login establishes a
named actor by Ed25519 proof of possession. Every subsequent API or CLI request
must carry explicit organization, tenant, case, and actor context and pass both
the current session check and deterministic role/scope authorization.

The boundary authorizes a request to enter its application use case. It does
not authorize a consequential action. `action.request` allows an Analyst to
submit a T0–T4 request to the later policy/broker path; it never substitutes for
policy, ROE, approval, credential lease, audit, or broker dispatch controls.

## Public contracts

The versioned contract is `coh.local-identity/v1` / `1.0.0` under
`contracts/identity/v1`. Actor records contain:

- a UUIDv7 actor and organization;
- a stable display token;
- independently assigned, sorted roles;
- exact tenant and case grants;
- an Ed25519 public key, positive revision, and active state.

Authorization requests contain a UUIDv7 request, opaque idempotency key,
SHA-256 payload digest, API or CLI channel, all four context identifiers, one
permission, and an action tier only where the permission requires it. Strict
decoding rejects unknown fields and trailing JSON. Private keys, signatures,
session tokens, passwords, raw bodies, and backend errors are not contract or
decision fields.

## Authentication protocol

The server performs this sequence:

1. Validate the claimed organization and actor and load the current active
   actor record.
2. Generate a 128-bit challenge identifier and 256-bit nonce from
   `crypto/rand`; set a two-minute default expiry.
3. Persist the challenge atomically and durably append a redacted
   `challenge_issued` event before returning it.
4. Ask the client to sign the base64url-decoded canonical message:

   ```text
   coh.local-auth.challenge/v1
   <challenge-id>
   <organization-id>
   <actor-id>
   <UTC-expiry-RFC3339Nano>
   <256-bit-base64url-nonce>
   ```

5. Atomically consume the challenge before checking the proof. Invalid proofs,
   retries, and concurrent replays cannot reuse it.
6. Revalidate the stored challenge structure, exact public key, actor revision,
   active state, expiry, and Ed25519 signature.
7. Generate a 256-bit opaque session token and a distinct non-secret session
   identifier. Return the token once; store only `sha256(token)`.
8. Durably append a redacted `session_issued` event before returning the token.
   If audit append fails, revoke the stored session and return `unavailable`.

The default session lifetime is eight hours and the hard maximum is 24 hours.
Challenge and session TTL configuration outside its safe range is rejected.
The native reference repository keeps challenges and sessions ephemeral, so a
restart requires reauthentication rather than restoring bearer authority.

## Authorization sequence

For every API and CLI request, `Service.Authorize`:

1. strictly validates the complete request and 256-bit session token;
2. looks up the session by token digest and validates its invariant fields;
3. denies an expired or explicitly revoked session;
4. requires exact session organization/actor equality with request context;
5. reloads the actor and requires the same active revision on every request;
6. enforces exact organization, tenant, case, role, permission, and tier
   semantics through `localidentity.EvaluateRBAC`;
7. atomically binds `(session ID, idempotency key)` to the complete request
   digest; and
8. durably appends the redacted, digest-bound decision before returning allow.

An exact retry is allowed with `replayed=true`. Reusing an idempotency key with
any changed request field, context, permission, tier, request identifier, or
payload digest returns `conflict`. Role or grant updates increment the actor
revision and immediately invalidate prior sessions. Explicit logout/revocation
sets `RevokedAt` atomically and is idempotent.

The in-memory workstation repository uses a single lock to make challenge
consumption, session revocation, and replay check-and-store operations atomic.
It deliberately does not provide an in-memory audit sink: `AuditSink` must
durably accept a decision, and absence or failure of that sink is fail-closed.

## Fixed role permissions

| Role | Permissions at this boundary |
|---|---|
| Analyst | case read/write, evidence read/write, query execution, workflow management, T0–T4 action request |
| Approver | case/evidence read, T2–T4 approval decision |
| Administrator | case read, configuration management, identity management, audit read |
| Auditor | case/evidence/audit read |
| Service | case/evidence read, service invocation |

Roles are additive and independently assignable. Administrator does not imply
Approver. Service cannot be combined with a human role. A grant either lists
sorted exact case IDs or explicitly grants all cases in one tenant; ambiguous,
empty, duplicate, or crossed grants deny.

## Audit and redaction

Authentication events contain safe outcome/reason codes, validated actor and
organization identifiers, actor revision, non-secret challenge/session
correlation IDs, timestamp, and an event digest. Authorization decisions add
request/payload digests, validated context, permission, tier, session ID,
actor revision, and replay state.

No audit type has a field for a private/public key, signature, signing message,
session token, token digest, raw body, or backend error. Malformed caller values
are omitted rather than copied into audit fields. Tests marshal every recorded
event/decision and assert that credential material is absent. Missing audit or
an append error changes the returned outcome to `unavailable`; no allowed
decision crosses the boundary.

## Failure and recovery

| Condition | Result |
|---|---|
| Malformed actor/request/context | `invalid_input`; no inferred scope |
| Unknown actor, invalid proof, or unknown token | `denied`; generic safe reason |
| Crossed organization/actor/tenant/case or role escalation | `denied` |
| Expired challenge/session, stale actor revision, or revocation | `denied` |
| Changed replay under an existing idempotency key | `conflict`; no allow |
| Directory, session, replay, randomness, or audit failure | `unavailable`; backend detail discarded |
| Canceled or expired context | `canceled` or `timeout`; a fresh request may recover |

## Verification and residual scope

The frozen contract suite contains nine valid actor/request fixtures and 22
adversarial mutations. Focused tests cover cryptographic success, invalid proof
consumption, replay, tampered challenge/session state, expiry, actor revision,
role escalation, crossed scope, redaction, audit failure, timeout,
cancellation, recovery, and concurrent atomicity under the race detector.

Run:

```sh
./scripts/verify_local_auth.sh
```

CYB-43 owns opaque secret references and secret backends. CYB-45 owns
target/action/actor/time-scoped credential leases and their dispatch-time
rotation/revocation. Append-only tenant-scoped hash-chain storage and signed
audit checkpoints are later audit-boundary work; this issue supplies and
fail-closes on the durable audit port. OIDC and recovery-admin behavior belong
to the server-mode identity implementation, not this local-workstation leaf.
Independent security architecture review remains required before the first
production release.
