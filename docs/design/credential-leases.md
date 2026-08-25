# Credential leases, rotation, and revocation

## Purpose

CYB-45 implements COH-E04-04 and SEC-012, SEC-024, and SEC-040. After final
authorization, policy, and approval decisions, the broker may issue one
short-lived credential capability for one actor, task, canonical action,
sorted target set, operation, connector or runner, authenticated transport
identity, credential version, and validity window. The capability is single-use
by default and never appears in a serializable contract.

This boundary does not make policy or approval decisions. It consumes trusted,
positive decision snapshots and rejects any changed or stale snapshot before
dispatch. Policy, approval lifecycle, and tamper-evident audit storage are
implemented by COH-E05; the lease broker already requires their ports and fails
closed when required audit cannot append.

## Issuance contract

The strict `coh.credential-lease/v1` request contains:

- a UUIDv7 request, idempotency key, and organization/tenant/case/actor context;
- one UUIDv7 task and canonical action digest;
- one sorted, unique, bounded set of target digests;
- one finite typed operation;
- one connector or runner ID and authenticated transport-identity digest;
- one credential class and versioned opaque secret reference; and
- a requested lifetime from one through 300 seconds.

It deliberately contains no credential value, capability, bearer token,
private key, password, path, URL, environment variable, or command. The broker
may shorten the requested lifetime. The frozen adversarial corpus has 24
mutations covering unknown fields, missing scope, malformed IDs/digests,
ambiguous targets, audience changes, excessive lifetime, secret-bearing fields,
and invalid or forbidden references.

The request does not prove authority. `IssuanceAuthority` is separate trusted
input and includes current actor revision and active state; positive
authorization, policy, and applicable approval decisions and their digests;
and an active audience revision observed within 30 seconds. A remote audience
must have mutually authenticated TLS. Exact authority/request context,
audience, and transport identity must match.

## Broker-owned capability

Successful issuance creates 256 random capability bits and a UUIDv7 lease ID.
Only the SHA-256 capability digest enters the atomic store. `Handle` exports
the lease ID but keeps capability bytes private and has no serializable token
field. `Destroy` overwrites the bytes and is idempotent. Entropy, store, or
mandatory audit failure returns no handle; if storage succeeded before audit
failed, the record is atomically revoked and the handle is destroyed.

Issuance idempotency is keyed by organization, actor, and idempotency key and
binds the complete request digest. Reusing an exact request is
`issuance_replay`; changed reuse is `idempotency_conflict`. Neither returns a
second capability. Concurrent issuance has exactly one winner.

## Dispatch order

Every credential-bearing dispatch follows this order:

1. Check cancellation and basic broker availability.
2. Hash the private capability and atomically claim its lease record.
3. In the same claim, reject an unknown/mismatched capability, prior
   revocation, expiration, or prior consumption. A successful claim marks the
   record consumed before any later work.
4. Destroy capability bytes.
5. Require exact current organization, tenant, case, actor, task, canonical
   action, ordered target set, operation, audience, and transport identity.
6. Require the task active, E-stop inactive, actor and audience active, remote
   mTLS valid, audience observation fresh, and actor/audience revisions plus
   authorization, policy, and approval digests unchanged from issuance.
7. Ask the broker-only secret resolver for the current referenced credential.
   It independently rechecks actor/scope, active state, backend record,
   credential version, replay state, and its own mandatory audit.
8. Append the redacted lease-dispatch authorization decision.
9. Only after both audit boundaries succeed, invoke the adapter callback with
   a temporary credential copy. The resolver overwrites that copy on return
   and destroys its owned value.

Scope tampering, stale authority, cancellation, E-stop, transport certificate
rotation/revocation, credential rotation/revocation, or audit failure therefore
cannot reach the callback. A timeout, cancellation, or transient store failure
before atomic claim retains the handle for a fresh-context retry. Any failure
after claim consumes the lease; recovery requires a new authorization and
lease, preventing ambiguous replay.

## Rotation and revocation

Credential rotation is checked at dispatch rather than only at issuance. The
secret backend returns current trusted version metadata; an old reference is
`credential_stale_reference`, while an inactive record is
`credential_secret_revoked`. No process restart or model/workflow cooperation
is needed.

Administrative `Revoke` atomically marks the lease before its audit append.
Allowed reasons are closed values for operator action, credential rotation,
actor revocation, task cancellation, E-stop, or audience revocation. If the
revocation audit append fails, the operation returns unavailable but the lease
stays revoked. A concurrent dispatch observes either the completed claim or the
revocation under the same store lock; it cannot bypass both.

Remote runner or service identity is bound by kind, ID, revision, and
transport-identity digest. Remote issuance and dispatch require current mTLS.
Certificate rotation changes the bound digest/revision and invalidates the old
lease; certificate or audience revocation denies immediately.

## Audit and redaction

Lease decisions record validated context, lease/request IDs, actor/audience
revisions, task/action/target-scope digests, finite operation and audience,
credential class, opaque reference digest, authorization/policy/approval
decision digests, secret-resolution decision digest, time bounds, outcome, and
safe reason code. They exclude capability bytes/digest, credential entry ID,
credential bytes, backend private detail, callback error, and secret-derived
material.

Invalid input clears free-form operation, audience ID, and credential class
before audit. Mandatory audit uses a cancellation-independent five-second
append context so a client cancellation cannot erase the denial record. Audit
failure always blocks issuance or callback entry. Callback errors are replaced
with `dispatch_failed`; no adapter detail crosses the boundary.

## Failure and recovery matrix

| Condition | Result |
|---|---|
| Invalid/secret-bearing issuance input | `invalid_input`; redacted audit; no capability |
| Actor, authorization, policy, approval, audience, or mTLS denial | `denied`; no capability |
| Exact/changed issuance replay | `conflict`; no second capability |
| Entropy/store/audit unavailable during issuance | `unavailable`; no usable capability |
| Expired, revoked, consumed, or tampered lease | `denied`/`conflict`; no secret resolution |
| Changed action/target/task/audience/transport or authority revision | `denied`; consumed lease; no callback |
| Task cancellation or E-stop | `denied`; consumed lease; no callback |
| Rotated/revoked credential | `denied`; consumed lease; no callback |
| Secret or lease audit failure | `unavailable`; consumed lease; no callback |
| Cancellation/timeout/store outage before claim | fail closed; fresh-context retry may recover |
| Callback failure after authorization | sanitized `dispatch_failed`; lease remains consumed |

## Verification and residual scope

Run:

```sh
./scripts/verify_credential_leases.sh
```

Tests cover contract denial cases, exact binding, redaction, entropy and audit
failure, stale authority, non-mTLS peers, concurrent issuance, concurrent
single-use dispatch, replay, capability tamper, expiration, administrative
revocation, actor/audience revocation, certificate and credential rotation,
task cancellation, E-stop, store recovery, callback failure, and zero callback
entry on every denial under the race detector.

`MemoryStore` is the deterministic process-local composition used by current
local and test profiles. A durable shared store is required before a
multi-replica server deployment can claim cross-process atomicity. Connector
and runner implementations consume this callback in COH-E06. Tamper-evident
audit persistence and signed checkpoints belong to CYB-49. Independent
security architecture review remains required before the first production
release.
