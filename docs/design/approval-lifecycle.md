# Approval lifecycle

| Field | Value |
|---|---|
| Issue | COH-E05-04 / CYB-51 |
| Requirements | SEC-006, SEC-008, SEC-040 |
| Contract | `coh.approval-lifecycle/v1` / `1.0.0` |
| Persistence | `coh.domain/v1` `approval` record plus transactional outbox |

## Purpose and ownership

The lifecycle turns a verified approval fingerprint into bounded, durable
authority. It supports request, grant, reject, expire, consume, and revoke
without treating fingerprint equality as an unused grant.

The service is private to `internal/broker`, the sole action-authority
boundary. Its policy/fingerprint proof and actor-authority types are not
re-exported. Workflows and transports therefore cannot construct, grant, or
consume approval authority directly. The security-neutral record and
transition invariants live in `internal/domain/approvallifecycle`.

## Bound authority

Every record immutably binds:

- approval, organization, tenant, and case identities;
- fingerprint, action-manifest, and policy-decision digests;
- requestor identity and fresh authority revision;
- action-owner identity;
- validity start and exclusive end;
- required distinct grant count; and
- maximum and current use counts.

Every revision also records the last acting identity/revision, bounded reason
code, operation digest, event identity, and broker-owned timestamp. It stores
no raw target, argument, payload, credential, policy source, prompt, evidence,
free-form reason, session token, public/private key, or secret value.

The operation digest covers the operation, approval identity, bounded
idempotency key, expected revision, reason code, complete fresh actor snapshot,
fingerprint, manifest-envelope digest, signer identity/revision/status and
public-key digest, and policy decision. Only the digest is persisted.

## State and authorization rules

The executable transition table is
[`approval-lifecycle-state-machine.md`](../../contracts/approval/v1/approval-lifecycle-state-machine.md).
Its terminal states are rejected, expired, consumed, and revoked.

Request requires an active, exact-scope requestor with `action.request`, an
exact requestor binding, and successful re-verification of the signed action,
signer authority, positive intent policy decision, and fingerprint. CYB-51
uses one required grant; the record supports a bounded threshold so CYB-48 can
add the policy-derived T4 value without changing persistence.

Grant requires an active exact-scope actor with `approval.decide`, a distinct
non-requestor identity, a current validity window, and fresh fingerprint proof.
Reject and revoke require `approval.decide`. Expire requires a scoped active
service identity with `service.invoke` and broker time at or after the exclusive
validity end. Consume requires the exact action owner with `action.request`, a
granted/current record, and fresh fingerprint proof.

Actor roles and permissions must be sorted, unique, bounded tokens. Identity,
scope, active state, and revision arrive from trusted broker composition for
each call; lifecycle code never recovers missing authority from stored or
model-provided data.

## Optimistic concurrency and retries

Every new transition supplies the immediately preceding revision and writes
exactly `revision + 1`. SQLite and PostgreSQL enforce this through the existing
metadata transaction compare-and-swap. Concurrent operations from the same
revision have one winner; all losers conflict.

The storage transaction retains its bounded idempotency key. In addition, the
record's last-operation digest lets a retry recover a committed result after a
lost response: only the same operation, inputs, actor authority, proof, key,
and expected revision return `replayed=true`. Changed input or a later record
revision conflicts. Recovery returns state; it does not create new authority
or decrement a use counter.

Consumption increments the use count in the same compare-and-swap that writes
the new state. Reaching the maximum produces terminal `consumed`. Consequently,
two concurrent consumers can never both obtain the final use.

## Audit and failure behavior

A successful state revision and one redacted outbox reference commit in the
same storage transaction. The topic identifies the operation and the immutable
record reference/digest identifies its complete safe provenance. Neither a
state change without audit nor an audit success without its state change can
commit.

Invalid and denied attempts have no state mutation, so they use the mandatory
approval audit sink. Audit is written with a detached five-second bounded
context so request cancellation does not erase the denial record. If audit is
unavailable, the effective result is `audit_unavailable`; no usable lifecycle
result is returned. Unvalidated identifiers and digests are blanked before an
event reaches audit.

Cancellation and deadline expiration preserve their typed outcomes and then
attempt mandatory audit. Storage, verifier, entropy, and malformed stored-state
failures are normalized to bounded reasons without backend details.

## Persistence and migration

The domain registry now maps `approval` to
`contracts/domain/v1/approval-lifecycle.schema.json`. This is the required
policy/audit schema migration from the earlier provisional approval payload.
Legacy payloads are never interpreted as active lifecycle authority and must
be re-requested.

No SQL DDL migration is required. Both adapters already store canonical
versioned domain envelopes by kind and identity, enforce optimistic revisions,
retain idempotency results, and commit outbox rows atomically. Their shared
conformance suite now writes and updates a real lifecycle approval record,
checks exact replay and stale conflict, and verifies the stored revision and
digest. PostgreSQL retains its existing tenant RLS around the same generic
tables.

## Threat decisions

| Threat | Required result |
|---|---|
| Model or workflow asserts approval | No broker proof capability; deny |
| Fingerprint, policy, signer, actor, or scope changes | Fresh verification fails or binding denies |
| Requestor self-approves | Deny and audit |
| Duplicate approver | Append-only distinct-grant invariant denies |
| Stale writer or changed retry | Conflict and audit |
| Concurrent final use | One commit; all other consumers conflict or see terminal state |
| Expired, rejected, consumed, or revoked grant | Terminal/default denial |
| Invalid input contains secret-like text | Never persist; blank unvalidated audit fields |
| Audit or storage unavailable | No usable success result |
| Crash after commit before response | Exact operation digest recovers committed state as replay |

The adversarial corpus is
[`lifecycle-denial-corpus.json`](../../contracts/approval/v1/fixtures/lifecycle-denial-corpus.json).
The dedicated verifier runs contract, state-table, service, concurrency,
adapter-conformance, race, vet, architecture, and file-size checks.
