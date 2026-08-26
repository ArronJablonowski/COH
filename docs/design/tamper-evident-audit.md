# Tamper-evident audit and verification

| Field | Decision |
|---|---|
| Issue | COH-E05-06 / CYB-49 |
| Requirements | SEC-020, SEC-021, SEC-022, EVAL-006, EVAL-013 |
| Chain scope | Independent organization/tenant sequence |
| Hash | Domain-separated SHA-256 over canonical COH-CJ-1 records |
| Checkpoint | Ed25519 at UTC-day rollover or 10,000 records, whichever occurs first |
| Failure posture | Required append/checkpoint failure returns no usable consequential result |

## Trust and data boundary

Audit producers do not send arbitrary maps or log strings. Each producer
projects its existing safe decision into the closed `coh.audit-event/v1`
shape: scope, stable event identity, actor and revision when known, bounded
operation/outcome/reason tokens, subject identity/revision, and digests. Raw
targets, arguments, request bodies, policy source, prompts, credentials,
signatures, evidence bytes, and backend errors have no storage field.

Authentication that precedes tenant selection enters the reserved
organization audit tenant. Policy evaluation, approval fingerprint/lifecycle,
authorization, secret resolution, credential lease, and transactional-outbox
projections use their exact tenant and case scope. Source UUIDs or complete
safe-event digests are idempotency identities. A changed replay conflicts.

## Append transaction

The workflow audit service reads the current tenant head, constructs sequence
`head+1`, hashes the canonical event, and creates the domain-separated record
hash over the prior head. SQLite serializes the transaction on its single
writer. PostgreSQL combines tenant RLS, a tenant advisory transaction lock,
and a head-row lock. Both adapters atomically commit:

1. the immutable canonical record and indexed integrity columns;
2. any mandatory signed checkpoint;
3. the new tenant head; and
4. the exact idempotency result.

SQLite rejects record/checkpoint UPDATE and DELETE through triggers.
PostgreSQL grants tenant-scoped SELECT/INSERT RLS policies only; forced RLS
provides no UPDATE/DELETE policy for immutable tables. Adapter APIs expose no
mutation or deletion operation.

## Checkpoint scheduling and custody

Before the first append on a new UTC date, the service signs the prior
non-empty interval. At 10,000 records after the last checkpoint, it signs the
new record. If both would trigger, daily rollover is earlier and wins. The
shared commit guard independently recomputes this choice in both adapters.

The broker-owned keyring keeps only the current private Ed25519 key and public
historical revisions. It validates validity/revocation intervals, signs only a
complete canonical draft, returns owned public-key copies, generates UUIDv7
checkpoint identities from cryptographic randomness, and zeroes private bytes
on destruction. An exact historical key revision verifies prior signatures;
a checkpoint at or after revocation fails.

## Verification and recovery

Online/offline verification reads every record in sequence and proves source
scope, canonical event digest, prior link, chain hash, checkpoint interval and
record count, chain-head binding, signature, exact key revision, UTC rollover
coverage, 10,000-record maximum interval, and the durable head. It rejects
truncation against the stored head, gaps, forks, insertion, deletion,
reordering, mutation, invalid signatures, unknown keys, and post-revocation
checkpoints.

Crash before commit leaves no record. Lost commit response is recovered by
exact event replay. A stale head retries from fresh state; changed idempotency
input never retries as success. Outbox settlement uses the resulting chain
hash as evidence and must remain retryable when append/checkpoint fails.

## Migration and operations

Audit v1 is a dedicated migration alongside generic metadata. SQLite takes and
verifies a pre-migration backup. PostgreSQL requires its externally verified
bootstrap backup and applies forced tenant RLS. Canonical timestamps are stored
as text so PostgreSQL microsecond conversion cannot alter nanosecond contract
bytes. Operators verify a complete export from genesis or a separately trusted
checkpoint; no repair tool may synthesize a missing link.
