# Storage port contract

| Field | Value |
|---|---|
| Issue | COH-E03-02 / CYB-35 |
| Requirement | NFR-020 |
| Contract | `coh.storage/v1` |
| Domain dependency | Qualified `coh.domain/v1` canonical records |
| Data classification | Operational metadata and immutable artifact references |
| Status | Implemented by the qualified SQLite and PostgreSQL adapters |

## Decision

Workflows receive one guarded `workflow.Repository`. Concrete SQLite and
PostgreSQL adapters implement the driver side and must be wrapped by
`workflow.GuardStorage` before composition. The port contains no SQL handles,
queries, driver errors, credentials, policy decisions, executable callbacks, or
evidence bytes.

The repository is composed from three small capabilities:

| Capability | Operations | Contract responsibility |
|---|---|---|
| Metadata | `Get`, `Transact` | Atomic metadata changes, optimistic revision checks, exact canonical bytes |
| Outbox | `ClaimOutbox`, `SettleOutbox` | Transactional publication, bounded tenant leases, idempotent settlement |
| Migration | `MigrationStatus`, `Migrate` | Registered apply/rollback, checksum binding, backup prerequisite, safe restart |

## Transaction and concurrency rules

A transaction carries a bounded idempotency key, one or more uniquely sorted
metadata mutations, and up to 256 uniquely sorted outbox messages. Each mutation
names the complete organization, tenant, case, kind, and record identity.
All mutations and outbox entries in one transaction must share exactly one
organization and tenant; a cross-scope transaction is denied before a driver is
called.

- `ExpectedRevision == 0` means the record must not exist.
- A put writes exactly `ExpectedRevision + 1`.
- A delete requires a positive existing revision and returns revision zero.
- Every mutation and outbox message commits atomically or none does.
- Repeating the same idempotency key with byte-equivalent input returns the
  original commit sequence with `Replayed=true`.
- Reusing an idempotency key for different input returns `conflict` without a
  write or outbox publication.
- A stale expected revision returns `conflict`; adapters never silently merge,
  overwrite, or infer a newer revision.

Metadata values are exact COH-CJ-1 canonical domain envelopes. The guard verifies
their digest and binds schema, kind, record ID, organization, tenant, case, and
revision to the storage key. It copies mutable byte slices at both sides of the
driver call so an adapter or caller cannot change an accepted record by aliasing.
Payload schema validation remains the domain-contract boundary's responsibility;
storage cannot reinterpret or authorize payload meaning.

## Outbox lifecycle

Outbox rows contain a topic plus immutable payload reference and digest, never
the evidence or executable action. A claim is bound to one organization and
tenant, a named worker, a maximum of 256 messages, and an explicit UTC lease
deadline. The guard denies over-limit, duplicate, unsorted, malformed, or
cross-tenant results.

Settlement binds the exact organization, tenant, message, and lease and records
`delivered`, `retry`, or `dead_letter`. Repeating an identical settlement is idempotent. A different
outcome for an already settled lease is a conflict. Outbox delivery does not
grant action authority; consequential effects still traverse the broker.

## Migration lifecycle

Migration code remains registered inside each adapter. A workflow-visible plan
contains only:

- contract version and component;
- positive target version;
- SHA-256 checksum of the registered migration artifact;
- SHA-256 digest of the verified pre-migration backup; and
- `apply` or `rollback` direction.

This prevents SQL, callbacks, shell commands, or arbitrary migration content from
crossing the port. The adapter persists progress internally. A canceled, timed
out, or interrupted call is retried from the registered plan; it resumes safely
or restarts safely and never accepts a changed checksum. Repeating a completed
direction returns the same result with `Replayed=true`. Rollback is an explicit
registered direction and cannot be synthesized from newer state.

Adapters register migrations by the pair `(component, version)`, allowing a
deployment binary to carry adjacent schema versions without conflating their
artifacts. After a component has persisted a nonzero version, any otherwise
valid registered plan whose version or checksum differs is rejected as
`denied`; the adapter does not auto-upgrade, auto-downgrade, or reinterpret that
mixed-version state. A version transition therefore requires a separately
designed transition protocol rather than an implicit `Migrate` call.

## Failure and recovery behavior

| Condition | Required result | Publication behavior |
|---|---|---|
| Malformed request or unsupported contract | `invalid_input` | Driver is not called |
| Digest, scope, identity, or driver-result mismatch | `denied` | No result is published |
| Missing record or registered migration | `not_found` | No default is invented |
| Stale revision or idempotency mismatch | `conflict` | No partial transaction |
| Context canceled | `canceled` | No successful result after cancellation |
| Deadline exceeded | `timeout` | No successful result after timeout |
| Unclassified adapter failure | `unavailable` | Safe diagnostic; backend detail is redacted |

Caller context is checked before and after every driver call. Recovery uses a new
context and the same immutable request. Context failure never becomes denial or
success, and an untyped driver error is not retained in the returned error chain.

## Adapter conformance

`internal/persistence/storetest.Run` is the common executable suite for every
storage adapter. It covers:

1. initial commit, exact replay, canonical read, and source immutability;
2. changed-input idempotency conflict, stale revision conflict, and valid update;
3. atomic outbox visibility, bounded claim, and replay-safe settlement;
4. cancellation, timeout, and clean recovery; and
5. initial migration state, apply, replay, registered mixed-version denial,
   checksum denial, and rollback.

CYB-39 and CYB-40 cannot qualify by substituting adapter-specific happy-path
tests for this suite. The M1 integration gate later runs the same domain and
storage conformance inputs against both implementations.

## Traceability

| Requirement | Implementation evidence |
|---|---|
| NFR-020 versioned and checksummed | `StorageContractVersion`, `MigrationPlan.Version`, `Checksum` |
| NFR-020 resumable or safely restartable | idempotent `Migrate`, persisted status/result, cancellation recovery suite |
| NFR-020 backup-aware | mandatory `BackupDigest` on every apply or rollback plan |
| NFR-020 upgrade and rollback tested | shared migration apply/replay/mixed-version denial/checksum denial/rollback conformance scenario |
| CYB-35 optimistic concurrency and idempotency | `Mutation.ExpectedRevision`, transaction idempotency conformance scenarios |
| CYB-35 storage-neutral boundary | six-method reflected API surface and architecture gate |
