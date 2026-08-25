# CYB-35 storage port verification report

| Field | Value |
|---|---|
| Issue | COH-E03-02 / CYB-35 |
| Requirement | NFR-020 |
| Verification date | 2026-08-25 |
| Contract | `coh.storage/v1` |
| Implementation checkpoints | `6b0cb42`, `255b777` |
| Data classification | Operational metadata and immutable references; no credentials or evidence bytes |
| Review status | Local technical evidence complete |

## Outcome

The workflow-visible repository now provides guarded, database-neutral metadata,
outbox, and migration capabilities. The boundary enforces canonical identity and
digest binding, optimistic revision checks, idempotency semantics, bounded tenant
leases, versioned checksum-bound backup-aware migrations, typed failures, context
cancellation and timeout, safe error redaction, and immutable input/output copies.

No SQLite, PostgreSQL, SQL, credential, policy, callback, or executor type crosses
the port. Concrete stores remain deliberately scoped to CYB-39 and CYB-40.

## Acceptance evidence

| Acceptance criterion | Evidence | Result |
|---|---|---|
| Transactional metadata and optimistic concurrency | `Transaction`, `Mutation.ExpectedRevision`, guarded commit-result validation | Pass |
| Transactional outbox | Atomic transaction message set plus claim/settle capabilities | Pass |
| Versioned migrations | `MigrationPlan` version/checksum/backup/direction and status/result lifecycle | Pass |
| Idempotency | Shared exact-replay, changed-input conflict, settlement replay, and migration replay scenarios | Pass |
| Narrow database-neutral interface | Three capabilities, six operations, reflection surface test | Pass |
| Typed errors and safe diagnostics | Seven stable codes; unknown driver detail removed from returned chain | Pass |
| Invalid/denial/conflict paths | Unit and conformance negative cases | Pass |
| Cancellation, timeout, and recovery | Pre/post driver context guard and clean-context recovery tests | Pass |
| Adapter parity foundation | One reusable suite at `internal/persistence/storetest.Run` | Pass |

## Executable scenarios

The guarded boundary tests cover missing and typed-nil drivers, valid transaction
and replay, byte and result-map immutability, invalid contract rejection, untyped
driver-error redaction, typed conflict propagation, cancellation, timeout,
recovery, canonical reads, bounded outbox claim, idempotent settlement,
cross-tenant result denial, migration apply/status/rollback, checksum mismatch,
record digest mismatch, envelope/key mismatch, and duplicate mutations.

The reusable adapter suite separately covers five end-to-end scenarios:

1. transaction commit, exact replay, and read;
2. idempotency mismatch, optimistic conflict, and valid revision update;
3. transactional outbox claim and replay-safe settlement;
4. cancellation, timeout, and recovery; and
5. migration pending, apply, replay, checksum denial, and rollback.

A synchronized in-memory reference driver passes the suite under unit and race
execution. SQLite and PostgreSQL adapters must run this same suite in CYB-39 and
CYB-40.

## Verification commands

```sh
scripts/verify_storage_contract.sh
scripts/check_file_sizes.sh
go test ./...
go test -race ./internal/workflow ./internal/persistence/storetest
go vet ./...
scripts/check_markdown_links.sh \
  docs/design/storage-port-contract.md \
  docs/evidence/CYB-35-storage-port-report.md
```

The final clean baseline quality report and deterministic checksum ledger are
published with the Linear closure record after the evidence commit is pushed.

## Residual scope

- CYB-39 owns SQLite transactions, WAL recovery, backup hooks, and invocation of
  the common conformance suite.
- CYB-40 owns PostgreSQL transactions, row-level tenant scope, connection bounds,
  backup hooks, and invocation of the same suite.
- CYB-44 owns cross-adapter crash injection and exactly-once workflow/action
  confirmation. CYB-35 creates the enforceable seams but does not claim those
  adapters or later integration tests are already complete.
