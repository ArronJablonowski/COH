# CYB-39 SQLite workstation store verification report

| Field | Value |
|---|---|
| Issue | COH-E03-03 / CYB-39 |
| Requirements | FR-078, NFR-009, NFR-011 |
| Verification date | 2026-08-25 |
| Storage contract | `coh.storage/v1` |
| Implementation checkpoint | `9f268b7` |
| Driver | `modernc.org/sqlite` v1.57.0, pure Go |
| Data classification | Operational metadata and immutable artifact references |
| Review status | Local technical evidence complete |

## Outcome

The native workstation now has a concrete SQLite storage driver with atomic
optimistic metadata transactions, exact idempotent replay, an atomic outbox,
bounded tenant-scoped UUIDv7 leases, replay-safe settlement, WAL/FULL durability,
abrupt-process reopen recovery, registered checksum-bound migrations, consistent
snapshot backup, and pre-migration backup verification.

The adapter remains behind the guarded six-method storage contract. It adds no
network, generic SQL, shell, policy, credential, or executor surface.

## Acceptance evidence

| Acceptance criterion | Evidence | Result |
|---|---|---|
| Workstation transactions and outbox | Atomic SQLite transaction plus common conformance scenarios | Pass |
| WAL-safe recovery | Subprocess commits and exits without `Close`; reopened store returns the exact committed replay | Pass |
| Registered migrations | Fixed metadata registry, DDL checksum, atomic state, apply/replay/rollback tests | Pass |
| Backup | WAL checkpoint, `VACUUM INTO`, streamed SHA-256, registry, pre-migration re-verification | Pass |
| Narrow interface and no bypass | Existing `workflow.StorageDriver`, guarded composition, architecture gate | Pass |
| Typed invalid/denial/conflict/cancel/timeout paths | Shared suite plus tampered-backup and rollback-denial cases | Pass |
| Idempotent boundaries | Transaction, settlement, migration, and retry/reclaim tests | Pass |
| CGo-independent native build | `CGO_ENABLED=0 go test ./internal/persistence/sqlite` | Pass |
| License and dependency closure | 26 exact modules, 2 embedded notices, locked vulnerability scan | Pass |
| Full baseline | 18 of 18 stages passed | Pass |

## Relevant trace

The WAL recovery trace is executable in
`TestWALRecoveryAndConsistentBackup`: the parent test prepares an empty backup
directory, starts `TestSQLiteCrashWriter` in a child process, and the child
commits fixture metadata and an outbox row before calling `os.Exit(0)` without
closing SQLite. The parent opens the same file, repeats the immutable request,
and receives `Replayed=true` with commit sequence 1. It then creates and verifies
a non-empty consistent backup.

The tamper trace creates a registered backup, appends bytes after registration,
and proves rollback is denied before DDL execution. The rollback safety trace
proves populated metadata cannot be destructively rolled back.

## Baseline evidence

The implementation baseline at the checkpoint passed all 18 stages. Its report
digest was `535f5fa8bf6e00b34f4c11216c9a7ee4ff5111e1ef41db4bba1748269777f4f8`.
The dependency stage approved 26 exact modules and found zero vulnerabilities;
the license stage approved all module hashes, two embedded SQLite notices, and
two shipped vulnerability-database inputs. The architecture report covered 22
packages with zero violations. Unit and race runs included the SQLite adapter,
the shared adapter suite, and the guarded workflow contract.

A final clean baseline report and checksum ledger are attached to CYB-39 after
this evidence packet is committed and pushed.

## Residual scope

- The workstation evidence CAS, Temporal persistence, configuration wiring, and
  packaging are separate planned adapters; SQLite stores only metadata and
  immutable references.
- CYB-40 implements the PostgreSQL server profile against the same conformance
  suite.
- CYB-44 expands crash injection through workflow replay and action confirmation.
- Independent security architecture review remains required before the first
  production release; it is non-blocking for this M1 implementation issue.
