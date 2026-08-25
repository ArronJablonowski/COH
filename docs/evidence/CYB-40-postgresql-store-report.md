# CYB-40 PostgreSQL server store verification report

| Field | Value |
|---|---|
| Issue | COH-E03-04 / CYB-40 |
| Requirements | FR-079, NFR-009, NFR-011 |
| Verification date | 2026-08-25 |
| Storage contract | `coh.storage/v1` |
| Implementation checkpoints | `12b8140`, `13429d2`, `4187ba3` |
| Driver | `github.com/jackc/pgx/v5` v5.10.0 |
| Qualified integration server | PostgreSQL 16.14 Alpine |
| Data classification | Operational metadata and immutable artifact references |
| Review status | Local technical evidence complete |

## Outcome

The server profile now has a concrete PostgreSQL repository with atomic
optimistic metadata transactions, tenant-scoped idempotency, an atomic outbox,
concurrent `SKIP LOCKED` workers, forced row-level tenant security, registered
transactional migrations, external backup verification, bounded connections,
and fail-closed runtime-role and TLS checks.

The shared contract was tightened so one transaction cannot cross organization
or tenant scope and outbox settlement always carries that explicit scope. The
SQLite adapter was updated to enforce the same settlement identity. The
workflow-visible six-method repository remains storage-neutral and exposes no
SQL, credentials, backup commands, callbacks, policy decisions, or executors.

## Acceptance evidence

| Acceptance criterion | Evidence | Result |
|---|---|---|
| Server transactions | pgx transaction commits records, outbox, idempotency result, and global sequence atomically | Pass |
| Row-level tenant scoping | RLS enabled and forced on all tenant tables; unscoped reads return zero and cross-scope writes are denied | Pass |
| Migrations | Registered checksum-bound transactional DDL, advisory locking, apply/replay/denial/rollback suite | Pass |
| Outbox workers | Ordered bounded claims with `FOR UPDATE SKIP LOCKED`; concurrent workers produce one owner | Pass |
| Backup hooks | Narrow `BackupVerifier`; failed immutable-backup proof denies DDL before migration | Pass |
| Connection limits | Pool defaults to 8, accepts explicit minimum/maximum bounds, and denies values above 128 | Pass |
| Runtime least privilege | Superuser and `BYPASSRLS` roles are denied during `Open` | Pass |
| Transport protection | TLS required except an explicit loopback-only integration-test exception | Pass |
| Typed failure handling | Invalid, denial, not-found, conflict, cancel, timeout, and unavailable mappings are redacted | Pass |
| Idempotent concurrency | Advisory lock yields one commit and one replay for simultaneous equal requests | Pass |
| Recovery | Timed-out database work rolls back; a new context reads the committed record successfully | Pass |
| Common semantics | All five `storetest.Run` conformance scenarios pass against PostgreSQL and SQLite | Pass |
| Full baseline | 18 of 18 required stages passed from a clean commit | Pass |

## Relevant traces

The tenant trace opens the store as a non-superuser role without `BYPASSRLS`,
commits a canonical record through the guarded port, and proves that the same
role sees zero rows without transaction-local organization and tenant settings.
It then attempts a differently scoped insert while the original tenant settings
are active; PostgreSQL's forced `WITH CHECK` policy rejects it.

The concurrency trace starts two workers against one outbox row. PostgreSQL row
locks and `SKIP LOCKED` return exactly one lease across both results. A separate
trace submits the same new transaction concurrently; the scoped advisory lock
causes one result to be the original commit and the other to be its exact replay
with the same commit sequence.

The recovery trace cancels `pg_sleep` through a 20 ms context deadline, observes
the typed `timeout` result, rolls the transaction back, and successfully reads
the previously committed record using a new context. The backup-denial trace
proves a verifier failure prevents registered DDL from starting.

## Dedicated integration evidence

`scripts/verify_postgres_store.sh` uses the exact official image digest
`sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777`.
It exposes PostgreSQL only on a random loopback port, stores its data and runtime
socket on disposable tmpfs mounts, creates a non-superuser/non-`BYPASSRLS`
application role, and runs the package with the race detector.

The clean integration run reported PostgreSQL 16.14, all five conformance
scenarios, forced RLS, backup denial, privileged-role denial, and race success.
The container is removed by the script's exit trap.

## Baseline evidence

The clean implementation checkpoint `4187ba304967b3f337f8e1d3ab9bf21954630c96`
passed all 18 baseline stages. Report digest
`7953ea828a385942407f5c7d8a851eb371e030de65d37dbc00ce912384c2aabe`
was promotable. The dependency stage approved 95 exact modules and reported
zero vulnerabilities against the locked database. The license stage approved
all 95 module license hashes, both SQLite notices, and both shipped
vulnerability-database inputs. The architecture report covered 24 packages with
zero violations.

A final clean baseline report and checksum ledger are attached after this
evidence packet itself is committed.

## Residual scope

- Production deployment must provide its infrastructure artifact-catalog
  implementation of `BackupVerifier`, a least-privilege database role, and a
  TLS endpoint. The adapter intentionally does not run `pg_dump`.
- Cross-node workflow crash injection and confirmed-action recovery belong to
  CYB-44, which this issue unblocks.
- Independent security architecture review remains required before the first
  production release; it is the approved non-blocking follow-up, not a blocker
  for this implementation issue.
