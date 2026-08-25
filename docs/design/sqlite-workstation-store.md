# SQLite workstation store

| Field | Value |
|---|---|
| Issue | COH-E03-03 / CYB-39 |
| Requirements | FR-078, NFR-009, NFR-011 |
| Storage contract | `coh.storage/v1` |
| Driver | `modernc.org/sqlite` v1.57.0 |
| Profile | Native, single-user workstation |
| Data | Operational metadata and immutable artifact references |
| Status | Implemented and verified |

## Decision

The workstation adapter is `internal/persistence/sqlite.Store`. It implements the
existing database-neutral `workflow.StorageDriver`; callers still receive only a
`workflow.Repository` produced by `workflow.GuardStorage`. SQL handles, queries,
driver errors, migration callbacks, evidence bytes, policy decisions, and action
execution do not cross that boundary.

The adapter uses the pinned pure-Go `modernc.org/sqlite` driver. This keeps the
native workstation path independent of a C compiler and is proven by the
SQLite verifier with `CGO_ENABLED=0`. The complete transitive module graph,
primary license hashes, embedded SQLite public-domain notice, and sqlite-vec MIT
notice are closed inputs in `ci/dependencies.allow` and `ci/licenses.allow`.

## Open and durability profile

`Open` accepts only an absolute clean database path and an existing absolute
backup directory. The resolved parent directories may be symlinks, but the
database itself must be a regular non-symlink file. One database connection is
used for the single-user workstation profile, and the adapter establishes and
verifies these fixed settings:

| Setting | Value | Reason |
|---|---|---|
| Journal | WAL | Committed state survives a process exit and readers do not observe a partial commit |
| Synchronous | FULL | A successful commit waits for durable WAL synchronization |
| Foreign keys | ON | Future registered schemas cannot silently bypass referential constraints |
| Trusted schema | OFF | Schema content cannot invoke unsafe application-defined behavior |
| Busy timeout | 5 seconds by default; bounded to 1 ms–1 minute | Lock contention is bounded instead of hanging indefinitely |
| WAL autocheckpoint | 1,000 pages | WAL growth is bounded under workstation use |

No Docker detection, network listener, generic SQL method, shell entry point, or
executor capability is introduced. This delivers SQLite persistence for FR-078;
the Temporal development service and local evidence store remain their own
adapters and issues.

## Transaction and schema model

The registered metadata migration creates records, idempotency results, outbox
messages, and a monotonic commit sequence. A metadata transaction:

1. hashes the complete immutable request and checks the idempotency key;
2. checks every expected revision inside the database transaction;
3. applies every put or delete;
4. inserts every outbox reference in the same transaction;
5. advances the commit sequence and stores the exact result for replay; and
6. commits all changes together or rolls all of them back.

An exact retry returns the original sequence and result with `Replayed=true`.
Changed input under the same key, stale revisions, reused outbox identities, and
unsafe rollback return typed conflicts or denials. Canonical record and digest
validation remains enforced by the guarded storage contract.

For NFR-011, metadata and its immutable artifact reference become visible in the
same atomic commit. This adapter never claims that referenced evidence bytes
exist: CAS ingestion must verify and publish the complete digest-addressed
artifact before it supplies a reference to this store.

## Outbox lifecycle

Claims are bounded, sorted, and restricted to one organization and tenant.
Every claimed message receives an internally generated UUIDv7 lease. Delivered
and dead-letter settlements are terminal and exact replays succeed. A retry is
persisted long enough for an exact settlement replay, then becomes claimable;
the next claim replaces the old lease and clears the retry marker. A stale or
different lease cannot settle the message.

The worker name is validated by the port but is not an authorization principal.
Outbox delivery grants no action authority; any consequential effect must still
pass the policy and broker boundaries.

## Registered migrations and backup

Migration SQL is a closed adapter registry. The workflow plan can name only a
component, version, registered checksum, verified backup digest, and direction.
Unknown or changed migration content is denied.

Before the initial metadata migration, the adapter creates a consistent SQLite
snapshot. Manual backups first request a passive WAL checkpoint and then use
SQLite `VACUUM INTO` to create a new file in the configured backup directory.
The file is streamed through SHA-256 and registered with its absolute path,
length, digest, and UTC creation time. Every apply and rollback re-reads and
rehashes that artifact before executing. A missing, changed, or unregistered
backup is denied. Metadata rollback is allowed only when records, idempotency
results, and outbox rows are empty.

Migration state and its resume digest are updated in the same SQLite transaction
as the registered DDL. Therefore a process exit yields either the prior state or
the completed state, never a durable half-applied marker.

## Recovery and failure behavior

The SQLite-specific integration test launches a subprocess, commits metadata
and outbox state, and exits without closing the store. A new process opens the
same WAL database and proves the original idempotent result is recoverable. This
directly exercises abrupt single-process recovery required by NFR-009. The later
CYB-44 crash-injection matrix will extend this from the adapter boundary to
workflow and action confirmation.

The shared storage suite additionally proves exact transaction replay, changed
retry and stale-revision conflicts, readback, transactional outbox delivery,
settlement replay, cancellation, timeout, clean-context recovery, migration
apply/replay/checksum denial, and rollback. SQLite-specific cases cover WAL
reopen, consistent backup, retry reclaim, non-empty rollback denial, and tampered
backup denial. Backend diagnostics are normalized to the seven storage error
codes and raw SQLite text never crosses the workflow boundary.

## Verification

```sh
scripts/verify_sqlite_store.sh
scripts/run_ci_quality.sh baseline
```

The dedicated verifier runs unit, race, CGo-disabled, vet, and architecture
checks. The baseline gate additionally covers formatting, file size, workflow
policy, secrets, static analysis, license, exact dependencies, locked
vulnerability data, SBOM, supply chain, and provenance.
