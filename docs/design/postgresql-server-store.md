# PostgreSQL server store

| Field | Value |
|---|---|
| Issue | COH-E03-04 / CYB-40 |
| Requirements | FR-079, NFR-009, NFR-011 |
| Storage contract | `coh.storage/v1` |
| Driver | `github.com/jackc/pgx/v5` v5.10.0 |
| Qualified integration server | PostgreSQL 16.14 Alpine, image digest `sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777` |
| Status | Implemented; release evidence pending |

## Purpose and boundary

`internal/persistence/postgres` is the multi-user server implementation of the
guarded workflow repository. It persists operational metadata and immutable
artifact references; it does not transport evidence bytes, make policy
decisions, execute actions, run shell commands, or create database backups.
Workflows receive only `workflow.Repository` after `workflow.GuardStorage` has
validated the storage contract.

The adapter uses native pgx transactions and a bounded pgx pool. Connection
URLs remain adapter configuration and never cross the workflow port. Errors are
mapped to the seven storage error codes without returning driver messages or
connection details.

## Connection and role requirements

Production connections require TLS. Plaintext is accepted only when the caller
explicitly enables the test exception and the parsed host is loopback. Pool
size is explicit, defaults to eight, and cannot exceed 128 connections.

The runtime database role must:

- own the COH tables and migration objects;
- be neither a superuser nor a role with `BYPASSRLS`;
- have no unrelated database authority; and
- use a dedicated database rather than a shared application schema.

`Open` checks role attributes before schema work. A privileged runtime role is
denied even when the supplied credentials are otherwise valid.

## Tenant row security

Every tenant data table carries `organization_id` and `tenant_id`. PostgreSQL
row-level security is both enabled and forced on records, idempotency entries,
and outbox rows. Each policy compares the row identity with two transaction-
local settings:

- `coh.organization_id`; and
- `coh.tenant_id`.

The adapter starts a transaction and assigns both settings with
`set_config(..., true)` before a tenant query. The local flag clears the values
on commit or rollback, preventing pooled connections from retaining a previous
tenant. Missing settings reveal zero tenant rows, and `WITH CHECK` rejects a
cross-tenant insert or update. The shared guard also denies a transaction that
contains more than one organization/tenant scope. Outbox settlement now carries
the same explicit scope as claim and metadata operations.

The global commit counter and migration state contain no tenant data and are
not RLS tables. They are never returned through a cross-tenant query.

## Transactions and idempotency

Each metadata transaction atomically commits all optimistic mutations, the
outbox rows, the immutable result, and its idempotency record. A transaction-
scoped advisory lock serializes the organization/tenant/idempotency-key tuple.
Concurrent equal requests therefore produce one commit and one replay instead
of a spurious optimistic conflict. Reusing a key with different bytes is a
typed conflict.

Record reads used for optimistic checks take row locks. A global monotonically
increasing commit sequence supplies provenance ordering; rolled-back attempts
can leave gaps but cannot publish partial state.

## Outbox workers

Claims are tenant-bound, ordered by message ID, and capped by the contract at
256 rows. `FOR UPDATE SKIP LOCKED` permits concurrent workers to claim disjoint
queue entries without duplicate ownership. A cryptographically random UUIDv7
lease, worker identity, and UTC deadline are written in the same transaction.

Settlement requires organization, tenant, message, and lease identities. An
identical settlement is replay-safe; a different result for the same lease is a
conflict. `retry` releases the deadline, and the next claim replaces the old
lease before another outcome is accepted.

## Migrations and backup hook

Only migrations compiled into the adapter can run. The workflow plan carries a
component, version, registered checksum, backup digest, and direction—never SQL
or an executable callback. PostgreSQL transactional DDL and a component-scoped
advisory lock make apply/rollback atomic under concurrent deployment attempts.
Migration state and a deterministic resume digest are committed with the DDL.

`BackupVerifier` is the narrow deployment hook. Before any migration starts, it
must prove that the supplied SHA-256 digest names an immutable backup in the
deployment's artifact catalog. The adapter does not call `pg_dump`, invoke a
shell, or accept a command. Verification failure is a denial. Base metadata
rollback is conservatively refused after the first committed metadata
transaction, preventing an RLS-blind destructive rollback.

For a new database, deployment must provide a verified bootstrap-backup digest;
this records that the pre-schema state was captured, even when it was empty.

## Failure and recovery behavior

| Condition | Result |
|---|---|
| Invalid URL, bounds, contract, or scope | `invalid_input` |
| Missing TLS, privileged role, RLS write, migration, or backup proof | `denied` |
| Missing scoped record/message | `not_found` |
| Revision, unique key, serialization, deadlock, or lease conflict | `conflict` |
| Caller cancellation | `canceled` |
| Caller/server timeout | `timeout` |
| Other connection/backend failure | `unavailable` |

Context cancellation reaches pgx. A canceled transaction is rolled back; a new
context can safely retry the same immutable request. pgxpool replaces unusable
connections without widening the repository interface.

## Verification

`scripts/verify_postgres_store.sh` starts an isolated, loopback-only PostgreSQL
container with tmpfs data, creates a non-superuser/non-`BYPASSRLS` application
role, and runs the adapter tests with the race detector. The suite covers:

1. all five shared storage conformance scenarios;
2. forced RLS visibility and `WITH CHECK` denial;
3. connection bounds and privileged-role rejection;
4. concurrent idempotent transactions and concurrent outbox claims;
5. backup denial, cancellation/timeout, and clean recovery; and
6. apply, replay, checksum denial, and rollback of registered migrations.

The ordinary unit lane skips the external-server cases when the two explicit
test URLs are absent. CYB-40 evidence must include the dedicated integration
output plus the repository baseline quality report.
