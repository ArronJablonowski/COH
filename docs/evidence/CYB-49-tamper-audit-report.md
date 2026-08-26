# CYB-49 tamper-evident audit verification

| Field | Evidence |
|---|---|
| Stable key | COH-E05-06 |
| Requirements | SEC-020, SEC-021, SEC-022, EVAL-006, EVAL-013 |
| Contract commit | `19d9ed578cb4abe353183a0a7a974e96c1804255` |
| Implementation commits | `c622cee9704ab3b8766dbd62ee6d9b59033126b5`, `abfd36b6fed9aa62f4e72c2a82cf39300a7461b0`, `9ce4c82219f463d50d296af85678d7679074870c` |
| Audit contract | `coh.audit-event/v1`, `coh.audit-record/v1`, `coh.audit-checkpoint/v1` / `1.0.0` |
| Clean baseline evidence | `COH-toolchains/ci-artifacts/baseline/run.lGBdIk` |
| Baseline report digest | `1fe5a10019c0b8f9ea5c22738f9f6994603c7bf88edaf18adf1a93452bf821f4` |
| Result | Passed |

## Verified control

COH now stores independent organization/tenant audit chains with monotonically
allocated sequences. Every immutable record contains one canonical closed,
redacted event, its SHA-256 digest, the prior chain hash, a domain-separated
chain hash, and canonical append time. The event schema has no raw payload,
target, argument, policy source, prompt, credential, signature, evidence-byte,
or free-form error field.

The workflow service reads and validates the current head, builds the next
record, and commits the record, optional mandatory checkpoint, head, and exact
idempotency result atomically. Exact replay returns the original sequence and
chain hash. Changed reuse denies. Concurrent writers use optimistic head
comparison; SQLite serializes its writer and PostgreSQL adds a tenant advisory
transaction lock plus a head-row lock.

SQLite and PostgreSQL use dedicated audit migrations and canonical-byte
columns. SQLite rejects record/checkpoint update and deletion through database
triggers. PostgreSQL forces tenant RLS and provides immutable tables only
tenant-scoped SELECT and INSERT policies. Neither adapter exposes an audit
mutation or deletion operation.

## Checkpoint and key proof

The service creates an Ed25519 checkpoint at the earlier of the first append
after a UTC date change or 10,000 records since the prior checkpoint. The
shared commit guard recomputes the mandatory trigger independently inside both
adapter paths, so a caller cannot omit or substitute the checkpoint.

Each checkpoint binds the organization, tenant, covered-from sequence, head
sequence/hash, exact record count, trigger reason, signing-key identity and
revision, and creation time. The signature uses a distinct canonical
domain-separated message. The broker keyring retains only the active private
key plus historical public authorities, checks validity and revocation time,
generates cryptographically random UUIDv7 checkpoint IDs, returns owned public
key copies, and zeroes private bytes on destruction.

## Mandatory producer and outbox composition

Typed projection adapters map existing safe policy activation/evaluation,
approval fingerprint, approval lifecycle, local/OIDC authentication and
authorization, secret resolution, and credential-lease decisions to the
closed event contract. Events before tenant selection enter a reserved
organization audit tenant rather than a real tenant's chain.

The transactional-outbox projector binds the exact outbox event ID, tenant and
case, topic, and payload digest. It returns the committed chain hash as
settlement evidence. A caller must keep the outbox retryable when projection
fails; a dead-lettered consequential event is not dispatch authority. Existing
policy, approval, identity, secret, and credential boundaries already convert
their mandatory sink failure to an unavailable result and return no usable
allow, session, secret, lease, or approval capability.

## Adversarial trace

| Test, fixture, or guard | Proven behavior |
|---|---|
| `TestRecordAndCheckpointRoundTrip` | Canonical event/record recovery and deterministic Ed25519 checkpoint verification succeed. |
| `TestTamperGapForkAndSignatureDeny` | Event mutation, digest mutation, chain mutation, sequence gaps, forks, and checkpoint tamper deny. |
| `TestAppendReplaysAndDailyCheckpoint` | Exact replay recovers the original result and UTC rollover checkpoints the prior interval. |
| `TestCheckpointTargetUsesEarlierMandatoryTrigger` | Record 10,000 checkpoints the new head; an earlier date rollover checkpoints the prior head first. |
| `TestCheckpointFailureBlocksAppend` | Signer/key failure leaves the new event uncommitted and returns unavailable. |
| `TestConcurrentAppendsSerialize` | Racing writers commit unique contiguous sequences through optimistic retry. |
| `TestCanceledAndTimedOutAppendPublishNothing` | Canceled and expired contexts publish no record. |
| `TestVerifyDetectsMutationAndMissingDailyCheckpoint` | Full verification detects record mutation and absent mandatory rollover checkpoints. |
| `TestOutboxProjectionReturnsSettlementEvidence` | Atomic outbox references enter the chain and return a settlement evidence hash. |
| Shared audit store conformance | SQLite and PostgreSQL produce the same append, replay, daily checkpoint, read, and stale-head behavior. |
| Adapter append-only tests | SQLite triggers and PostgreSQL forced RLS reject record update and deletion. |
| `denial-corpus.json` | 34 unique contract, canonicalization, replay, chain, signature, key, availability, crash, and dead-letter denials remain frozen. |

The verifier reads the complete ordered interval and validates canonical event
digests, sequence and previous links, record hashes, scope, checkpoint coverage
and counts, signature/key revision and admitted interval, UTC rollover,
10,000-record maximum intervals, and the stored durable head. Truncation,
insertion, deletion, reordering, mutation, unknown keys, stale revisions, and
post-revocation checkpoints fail integrity verification.

## Migration and recovery

SQLite creates and verifies a backup before applying its audit migration.
PostgreSQL uses the externally verified bootstrap backup required by its
storage contract. PostgreSQL stores canonical timestamps as text so database
microsecond conversion cannot alter nanosecond contract bytes.

A crash before commit leaves no partial record. Lost commit response is
recovered by exact event identity. A stale head reloads and retries; changed
input never recovers as success. Recovery verifies the durable head and chain
instead of guessing or synthesizing a missing record.

## Gate evidence

The dedicated verifier completed with:

```text
tamper-audit summary: chains=tenant-scoped append=immutable hash=sha256 checkpoints=daily-or-10000 signature=ed25519 replay=exact concurrency=cas adapters=sqlite+postgres denials=34 failures=0
```

It validates all three JSON schemas and the 34-case denial corpus, then runs
domain, workflow, keyring, shared-store, SQLite, and PostgreSQL tests; race,
vet, architecture, and file-size gates also pass.

The clean baseline ran at `9ce4c82` with `vcs_modified=false`. All 18 required
stages passed: format, file size, workflow, worktree/history secret scans,
architecture, quality-contract, vet, static analysis, unit, race, fuzz seeds,
license, dependency/vulnerability, SBOM, supply chain, evidence secret scan,
and provenance. It covered 42 architecture packages with zero violations and
verified 183 approved modules with zero vulnerabilities.

## Follow-on bindings

The COH-E05 integration gate must prove that canonical manifest, policy,
approval, audit reservation/outbox delivery, and consequential dispatch remain
one fail-closed composition. Execution isolation, credential/runner lease,
E-stop, and exactly-once side-effect reconciliation remain COH-E06 controls.
The independent review tracked by CYB-173 remains a hard pre-production gate.
