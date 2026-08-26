# COH tamper-evident audit contract v1

| Field | Value |
|---|---|
| Issue | COH-E05-06 / CYB-49 |
| Requirements | SEC-020, SEC-021, SEC-022, EVAL-006, EVAL-013 |
| Event | `coh.audit-event/v1` / `1.0.0` |
| Record | `coh.audit-record/v1` / `1.0.0` |
| Checkpoint | `coh.audit-checkpoint/v1` / `1.0.0` |
| Canonicalization | COH-CJ-1 |
| Hash | SHA-256 |
| Signature | Ed25519 |

## Boundary

Each organization/tenant pair owns an independent monotonically sequenced
chain. An event is a closed, redacted projection: it admits identifiers,
revisions, bounded tokens, timestamps, and digests, but has no field for raw
requests, targets, arguments, policy source, prompts, evidence bytes,
credentials, signatures, or free-form error text.

`event_id` is either the source UUIDv7 or, for a source without a distinct
event identity, the SHA-256 digest of that source's complete canonical safe
event. This gives exact crash replay without inventing nondeterministic IDs.
Organization-scoped events that occur before tenant selection use the reserved
tenant UUID `00000000-0000-7000-8000-000000000000`; they never enter a real
tenant's chain.
`occurred_at` is retained when the source supplies a stable canonical time. It
is omitted when the source has no replay-stable occurrence time; verifiers use
the always-present record `appended_at` and never invent a source timestamp.

The first record uses the all-zero SHA-256 genesis value. Every later record
must name the immediately preceding sequence and chain hash. Append allocates
the sequence and commits the canonical event, event digest, prior hash, chain
hash, and idempotency result atomically. Exact replay returns the prior result;
changed reuse, gaps, forks, mutation, deletion, insertion, or reordering deny.

## Record hash

For hashing only, `chain_hash` is replaced by the all-zero genesis value. The
stored chain hash is:

```text
SHA-256(
  "COH-AUDIT-RECORD-V1\0" ||
  uint64be(len(canonical_record_preimage)) ||
  canonical_record_preimage
)
```

The event digest is SHA-256 over the canonical embedded event. Both checks are
required; a matching outer hash never excuses an invalid event contract.

## Checkpoints

A checkpoint signs the exact tenant chain head, covered sequence interval,
record count, reason, key identity/revision, and canonical UTC creation time.
For signing only, `signature` is the unpadded base64url encoding of 64 zero
bytes. The Ed25519 input is:

```text
"COH-AUDIT-CHECKPOINT-V1\0" ||
uint64be(len(canonical_checkpoint_preimage)) ||
canonical_checkpoint_preimage
```

The durable appender creates a checkpoint at the earlier of:

- the first append after a UTC date change, covering the prior non-empty
  interval; or
- 10,000 records after the prior checkpoint.

Shutdown/export may add `manual_final`, but it cannot replace either mandatory
trigger. A required append or checkpoint that cannot be durably committed
returns unavailable; consequential action receives no usable authorization or
dispatch result.

Historical verification resolves the exact signing key revision. Revocation
does not erase a valid signature created before revocation, but the verifier
reports the key lifecycle evidence and rejects a checkpoint created outside
that revision's admitted interval.

## Persistence and recovery

SQLite and PostgreSQL use dedicated append-only audit record, checkpoint,
idempotency, and head state. PostgreSQL tenant RLS is mandatory. Recovery reads
and verifies the stored head before accepting another append; it never repairs
a fork or gap by guessing. Backup/export verification starts from genesis or a
trusted checkpoint and must consume the complete ordered interval.
