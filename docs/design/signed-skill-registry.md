# Signed and reviewed skill registry

## Purpose

COH-E09-01 establishes the trust boundary between skill-package production and
agent consumption. Production orchestration may name a reviewed skill, but it
cannot load writable skill directories, invent a permission, select a stale
version, approve a review, or grant signature authority.

The durable registry owns promotion state and immutable signed envelopes.
Agent orchestration receives only a narrow lookup activity. The activity asks
a trusted authority port for exact current policy and key/review snapshots,
then submits all bindings to the registry. Neither the model nor the action
broker receives the authority objects.

## Admission chain

1. Strict decoding produces canonical COH-CJ-1 manifest and command bytes.
2. The manifest digest and command digest are recomputed.
3. Publisher, every independent reviewer, and owner signatures are verified
   under separate domains and current authority revisions.
4. Review identity, revision, decision, reviewer set, and evidence must exactly
   match the current review snapshot.
5. The policy-decision digest is recomputed and its actor/scope/action/target
   must exactly match the signed command.
6. Current durable state and optimistic revision must match the command.
7. Promotion verifies predecessor lineage; rollback selects only the immediate
   predecessor; revocation selects only current.
8. Audit appends idempotently before availability and returns a digest-bound
   receipt.
9. Registry provenance incorporates the prior provenance, command,
   idempotency, policy, review, and audit digests.
10. One guarded repository transaction commits new state and, for a new
    promotion, the immutable signed envelope.

An audit success followed by a lost database response is safe. Retry observes
the committed command and idempotency digests and returns the same state
without another transition. An audit success followed by a failed database
commit leaves an orphan audit fact but never exposes uncommitted skill state.

## Resolution chain

Resolution binds request ID, actor, organization, tenant, case, task, expected
manifest digest, required permission, policy digest, and deadline. The access
decision digest is recomputed. Durable state must be promoted and point to that
exact digest. The immutable envelope is loaded and signatures, current
publisher/reviewer authority, review, validity, and permission are rechecked.
Revocation therefore takes effect on the next lookup without restarting a
worker.

Audit must succeed before the copied result is returned. Results contain
manifest/content/resource digests, bounded metadata, permission names, owner,
review, and provenance only. They contain no content bytes or authority-bearing
object. COH-E09-02 may use these references for progressive discovery, but
retrieval remains a later separately authorized operation.

## Durability and immutability

The repository adapter writes `coh.domain/v1` catalog records through the
guarded storage port. State uses deterministic UUIDv7-shaped record identity
for organization/tenant/skill; immutable versions use a separate deterministic
identity for organization/tenant/manifest digest. SQLite WAL, FULL synchronous
mode, optimistic revisions, and the storage idempotency ledger provide durable
atomic transitions and changed-replay rejection.

Earlier version records are never updated by later promotion, rollback, or
revocation. Rollback moves a pointer and reverses the previous/current lineage;
it does not copy or rewrite envelope bytes.

## Failure model

Malformed input, unsigned or tampered bytes, stale/revoked authority,
non-independent review, policy/access digest drift, cross-scope access,
unpromoted permission, stale state, changed replay, missing version, audit
failure, cancellation, timeout, and corrupt store output fail closed.
Dependency messages are reduced to stable reason codes; raw errors, secrets,
content, paths, and policy sources are never returned in registry results.
