# Progressive skill discovery

| Field | Value |
|---|---|
| Issue | COH-E09-02 / CYB-73 |
| Requirement | FR-042 |
| Milestone | COH-M3 Agent Alpha |
| Contract | `coh.skill-discovery-*/v1` / `1.0.0` |
| Registry dependency | COH-E09-01 / CYB-70 |

## Purpose

An agent must not receive every skill package, instruction body, or resource in
its context. Progressive discovery exposes only enough information for the
agent to select a candidate, then requires separate authorization before
revealing details or resolving one resource. Discovery never executes a skill.

The three phases are:

1. `compact_search`: return a bounded page containing only skill name, semantic
   version, exact manifest digest, and registry provenance.
2. `detail_expand`: for one exact compact result, return signed manifest
   metadata and resource descriptors after rechecking current authority.
3. `resource_fetch`: for one exact signed resource name and digest, return one
   matching immutable artifact reference.

## Durable catalog

The general workflow repository intentionally has no list or scan operation.
CYB-73 therefore adds one organization/tenant-scoped promoted-skill catalog
record maintained atomically by the CYB-70 repository adapter. Promotion or
rollback inserts or replaces a compact entry; revocation removes it in the same
optimistic transaction as the registry state change.

The catalog is a candidate index, not an authorization source. Each entry binds
the current manifest digest, registry-state revision, and registry provenance.
Before returning a compact result, discovery calls the signed registry for the
exact entry. The registry reloads durable state, verifies that it remains
promoted, re-verifies signatures, review and validity, checks the requested
permission and exact access decision, and appends its audit event. Any catalog
or state mismatch denies the whole page.

### Cutover

The generic SQL metadata schema does not change, but the skill metadata shape
does. A non-empty store created before CYB-73 can contain promoted CYB-70 state
without the new catalog record. That condition intentionally appears as an
empty catalog; discovery never scans arbitrary records or invents entries.
Before enabling discovery on such a store, operators must apply a reviewed
catalog backfill from the authoritative signed registry inventory or promote a
new reviewed version of each required skill. Empty pre-production stores need
no backfill. Rollback to a worker that does not maintain the catalog must not be
used while discovery writes are enabled.

## Scope and authorization

Every phase binds request ID, idempotency key, organization, tenant, case, task,
actor, policy digest, required permission, operation deadline, and exact phase.
Search authorization additionally binds query digest, page size, catalog
snapshot, and incoming cursor. Candidate authorization adds skill and manifest.
Detail adds the exact compact-result manifest. Resource resolution adds exact
resource name and digest.

The sequence is enforced through durable parent records. A detail request names
the compact-search idempotency key and expected search-result digest;
discovery loads that case/task-scoped record and confirms that its page contains
the exact skill and manifest. A resource request similarly names the detail
idempotency key and expected detail-result digest, and the stored detail must
contain the exact resource descriptor. Missing, cross-scope, substituted, or
changed parents are denied before phase authorization.

The authority returns a discovery decision plus the CYB-70 access and signing
authority snapshots. Discovery recomputes the discovery decision digest and
compares every field before calling the registry. Identity or policy fields
supplied by a model cannot authorize themselves.

## Pagination

Catalog entries and filtered results are deterministically sorted by skill
name. A page contains at most 32 entries. The cursor is a SHA-256 token over the
case/task/actor/policy/permission/query/snapshot/offset tuple; it contains no
path, URL, content, or mutable backend locator. A continuation request must
supply both the cursor and its expected snapshot digest. Changed snapshots,
forged cursors, or out-of-range offsets are denied.

## Retrieval boundary

The retriever receives only the already verified resource descriptor and exact
scope, policy, provenance, discovery-decision digest, and deadline. It returns
only `domain.ArtifactRef`. Discovery checks digest, media type, classification,
and length against the signed descriptor. The controller has no HTTP client,
shell, filesystem-write, connector, executor, model, or callback field.

Hostile-content inspection and quarantine are the downstream responsibility of
COH-E09-04 / CYB-75. CYB-73 deliberately returns an immutable reference rather
than content bytes so that later defense cannot be bypassed.

## Replay and recovery

Each operation records its canonical intent digest, authorization decision
digests, result digest, and provenance in the case-scoped metadata store.
Same-key changed intent is denied. Exact replay re-runs current authorization
and signed-registry resolution before returning the durable prior result, so a
later revocation or authority withdrawal takes effect immediately. If a search
snapshot or recomputed result differs from the stored result, replay is denied
as stale. Resource replay also revalidates the signed descriptor and requires
the retriever's exact immutable response.

All returned slices are owned copies. Cancellation and deadline errors remain
typed across catalog, authority, registry, retriever, and persistence
boundaries. Ambiguous dependency failure is unavailable and retryable; it never
falls through to an allow result.
