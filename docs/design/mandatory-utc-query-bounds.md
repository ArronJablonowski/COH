# Mandatory UTC query bounds

| Field | Value |
|---|---|
| Issue | COH-E12-02 / CYB-84 |
| Requirements | FR-046, FR-047, FR-048, SEC-013 |
| Upstream contract | COH-E12-01 / CYB-85 query connector SPI |
| Authority boundary | COH-E05 policy, approval, audit, E-stop |
| Evidence boundary | COH-E10 immutable provenance and custody |
| Decision | Default deny; audit acceptance precedes query admission |

## Boundary and threat model

The admission control receives an immutable validated CYB-85 query plus a fresh
trusted authority snapshot. Query bytes cannot assert actor state, allowlists,
authorization, policy, approval, audit readiness, E-stop state, current time,
or revocation state. Those facts come from authenticated broker composition.

The control addresses these abuse and failure cases:

| Threat or ambiguity | Fail-closed invariant |
|---|---|
| Missing or cross-tenant scope | Organization, tenant, case, source, actor, and every resource must match fresh authority exactly. |
| Unbounded/live query | A non-empty half-open `[start,end)` interval is mandatory; start must precede end and both values are exact nanosecond UTC. |
| Excessive collection | Requested duration and every row/byte/time/page/slice/cost/rate limit must be nonzero and no wider than current authority and capability. |
| Future-unsafe interval | End may not exceed the broker-owned admission time plus the explicit clock-skew allowance; no implicit live tail exists. |
| Model or request grants authority | Only trusted authorization, policy, approval, actor, capability, allowlist, E-stop, and revocation snapshots can admit. |
| Stale/revoked authority | Actor, source, capability, policy, approval, and allowlist revisions are fresh, active, and unrevoked at admission. |
| Replay or request mutation | Idempotency identity binds canonical query digest plus all authority revisions/digests; exact replay is identifiable, changed replay is denied. |
| Audit outage | A redacted canonical decision must be durably accepted before an allowed result can be returned; audit failure denies admission. |
| Secret disclosure | Decisions contain IDs, revisions, bounded reason enums, timestamps, and digests only—never native query text, rows, credentials, handles, or vendor errors. |
| Timeout/cancellation | No allowed decision is published after context cancellation or deadline; retry starts from immutable inputs and fresh authority. |

## Contract composition

CYB-85 owns query syntax-neutral records and canonical identity. CYB-84 owns
security admission only. It does not parse a vendor language, execute a query,
relax a limit, fetch a credential, or infer approval. Vendor-specific read-only
validators remain downstream connector responsibilities, and both admissions
must succeed before execution.

The trusted authority snapshot binds:

- exact organization, tenant, case, actor, source, and sorted resource allowlist;
- actor/source/capability/allowlist revisions and observation time;
- authorization, policy, approval (when required), E-stop, and revocation state;
- maximum interval duration, future skew, and every typed query limit; and
- canonical decision/evidence digests used by COH-E10 provenance.

An approval is optional only when the trusted policy says it is not required.
Request data cannot make approval optional. If required, the approval must be
active, in scope, unexpired, unrevoked, and bound to the canonical query and
policy-decision digests.

## Decision and audit semantics

Outcomes are `allowed`, `denied`, `invalid`, or `unavailable`, with closed
bounded reason codes. The decision digest covers the canonical redacted record
with its digest field empty. Both allowed and denied attempts are submitted to
the audit sink. An unavailable audit sink changes any otherwise allowed result
to `unavailable/audit_unavailable` and returns no admission.

An exact replay may return `replayed: true` only after current authority,
revocation, E-stop, freshness, and audit checks run again. A stored prior allow
is never authority for a later execution.

## Compatibility, recovery, and rollback

Unknown versions, fields, revisions, reason values, or authority states deny.
Changing time meaning, allowed skew, limit meaning, approval semantics, replay
identity, canonicalization, or authority bindings is security-sensitive and
requires a new major contract plus adversarial migration evidence. Recovery
re-evaluates the immutable query under fresh authority. Rollback restores the
prior control, schema, and policy together and does not relabel or rewrite
existing decisions or query evidence.
