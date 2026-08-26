# Approval lifecycle state machine v2

| Current | Operation | Next | Required invariant |
|---|---|---|---|
| absent | request | requested | Fresh requestor actor/principal, scope, fingerprint, manifest-derived tier, validity, and use authority |
| requested | grant | requested | Append one distinct eligible enrolled human actor/principal below the tier-derived threshold |
| requested | grant | granted | Appended distinct enrolled human actor/principal reaches the tier-derived threshold |
| requested | reject | rejected | No use and no grant-history mutation |
| requested | expire | expired | Broker time is at or after `valid_until` |
| requested | revoke | revoked | Fresh authorized actor and unchanged binding |
| granted | consume | granted | Atomically increment use count below its maximum |
| granted | consume | consumed | Atomically increment use count to its maximum |
| granted | expire | expired | Broker time is at or after `valid_until` |
| granted | revoke | revoked | Fresh authorized actor and unchanged binding |

`rejected`, `expired`, `consumed`, and `revoked` are terminal. An exact retry
uses the same bounded idempotency key and returns the original commit result.
Reusing that key with changed input conflicts. Every new transition requires
the immediately preceding record revision; a stale revision conflicts and
cannot authorize an action.

All immutable fingerprint, scope, requestor, validity, threshold, and usage
bindings must remain byte-for-byte equal across revisions. Grant history is
append-only; actor identities and stable human-principal identities are both
distinct. Neither the requestor actor nor the same requestor principal under a
different account can grant the request. Broker time and fresh identity,
enrollment, and fingerprint authorities—not caller assertions—control
eligibility, expiration, and consumption.

The threshold is derived only after fresh signed-manifest/fingerprint
verification. T4 always uses two and every other currently supported approval
tier uses one. No command has a caller-settable threshold. A T4 record remains
`requested` after its first grant. Consumption revalidates current active,
human, enrolled, exact-scope Approver authority for both stored actor/principal
pairs; unenrollment, role loss, actor revocation, identity aliasing, stale
revision, or a missing second authority denies.

Each successful revision and its redacted audit outbox reference commit in one
storage transaction. A denied or invalid attempt must also reach the mandatory
audit boundary before the caller receives a final denial; unavailable audit
fails closed.
