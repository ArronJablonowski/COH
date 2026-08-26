# Approval lifecycle state machine v1

| Current | Operation | Next | Required invariant |
|---|---|---|---|
| absent | request | requested | Fresh requestor, scope, fingerprint, validity, and use authority |
| requested | grant | requested | Append one distinct eligible approver below the threshold |
| requested | grant | granted | Appended distinct grant reaches the required threshold |
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
append-only, approver identities are distinct, and the requestor cannot grant
their own request. Broker time and fresh identity/fingerprint authorities—not
caller assertions—control eligibility, expiration, and consumption.

Each successful revision and its redacted audit outbox reference commit in one
storage transaction. A denied or invalid attempt must also reach the mandatory
audit boundary before the caller receives a final denial; unavailable audit
fails closed.
