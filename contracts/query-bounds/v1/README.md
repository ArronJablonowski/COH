# Mandatory UTC query-bounds contract v1

| Field | Value |
|---|---|
| Issue | COH-E12-02 / CYB-84 |
| Requirements | FR-046, FR-047, FR-048, SEC-013 |
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Decision digest | `COH-QUERY-BOUND-DECISION-V1\0` + canonical bytes, SHA-256 |

This security control admits only immutable CYB-85 queries that match fresh
trusted actor, tenant, case, source, resource-allowlist, capability,
authorization, policy, approval, audit, E-stop, and revocation state. A closed
nanosecond UTC `[start,end)` range and every nonzero typed limit are mandatory.

The decision is deliberately redacted. It contains stable IDs, revisions,
timestamps, reason enums, and domain-separated digests but no native query,
result row, credential, secret, vendor handle/error, URL, or header. Both allow
and deny decisions must be durably accepted by audit before the method returns;
audit failure cannot produce an admission.

The canonical allowed fixture proves byte and digest stability. The denial
corpus inventories the adversarial reasons exercised by the Go suite. See
`docs/design/mandatory-utc-query-bounds.md` for the threat model, authority
ownership, replay, migration, recovery, and rollback rules.
