# Tamper-evident audit v1 compatibility

| Input or state | Result | Recovery |
|---|---|---|
| Exact v1 event and current tenant head | Append next immutable record | None |
| Exact idempotent replay | Return prior sequence and chain hash | None |
| Changed idempotency-key reuse | Conflict; append nothing | Use a new key for a new event |
| Missing, reordered, inserted, or modified record | Integrity failure | Restore verified backup; never synthesize history |
| Forked or stale expected head | Conflict; append nothing | Reload and retry the same event |
| UTC day rollover | Atomically checkpoint prior interval before usable success | Restore signer/store and retry |
| 10,000th record since checkpoint | Atomically append and checkpoint new head | Restore signer/store and retry |
| Missing, unknown, stale, or invalid signing key | Unavailable; no usable success | Restore exact admitted key authority |
| Revoked key used after revocation | Integrity failure | Investigate and re-establish trust from prior checkpoint |
| Audit/checkpoint store unavailable | Consequential action blocked | Restore store and retry from the beginning |
| Unknown contract or algorithm | Unsupported; append/verify nothing | Upgrade through an explicitly reviewed migration |
