# Chain-of-custody v1 compatibility

| Input or state | Result | Recovery |
|---|---|---|
| Exact command at expected case revision and custody head | Append one immutable record and receipt | None |
| Exact idempotent replay | Reauthorize, verify both chains, repair audit if needed, return original receipt | None |
| Changed idempotency reuse | Deny before artifact resolution or append | Use a new key for a new command |
| Stale case revision or custody head | Conflict; append nothing | Reload state and obtain fresh authority |
| Unknown operation, phase, field, reason, or schema version | Reject before authority or storage | Upgrade through an explicit contract migration |
| Cross-tenant or cross-case artifact/manifest | Deny without disclosure or existence signal | Correct the exact case-scoped reference |
| Invalid artifact, manifest, receipt, record, head, or lineage | Integrity failure; stop affected writes | Restore from verified evidence; never synthesize a link |
| Missing, revoked, expired, or changed authority | Deny; append no successful custody link | Obtain a new exact decision if policy permits |
| Redaction with a missing/changed governing decision or a value placed in prior custody authorization | Reject; append no custody link | Bind the exact redaction decision in `governing_decision_digest` |
| Concurrent exact command | One record; all callers recover the same receipt | None |
| Concurrent different commands at one head | One winner, remaining commands conflict | Reload and reauthorize each loser |
| Storage failure before commit | No record, head movement, or receipt | Retry from the beginning |
| Lost response after commit | Exact receipt is recoverable | Replay the identical command |
| Audit append/checkpoint failure after custody commit | Withhold usable success | Exact replay repairs the same audit event |
| Missing/reordered/inserted/modified/truncated custody data | Independent verification fails | Restore a verified complete interval |
| Broken lineage or changed artifact bytes | Independent verification fails | Quarantine affected data; never rewrite history |
| Unknown newer contract | Read/append unsupported | Retain bytes and upgrade the reader |
