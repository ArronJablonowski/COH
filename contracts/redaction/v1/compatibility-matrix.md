# Governed redaction v1 compatibility matrix

| Input or stored state | V1 behavior | Required operator action |
|---|---|---|
| Exact V1 command, rule, approved plan, approval, source, case, and custody head | Evaluate and derive under fresh authority | Continue only through completed receipt |
| Unknown schema/contract version or additional field | Reject | Migrate with a reviewed explicit converter |
| Regex, script, semantic selector, prompt, callback, or caller replacement content | Reject | Author a signed bounded V1 rule and exact byte plan |
| Empty, unsorted, duplicate, overlapping, out-of-range, excessive, or digest-drifted span | Reject before publication | Replan from the verified immutable source |
| Rule/media/mode mismatch or unknown/revoked signing key | Reject | Install a trusted rule revision or choose supported media |
| Missing, expired, rejected, revoked, self, changed, or unrelated consumed approval | Reject | Obtain a fresh exact policy decision and approval |
| `granted` or terminal `consumed` proof from this exact idempotent intent use | Accept after proof verification and fresh authority | Continue/replay only the bound redaction |
| Stale actor, case revision, policy, revocation digest, or custody head | Reject/conflict | Reload, reevaluate, reapprove where needed, and retry with a new intent |
| Deterministic pass mismatch, invalid output format, or mapping drift | Reject and quarantine candidate | Investigate adapter/rule integrity; never bless the bytes manually |
| Exact replay after derived/mapping publication or custody commit | Reauthorize, verify durable evidence, repair audit, return original receipt | No duplicate or synthetic record |
| Changed idempotency reuse | Deny | Submit a new idempotency identity and approval-bound plan |
| Complete interval without valid audit/checkpoint coverage | No releasable success | Repair audit proof or restore verified state |
| Source overwrite, relabel, replacement, or deletion request | Unsupported and denied | Retain the immutable source under its original controls |
| Older binary encountering `redaction` metadata kind | Reject unknown kind | Disable writes; retain V1 reader for forward recovery |

The contract is forward-incompatible by default. A future version may add a
new signed rule profile or mapping form only with a new schema version, explicit
reader, migration evidence, adversarial corpus, and rollback procedure. It may
not reinterpret a V1 digest, span, approval, custody receipt, or source identity.
