# Model-surface provenance v1 compatibility matrix

| Scenario | Required behavior |
|---|---|
| Exact replay, same versions and sources | Re-resolve all sources and artifacts; require byte-identical projection, binding, and surface digests |
| Changed source revision, bytes, digest, order, or scope | Deny before provider dispatch |
| Unknown event type or version | Deny; no generic fallback projection |
| Log-only event supplied as visible input | Deny |
| Live coordination signal supplied as history | Deny |
| Mutable artifact or unverifiable durable record | Deny |
| Untrusted content presented as an instruction or tool schema | Deny; it remains data-only |
| Fork | Create a new projection/request identity; retain exact ancestor source IDs and artifact digests |
| Resume after restart | Load durable transition, re-resolve the projection, and continue only if all digests match |
| Cancellation or timeout before dispatch | Record an explicit terminal outcome and invoke no provider |
| Cancellation, timeout, or interruption during streaming | Retain ordered chunks and source lineage; record a non-success terminal outcome |
| Empty provider result | Record explicit `empty` with an assembled digest; do not infer success from silence |
| Provider fallback | New attempt and binding; same verified projection/surface; never merge streams across attempts |
| Compaction | Replacement exactly covers the removed sources and preserves all leaf evidence/time/order/result/completeness/uncertainty metadata |
| Nested compaction | Expand to original leaf coverage before comparison or replay |
| v1 reader, future contract/projection/event version | Deny as unsupported |
| Future reader, v1 record | Accept only through an explicit tested compatibility path; never reinterpret v1 fields |
| Cross-tenant, cross-case, cross-task, or cross-run source | Deny even when the content digest is otherwise valid |
| Audit unavailable or authorization/policy/approval binding changed | Deny dispatch; provenance is not authority |
| Provider returns mismatched request/attempt/binding lineage | Deny response assembly and retain an explicit failed or uncertain terminal record |

All supported native workstation, native server, Compose, connected,
restricted-connected, air-gap, Web, CLI, API, headless, and test profiles use the
same v1 projection semantics and canonical digests.
