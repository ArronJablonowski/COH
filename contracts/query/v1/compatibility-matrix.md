# Query connector v1 compatibility matrix

| Input or change | v1 result |
|---|---|
| Exact schema/version, known fields, valid bindings and bounds | Accept |
| Member reordering or insignificant whitespace | Accept to identical canonical bytes and digest |
| Unknown or missing field, duplicate key, trailing value, invalid UTF-8 | Deny |
| Unknown schema or contract version | Deny; no downgrade or guessing |
| Missing scope, authority, capability, schema, time, or limit | Deny |
| Unsorted or duplicate set | Deny |
| Generic HTTP, credential, token, mutation, or passthrough field | Deny |
| Timeout or cancellation during validation | Publish nothing; retry from immutable input |
| Same query after recoverable interruption | Revalidate to the same canonical digest |
| New optional field | Requires mixed-reader proof; not silently compatible |
| Removed, renamed, retyped, or reinterpreted field | New major schema and lineage migration |
| Changed canonical or digest rules | New canonical profile and major schema |
| Changed opaque-handle meaning or exposed vendor value | Security-sensitive breaking change |

Migration creates a new record linked to the original digest. It never rewrites
query or result evidence. Rollback restores the prior reader, schema, and
adapter together; it never strips newer fields or relabels bytes as v1.
