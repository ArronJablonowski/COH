# Security Onion Connect and structured OQL contract v1

This contract publishes COH-E13-04's deliberately narrow Security Onion 3.x
query boundary. Deployment configuration is secret-free. A credential broker
resolves the dedicated API client reference at call time; the client must have
exactly `events/read`. Each typed operation performs a fresh OAuth2
client-credentials exchange and discards temporary secret, token, and vendor
response buffers after use.

The complete network surface is `POST /oauth2/token`, qualified
`GET /connect/info/`, and qualified `GET /connect/events/`. There is no generic
HTTP method. Case, detection, grid, configuration, client administration, job,
packet/PCAP, stream, user, and mutation routes remain unreachable even when
present in the live OpenAPI or available to an overprivileged principal.

Caller query text is the JSON document described by
`security-onion-oql.schema.json`, never raw OQL. COH validates typed logical
fields and rebuilds Lucene predicates, mandatory tenant/source filters, the UTC
range, configured projection or grouping, stable sort, and all limits. Raw
Lucene, pipes, scripts, wildcards, caller projection/sort, and unknown members
fail closed.

## Completeness and compatibility

The Connect events API documents neither a stable continuation cursor nor a
guarantee that the requested limit is below the backend maximum. COH reports a
cap-filled response as partial and truncated. Event results are complete only
when the response is error-free, exactly bound to the plan, below every cap,
and `totalEvents` equals the released row count. Aggregations with input events
but no provable complete bucket count are partial with
`securityonion_completion_unconfirmed`; they are never silently complete.

V1 qualifies the current live OpenAPI digest and exact operation security,
parameters, media type, and root type before use. Additive event-envelope or
aggregation fields are not accepted automatically; they require a new fixture
and compatibility review. A path, method, auth, parameter, required response,
projection, grammar, or completeness change requires new conformance evidence;
an incompatible public configuration or plan shape requires a new major
contract.

## Rollout, migration, recovery, and rollback

Rollout starts disabled. Pin the manager CA and SPKI, register a dedicated API
client reference, capture and sanitize the live OpenAPI/response family, run
`scripts/verify_security_onion.sh`, and enable one bounded canary case. Monitor
typed denials, backend-cap partials, token outages, latency, and local capacity;
never log Authorization headers, native JSON/OQL, literals, rows, or bodies.

Credential rotation changes the broker version behind the same reference.
Manager certificate, OpenAPI, source mapping, field mapping, projection, or
limit changes invalidate capability/schema snapshots and require
requalification. Retry a pre-response outage with a fresh token and current
authority. After ambiguous transport or lost local job state, create a fresh
attempt; do not invent a continuation or reuse stale native state.

Rollback disables new probes/validation, revokes credential leases and the API
client, expires process-local capability/schema/job state, and preserves
durable encrypted/redacted evidence. Re-enable only after a fresh qualification
and canary. Independent security architecture review remains required before
the first production release.
