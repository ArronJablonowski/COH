# Splunk discovery contract v1

This contract binds a COH source to one self-managed Splunk Enterprise search
head. It permits only bounded, read-only identity, current-context, index
inventory, and registered-field discovery. Splunk Cloud, generic REST
passthrough, authentication endpoints, redirects, ambient proxies, wildcard or
internal indexes, and privileged capabilities are outside v1.

Operators provision an authentication token out of band and register only its
credential-broker reference. COH releases a scoped, single-use lease after the
TLS peer and configured server GUID match. Public configuration, qualification,
capability, schema, denial, and error evidence never contains the token, a
Splunk session key, native response text, result rows, or vendor bodies.

Registered Splunk fields do not provide reliable per-index logical types.
Operators therefore declare the logical type and resource membership; live
discovery may only intersect that declaration with the bounded registered-field
inventory. Deployment identity, credential authority, capability set, config,
or qualified minor-version changes require requalification.

## Compatibility

V1 supports self-managed Splunk Enterprise 9.4 and 10.0 search heads through
the documented management REST API. It is qualified only for authentication
tokens supplied by COH's credential broker. Splunk Cloud is unsupported because
`data/indexes` is not a qualified Cloud inventory surface. Username/password,
session-key login, token creation, app endpoints, search jobs, generic REST,
and every mutation are outside this contract. Search execution is delivered by
the separate parser-policy and search-job lifecycle leaves.

## Rollout and migration

Start disabled. Validate this fixture family, confirm the expected server GUID,
search-head role, qualified minor, trust roots, and SPKI out of band, provision
a dedicated token whose role has `search` but none of the denied capabilities,
then run `scripts/verify_splunk_discovery.sh`. Enable one test source and watch
bounded denial reason counts before expanding. A GUID, role, version, TLS,
credential authority, resource, field, or type change requires a new
qualification and invalidates capability/schema-cache identities.

For credential rotation, register the new secret version with the broker and
let new single-use leases resolve it; no token is stored in adapter state.
Transient outages are retried by issuing a new authorized call. Truncated or
ambiguous inventories, identity drift, or lost process-local cursor state are
terminal for that attempt and require a fresh probe/discovery.

## Rollback

Disable the source, revoke outstanding leases, expire capability and schema
cache entries, and discard opaque cursors. Rollback does not mutate Splunk or
delete COH evidence. Re-enable only after a fresh TLS and deployment
qualification succeeds under current authority.
