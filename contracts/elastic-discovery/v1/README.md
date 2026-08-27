# Elastic discovery contract v1

`elastic-discovery-config.schema.json` is the public, secret-free deployment
contract for COH-E13-01. It binds one logical COH source to one HTTPS Elastic
deployment, expected cluster/build identity, qualified versions, a pinned TLS
SPKI digest, logical-resource-to-index expressions, explicit vendor fields,
and finite capability/schema limits.

The configuration contains no API key. Operators provision an Elastic API key
with cluster `monitor` and index `view_index_metadata` plus `read` for only the
configured targets, then register its reference with COH's credential broker.
Each request consumes a new single-use lease. Additional Elastic roles are
unioned rather than subtractive, so operators must ensure the principal has no
write or broader index role.

The adapter calls only `GET /`, `GET /_resolve/index/{name}`, and
`POST /{index}/_field_caps`. It denies ambient proxies, redirects, non-TLS
origins, remote-cluster syntax, hidden/restricted targets, broad wildcards,
runtime mappings, scripts, arbitrary filters, and generic request passthrough.

## Operations

Rollout starts disabled. Validate the configuration and fixture family, verify
the SPKI and cluster UUID out of band, provision the credential reference, run
`scripts/verify_elastic_discovery.sh`, then enable the source for a test case.
Monitor bounded denial reason counts; authentication messages and vendor bodies
must never be logged.

Rotation registers a new secret version and lets new leases resolve it. A TLS,
cluster, build-flavor, target-membership, or qualified-version change requires
a fresh capability snapshot and schema-cache key. Unknown majors and unlisted
minor families remain disabled until their recorded fixtures pass conformance.

Rollback disables new probes, revokes outstanding connector leases, expires
opaque schema cursors, and invalidates the source capability/schema cache. It
does not mutate Elastic or delete COH evidence. Re-enable only after a fresh
identity probe under current authority.

## Compatibility

V1 supports qualified self-managed Elastic 8.x and 9.x minor families. Elastic
Serverless is a separate deployment profile because its reported version is
compatibility metadata. Adding endpoints, authentication schemes, target kinds,
field wildcarding, type mappings, or relaxed response semantics requires a new
review and adversarial fixture evidence; incompatible identity or cursor rules
require a new major contract.
