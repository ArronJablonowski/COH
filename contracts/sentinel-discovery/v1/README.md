# Sentinel metadata discovery contract v1

This contract binds one COH source to one Microsoft Sentinel backing Log
Analytics workspace in the Azure public cloud. It permits only a bounded
authenticated metadata GET at the exact `v1` data-plane endpoint. ARM
management, ingestion, query, batch, cross-workspace/resource scope, redirects,
ambient credentials, API keys, generic HTTP, and every mutation are outside v1.

Operators register only a credential-broker reference for a dedicated
read-only Entra identity with the exact
`https://api.loganalytics.io/.default` audience. Configuration binds the tenant,
workspace UUID, returned ARM resource identity, region, endpoint, TLS identity,
logical tables/fields, and limits. Live metadata may only confirm or narrow the
reviewed declaration.

V1 supports the Azure public-cloud endpoint and current `v1` metadata shape.
Sovereign clouds, private/custom endpoints, Application Insights, dynamic
columns, alternate API versions, and additional metadata authority require a
reviewed contract revision and new recordings.

Rollout begins disabled and requires a fresh credential, TLS, workspace, table,
and column qualification. Rotation uses a new broker secret version and fresh
leases. Rollback disables the source, revokes leases and policy, expires all
process-local snapshots/cursors, restores the prior reviewed binary/config, and
preserves redacted evidence. No database migration or vendor mutation occurs.
