# Sentinel authentication and metadata discovery

| Field | Value |
|---|---|
| Issue | COH-E14-04 / CYB-97 |
| Parent | COH-E14 / CYB-21 |
| Requirements | FR-045, FR-046, SEC-013 |
| Decision | A public-cloud Azure Monitor Logs data-plane-only v1 adapter with broker-owned OAuth leases, one exact allowlisted workspace per source, one typed metadata GET, and operator-declared logical schema intersected with live workspace metadata |

## Vendor and endpoint boundary

Microsoft Sentinel data is queried through its backing Azure Monitor Log
Analytics workspace. CYB-97 performs discovery only. The production transport
exposes one typed operation:

`GET https://api.loganalytics.azure.com/v1/workspaces/{workspace-id}/metadata`

The workspace ID is the exact configured primary workspace UUID. The API
version is exactly `v1`; the host, method, path segments, query, headers, and
workspace are not caller supplied. Redirects, ambient proxies, alternate
hosts, arbitrary paths, query strings, bodies, and generic HTTP methods are
unavailable.

The adapter has no type that can call `management.azure.com`, Microsoft Graph,
the Logs Ingestion API, data-collection endpoints, query/batch endpoints,
resource-centric or cross-workspace queries, saved-query/function execution,
workspace/table mutation, Sentinel management APIs, or any PUT, POST, PATCH,
or DELETE operation. ARM resource IDs returned by metadata are identity values
only and never become management URLs.

Authoritative Microsoft references:

- [Log Analytics API access and authentication](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api)
- [Log Analytics metadata GET](https://learn.microsoft.com/en-us/rest/api/logsquery/metadata/get?view=rest-logsquery-v1)
- [Log query scope and permissions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/scope)
- [Azure Monitor Logs table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-table-overview)

Microsoft documents `https://api.loganalytics.azure.com` as the public data
endpoint, `v1` as the current public API, and
`https://api.loganalytics.io/.default` as the OAuth scope. Workspace queries
require `Microsoft.OperationalInsights/workspaces/query/*/read`; a dedicated
custom role should contain only the read permissions needed by the admitted
workspace.

## Authentication and transport identity

Configuration contains a credential-broker reference, never a client secret,
certificate private key, refresh token, access token, API key, connection
string, or Azure CLI cache. The broker must acquire a short-lived Microsoft
Entra service-principal or workload-identity token for the exact tenant and
`https://api.loganalytics.io/.default` audience. API-key, basic, implicit,
interactive, device-code, managed ambient, and caller-provided bearer paths
are unsupported.

Each metadata call consumes one fresh broker lease bound to organization,
tenant, case, actor, policy and audit digests, source, exact workspace, typed
operation, audience, endpoint, and TLS identity. Token bytes exist only inside
the lease callback and Authorization header construction, are overwritten
before return, and never enter adapter state, errors, logs, fixtures, evidence,
or digests.

TLS requires 1.3, normal hostname and chain validation, configured roots, and
an exact peer certificate identity digest before credential release. The
authenticated connection is rechecked after the request. Redirects and proxy
environment variables are disabled. Request and response receipts contain
only request, response, lease-decision, and transport digests.

## Configuration and workspace qualification

One source binds one canonical public-cloud endpoint to one Entra tenant UUID,
one workspace UUID, one exact normalized ARM resource ID, expected region,
adapter/API versions, credential class/reference, OAuth audience, TLS roots and
identity, logical resource/table declarations, logical field declarations,
and finite response, inventory, schema-page, lifetime, and common query limits.

V1 rejects sovereign/private endpoints because their hosts and token audiences
require separate qualification. It also rejects userinfo, plaintext HTTP,
ports other than 443, fragments, non-root base paths, percent-encoded path
substitution, wildcard workspace/table/field identifiers, duplicate or
case-colliding aliases, system/control characters, zero limits, and unknown
configuration fields.

Qualification performs the typed metadata call and requires:

- one workspace object whose ID is the configured workspace UUID;
- the exact configured ARM resource ID and expected Azure region;
- a bounded nonempty table inventory with no continuation or partial marker;
- every configured table exactly once and related to the configured workspace;
- every configured column exactly once with its documented type;
- a nonempty exact timespan column for each admitted event table;
- a valid credential lease and transport receipt under current authority.

Unexpected tables and columns are ignored only after the entire response is
bounded and strictly decoded; they never widen configuration or caller scope.
Missing, duplicate, conflicting, truncated, ambiguous, or malformed metadata
is drift and fails closed. Functions, saved queries, applications, solutions,
categories, resource types, permissions, and tags cannot authorize schema or
execution and are discarded before evidence.

Qualification binds the workspace UUID/resource ID/region, `v1`, endpoint,
audience, configuration, normalized admitted table and column metadata, exact
receipts, observed time, and expiry into a self-verifying digest.

## Logical schema projection

Configured logical resources map one-to-one to exact KQL table names. Fields
map an exact vendor column to a logical name, common type, nullability, and
resource set. Live metadata may narrow these declarations but never create a
logical name, infer permissions, change a type, or add a table.

Supported v1 scalar mappings are explicit: vendor `string`, `guid`, and
`dynamic` require a reviewed logical representation; `datetime`, `int`,
`long`, `real`, `decimal`, `bool`, and `timespan` map only to compatible common
types. Dynamic columns are excluded by default and require a later reviewed
contract because their nested shape is not proven by table metadata. A type,
timespan-column, nullability, table, or alias change invalidates qualification.

Normalized schema entries are sorted by logical resource then logical field.
The schema digest binds qualification, capability, exact caller scope and
authority, admitted configuration, normalized metadata, receipts, and entries.
Common SPI paging occurs only over an immutable adapter-owned snapshot using an
opaque digest-bound cursor that expires with the capability.

## Capability, errors, and recovery

After live qualification, `Probe` advertises only read-only and schema
discovery. Validation remains false until the CYB-98 Kusto.Language helper is
qualified; polling, paging, cancellation, and statistics remain false until
the later Sentinel execution leaf. The adapter cannot claim partial
qualification or partial schema.

Invalid local input is rejected before a lease or network call. Authentication
or authorization denial, TLS/endpoint drift, workspace/resource/region drift,
metadata ambiguity, oversize input, timeout, cancellation, receipt failure, or
outage yields a stable bounded typed error and releases no schema. Error and
audit records expose no token, secret, tenant credential, bearer header,
workspace URL, vendor body, KQL, or result row.

Exact concurrent discovery may coalesce only after live capability admission
and only for the same scope, authority, resource set, capability digest, and
limits. An outage leaves prior immutable snapshots unchanged but cannot relabel
them current. Recovery repeats qualification with a fresh lease; it does not
reuse a failed response or stale token. Lost cursor state is unavailable and
requires a fresh discovery request.

## Compatibility, rollout, migration, and rollback

V1 supports the Azure public cloud Log Analytics data endpoint and `v1`
metadata shape represented by sanitized deterministic recordings. It does not
claim a server product build or Sentinel feature version. Azure Government,
China, private link/custom DNS, resource-centric scope, Application Insights,
cross-workspace metadata, beta/legacy API versions, or new metadata types need
a reviewed endpoint/audience contract and new recordings.

Start disabled. Provision the dedicated read-only identity and exact workspace
role out of band, register its broker reference, pin the endpoint trust,
validate the fixture family, and run a bounded canary. No database migration is
introduced; consumers obtain a new capability snapshot after any configuration
or adapter change.

Rollback disables the source, revokes credential leases and policy decisions,
expires qualification/capability/schema/cursor state, restores the prior
reviewed binary and configuration, and preserves redacted evidence. Because
CYB-97 is read-only discovery, there is no vendor-side compensation. Re-enable
only after fresh tenant, workspace, TLS, metadata, and authority qualification.

## Threat-model conclusion

The primary threats are bearer disclosure, confused tenant or audience,
workspace/ARM substitution, management-plane escape, alternate cloud/host
confusion, redirect/proxy credential release, metadata widening, saved
function/query confusion, dynamic-column type invention, response-body
leakage, hidden partial inventory, cursor theft, and stale-cache promotion. The
frozen controls are broker-only short-lived leases, pre-release TLS identity,
one exact data-plane GET, public-cloud endpoint/audience pinning, exact
workspace identity, bounded atomic metadata, allowlist intersection,
operator-declared logical types, immutable snapshots, opaque cursors,
digest-only receipts, and fail-closed recovery.
