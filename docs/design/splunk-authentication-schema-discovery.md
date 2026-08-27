# Splunk authentication and schema discovery

| Field | Value |
|---|---|
| Issue | COH-E14-01 / CYB-95 |
| Parent | COH-E14 / CYB-21 |
| Requirements | FR-045, FR-046, SEC-013 |
| Decision | A typed, Enterprise-only v1 discovery adapter with broker-owned token leases, pinned splunkd identity, bounded one-shot inventory, and operator-declared field types intersected with live registered fields |

## Vendor and authentication contract

Splunk Enterprise supports direct REST API access with authentication tokens.
COH accepts only a broker reference to an operator-provisioned, short-lived or
revocable search token; it does not call `auth/login`, accept a username or
password, create HTTP auth tokens, or manage users or roles. Each request uses a
fresh single-use credential lease. The token exists only inside the lease
callback and HTTP header construction and is destroyed before the typed call
returns.

The v1 transport exposes exactly four GET operations:

1. `/services/server/info?output_mode=json&count=1` binds product type, version,
   build, server roles, and the configured deployment identity.
2. `/services/authentication/current-context?output_mode=json&count=1` proves
   the authenticated principal's assigned capabilities. The decoder projects
   only the capability list and discards identity/profile/password-shaped
   properties; no response body enters evidence.
3. `/services/data/indexes?output_mode=json&count={max+1}&offset=0&summarize=true`
   inventories candidate Enterprise indexes. The decoder projects only name,
   disabled state, and datatype.
4. `/servicesNS/nobody/search/search/fields?output_mode=json&count={max+1}&offset=0`
   inventories registered field configuration in the fixed system-owned search
   app namespace. The decoder projects only exact field names and indexed-state
   metadata.

There is no generic HTTP method, path, namespace, parameter, body, header, or
Splunk SDK request. Although several vendor resources support POST or DELETE,
the adapter type system has no mutation method. It also cannot reach searches,
saved searches, lookup/config endpoints, token management, role management,
index control/reload, cluster control, ingestion, apps, deployment management,
or internal/admin endpoints.

Authoritative Splunk references:

- [REST API authentication and authorization](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-user-manual/10.2/rest-api-user-manual/basic-concepts-about-the-splunk-platform-rest-api)
- [`server/info`](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.2/introspection-endpoints/introspection-endpoint-descriptions)
- [`authentication/current-context`](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.0/access-endpoints/access-endpoint-descriptions)
- [`data/indexes`](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.4/introspection-endpoints/introspection-endpoint-descriptions)
- [`search/fields`](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.4/knowledge-endpoints/knowledge-endpoint-descriptions)

## Compatibility decision

The initial implementation targets self-managed Splunk Enterprise minor
families only when their exact sanitized fixture family is pinned in admitted
configuration. The first qualification candidates are Enterprise 9.4.x and
10.4.x on a search head or single-instance search tier. Unknown product types,
major versions, unqualified minors, snapshots/development builds, forwarder-only
roles, and indexer endpoints not admitted as a search tier fail closed.

Splunk documents `data/indexes` as Enterprise-only. Splunk Cloud is therefore
explicitly unsupported in v1 rather than relying on administrator-only APIs or
treating operator configuration as live discovery. Cloud support requires a
separate reviewed inventory contract and recorded fixture for a Cloud-supported
read-only surface.

## Trust and deployment boundaries

Admitted configuration binds one source ID to a canonical root HTTPS origin,
expected deployment ID, product type, server role profile, exact qualified
minor family, build policy, adapter version, credential reference/class,
minimum assigned capabilities, transport identity digest, resource allowlist,
logical field declarations, and finite request/response/index/field/page/time
limits. It rejects plaintext HTTP, userinfo, fragments, non-root base paths,
redirects, ambient proxies, dynamic hosts, caller namespaces, control
characters, percent-encoded path substitution, and unbounded limits.

TLS requires 1.3, normal hostname/chain validation, configured roots, and an
exact peer certificate identity digest before token release. Every credential
lease binds organization, tenant, case, source, actor, authority/policy/audit
digests, typed operation, exact target set, audience, and TLS identity. Receipts
contain only request, response, lease-decision, and transport digests.

The role must have only the search/index visibility needed for admitted
resources. Qualification denies administrative or mutation capabilities such
as `admin_all_objects`, authentication/role changes, index editing, ingestion,
deployment control, app installation, and script execution even when the four
GET calls would otherwise succeed. A changed capability set produces a new
source identity and requires requalification.

## Index and field discovery

Configured resource IDs map one-to-one to exact lowercase Splunk index names.
V1 rejects wildcard, federated, internal/system, disabled, metrics, remote, or
unexpected indexes unless a later reviewed resource type explicitly supports
them. The live index inventory is intersected with, and must exactly account
for, the requested subset of the operator allowlist; it can narrow but never
widen caller scope. Unexpected vendor entries are ignored only after their
bounded names are proven outside the allowlist and never become schema output.

Vendor inventory uses one request with `count=maximum+1`, `offset=0`, and an
exact response byte limit. A paging total, entry count, or `next` link beyond
the configured maximum denies discovery. This avoids asserting a stable
snapshot across independently mutable vendor pages. Paging exposed through the
common query SPI occurs only after the full normalized schema is immutable in
adapter-owned, expiring state.

Splunk's `search/fields` endpoint describes registered field configuration; it
does not prove per-index observed types. COH therefore never infers a logical
type from it. Operators declare exact vendor field name, logical schema name,
type, and nullability in reviewed configuration. Discovery intersects those
declarations with the live registered-field set and emits only exact matches.
Missing declarations, duplicate aliases, case collisions, unsafe names,
unregistered fields, or incompatible indexed metadata fail closed. Runtime
search/result validation in CYB-96 must rebind actual result fields and values
to this schema before releasing rows.

Normalized entries are sorted by logical resource and field name. The schema
digest binds admitted configuration, source identity, exact capability set,
live index inventory, registered-field inventory, projection decisions, typed
entries, and all redacted receipts. Opaque common-SPI cursors contain no token,
SID, endpoint, namespace, or vendor paging material and expire with the
capability snapshot.

## Capability and partiality

`Probe` can advertise read-only and schema-discovery support after all identity,
capability, scope, TLS, and receipt checks pass. Search validation, polling,
paging, cancellation, and statistics are not advertised by this leaf until the
CYB-99 parser and CYB-96 job lifecycle are qualified.

Qualification and schema discovery are atomic. Authentication denial,
forbidden capability, identity/version/build/role drift, missing allowlisted
index or field, response warning/message, pagination ambiguity, malformed or
oversized JSON, timeout, cancellation, or audit/receipt failure returns a
bounded denial, unsupported, canceled, or unavailable error. It never emits a
partial capability or partial schema and never relabels a prior cache entry as
current.

## Recovery, rollout, and rollback

Retry after an outage starts again at server identity with fresh authority and
a new credential lease. An exact concurrent request may coalesce only at the
existing schema-cache boundary after capability admission; transport calls do
not share credentials or mutable response buffers. A changed token capability,
TLS peer, version/build, server role, index set, field registration, source
configuration, or allowlist produces a new digest and cache key.

Rollout starts disabled and requires a dedicated scoped token, pinned splunkd
trust, a passing exact-version fixture/conformance suite, public contract,
current bounds admission, and a bounded canary. Rollback disables the source,
revokes the token/leases, expires adapter cursor and cache state, and preserves
existing signed evidence. It never mutates Splunk, deletes cached history, or
reuses stale qualification.

## Threat model conclusions

The primary threats are credential disclosure, endpoint/path substitution,
overprivileged-token confusion, capability drift, namespace widening, mutable
vendor paging, hidden Cloud/Enterprise differences, index/system-field leakage,
type invention, response-body leakage, and stale-cache promotion. The frozen
controls are broker-only ephemeral token access, authenticated identity before
release, four typed GETs, Enterprise-only qualification, fixed namespace,
bounded one-shot inventories, allowlist intersection, operator-declared types,
strict projection, digest-only receipts, immutable normalized schema, and
fail-closed recovery.
