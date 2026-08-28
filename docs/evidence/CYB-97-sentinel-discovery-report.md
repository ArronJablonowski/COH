# CYB-97 Sentinel authentication and metadata discovery report

| Field | Value |
|---|---|
| Issue | COH-E14-04 / CYB-97 |
| Parent | COH-E14 / CYB-21 |
| Requirements | FR-045, FR-046, SEC-013 |
| Implementation commits | `2f9d953` through `8633fa0` |
| Focused verification | `scripts/verify_sentinel_discovery.sh` |
| Full CI evidence | Recorded in the CYB-97 closure comment and attached quality report |
| Residual production condition | Independent security architecture review before first production release |

## Delivered boundary

COH now has a public-cloud Microsoft Sentinel discovery adapter for the Azure
Monitor Logs data plane. Its vendor client exposes exactly one operation:

`GET https://api.loganalytics.azure.com/v1/workspaces/{workspace-id}/metadata`

The host, `v1` API, workspace UUID, OAuth audience, tenant, method, path,
headers, TLS identity, targets, authority, and limits are configuration or
policy bound. No caller can supply a generic URL, method, path, query, body, or
bearer token. ARM management, Microsoft Graph, ingestion, query/batch,
cross-workspace, saved-query/function, sovereign/private/custom endpoints, and
all mutation surfaces are absent from the client type.

The broker lends short-lived token bytes only after TLS 1.3 chain, hostname,
and configured peer-identity verification. The authenticated connection is
rechecked. Ambient proxies and redirects are disabled. Responses are bounded,
duplicate-key checked, closed-shape decoded, and converted to digest-only
receipts; vendor bodies and bearer material never enter errors or evidence.

Authoritative vendor references:

- [Azure Monitor Logs API access and authentication](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api)
- [Azure Monitor Logs metadata GET](https://learn.microsoft.com/en-us/rest/api/logsquery/metadata/get?view=rest-logsquery-v1)
- [Azure Monitor Logs query scope and permissions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/scope)
- [Azure Monitor Logs table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-table-overview)

## Qualification and schema behavior

Live qualification requires one exact workspace UUID, normalized ARM resource
ID, expected region, API version, complete bounded table inventory, configured
timespan columns, configured fields with explicit scalar compatibility, and a
valid authority-scoped credential/TLS receipt. The canonical qualification
binds configuration, metadata, receipts, observation time, and finite expiry.
Any identity, table, column, type, digest, receipt, or time drift fails closed.

`Probe` repeats the live check and publishes a capability bound to the exact
scope and authority. It advertises read-only, schema discovery, and the common
validation interface. Validation is deliberately fail-closed with
`sentinel_validator_unavailable` until CYB-98 qualifies the Kusto.Language
helper. Polling, result paging, cancellation, and statistics remain false and
their SPI methods return typed unsupported results without vendor access.

`DiscoverSchema` intersects live metadata with operator-declared logical
resources and fields. Unexpected vendor tables and columns cannot widen scope.
Public pages contain only logical names and common types. Snapshots are
immutable and bounded; exact concurrent requests coalesce, exact replay is
deterministic, and opaque expiring cursors bind capability, scope, authority,
request, schema, provenance, offset, and expiry.

## Compatibility and conformance

| Deployment | Endpoint/audience | Outcome |
|---|---|---|
| Azure public Log Analytics workspace | `api.loganalytics.azure.com` / `api.loganalytics.io/.default` | Supported after live qualification |
| Azure Government, China, private/custom endpoint | Different trust boundary | Unsupported; reviewed contract revision required |
| ARM management, Graph, ingestion, query/batch, cross-workspace | Not represented by a typed operation | Unreachable/denied |
| Unknown API, response shape, continuation, partial inventory, scalar type | No qualified recording | Denied/unsupported |

The recording is a sanitized deterministic representation of Microsoft's
documented `v1` metadata shape, not a claim of access to a live tenant. A real
deployment still requires its dedicated least-privilege identity, exact
workspace role, broker registration, trust pins, and fresh live qualification.

## Adversarial, recovery, and privacy evidence

Coverage includes malformed and duplicate JSON, unknown and continuation
fields, oversize metadata, alternate endpoint/audience/target/authority,
management-plane substitution, TLS substitution before token release, header
injection, redirects, invalid lease receipts, credential and vendor-body
redaction, workspace/resource/region/table/column/type/digest drift,
pre-cancellation, deadline, outage and fresh-lease recovery, qualification and
capability expiry, deterministic replay, cursor theft/tamper/staleness,
capability substitution, page bounds, and 16-way discovery coalescing under the
race detector.

The 14-case denial corpus is machine-linked to executable tests. Secret scans
cover the worktree, Git history, and evidence. Capability, schema, trace,
recordings, errors, and CI evidence contain no credential, bearer, tenant
secret, workspace URL, native KQL, result row, or vendor body. Partial metadata
never becomes a complete schema.

## Rollout, migration, recovery, and rollback

- Start disabled. Provision a dedicated identity with only the required
  workspace query/read permission, register its broker reference, configure
  exact trust pins, and require a fresh successful qualification and canary.
- No database migration is introduced. Existing capability/schema snapshots
  are historical evidence and are never upgraded in place; obtain new
  snapshots after any configuration, adapter, endpoint, API, identity, schema,
  trust, or policy change.
- An outage leaves prior immutable evidence unchanged but cannot relabel it
  current. Recovery performs a new TLS preflight and fresh credential lease; it
  never reuses a failed body, stale token, qualification, or cursor.
- Lost process-local capability, replay, or cursor state is unavailable and
  requires new qualification/discovery under current authority.
- Rollback disables the source, revokes credential leases and policy decisions,
  expires qualification/capability/schema/cursor state, restores the prior
  reviewed binary and configuration, and preserves only redacted evidence.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Allowlisted workspace credential scope, metadata, management denial, resource/API versions | Typed transport, qualification, recordings | Pass |
| Typed operations, capability/resource bounds, cancellation handling, redaction, explicit unsupported behavior | Capability snapshot, adapter SPI, hostile transport tests | Pass |
| Invalid input, denial, timeout/cancel, outage/recovery preserve provenance and policy | Denial corpus, adversarial trace, recovery tests | Pass |
| Success/failure automation and CI/race/architecture/secret/license/dependency/size gates | Focused verifier and clean full baseline attachment | Pass |
| Recorded fixture, capability, conformance report, redacted trace cross-reference COH-E14-04 and requirements | This checksummed packet | Pass |

No CYB-97 blocking finding remains. The approved non-blocking product-level
follow-up is unchanged: obtain an independent security architecture review
before the first production release.
