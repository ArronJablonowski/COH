# COH-E14-03 Splunk search-job lifecycle design

| Field | Decision |
|---|---|
| Issue | CYB-96 / COH-E14-03 |
| Requirements | FR-051, FR-054 |
| Dependencies | CYB-16, CYB-95, CYB-99 |
| Supported deployment | Qualified self-managed Splunk Enterprise 9.4 and 10.0 search heads |
| Execution mode | Bounded asynchronous historical jobs only |
| Security decision | COH owns every SID and exposes only authority-bound opaque handles |

## Authoritative vendor behavior

Splunk creates an asynchronous job with `POST /services/search/jobs` when
`exec_mode=normal`. The response returns a search identifier (SID). Job status
is available from `GET /services/search/jobs/{sid}`, finalized rows from
`GET /services/search/jobs/{sid}/results`, and cancellation from
`POST /services/search/jobs/{sid}/control` with `action=cancel`.

The documented states are `QUEUED`, `PARSING`, `RUNNING`, `FINALIZING`, `DONE`,
`PAUSE`, `INTERNAL_CANCEL`, `USER_CANCEL`, `BAD_INPUT_CANCEL`, `QUIT`, and
`FAILED`. Splunk also exposes preview and streaming result surfaces before a job
is done. COH never calls those surfaces and never publishes rows until the
vendor reports `DONE`.

Splunk recommends explicit time modifiers for REST searches. COH supplies the
CYB-99 admitted UTC bounds as `earliest_time` and `latest_time`, forces
`exec_mode=normal`, disables previews, requests no status buckets, and supplies
explicit `max_count`, `max_time`, `auto_cancel`, and `timeout` ceilings derived
from the admitted query limits and adapter hard limits. Real-time search modes,
oneshot/export, saved-search dispatch, custom job properties, user-selected
priority, and caller-selected namespaces are not supported.

Primary references:

- <https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions>
- <https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/10.4/rest-api-tutorials/creating-searches-using-the-rest-api>
- <https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/search-endpoints/search-endpoint-descriptions>

## Typed operation allowlist

The client exposes exactly four lifecycle operations in addition to the
completed discovery and parser operations:

| Operation | Method and path | Fixed behavior |
|---|---|---|
| `splunk.search.create` | `POST /services/search/jobs` | Canonical CYB-99 SPL, normal asynchronous mode, explicit historical bounds and ceilings |
| `splunk.search.status` | `GET /services/search/jobs/{sid}` | One strict bounded job record; no list or search filter |
| `splunk.search.results` | `GET /services/search/jobs/{sid}/results` | JSON, explicit count and offset, only after locally observed `DONE` |
| `splunk.search.cancel` | `POST /services/search/jobs/{sid}/control` | Exactly `action=cancel` |

There is no generic HTTP method, path, query, form, namespace, action, or SID
parameter at the connector boundary. Each call uses a fresh credential lease
bound to the exact operation, source, resources, actor, authority, request
digest, and pinned TLS identity. Redirects remain denied.

## Dispatch admission and SID ownership

`Execute` first applies the common query/validation admission rule, then loads
the exact retained CYB-99 plan. Query digest, accepted validation digest, plan
digest, capability and schema digests, source/resource scope, actor and all
authority digests, UTC range, and limits must still match and be unexpired and
unrevoked. An accepted validation is not renewable authority.

The adapter submits only the retained canonical SPL. It validates a returned
SID for bounded length, safe ASCII, and a single JSON value, then stores it in
adapter-private state. The public `query_job` handle contains a deterministic
COH identifier and an opaque digest over the query, plan, attempt, SID digest,
dispatch receipt, issue time, and expiry. It never contains the SID itself.

Identical concurrent execution requests coalesce behind one dispatch. Exact
replay returns the same execution record. A changed validation, query,
authority, attempt, or handle is a conflict and cannot address the stored SID.
Unknown, expired, removed, or stolen handles do not trigger vendor calls.

## State machine and polling

The allowed local state progression is:

```text
created -> queued/parsing/running -> finalizing -> done
                              \-> failed/canceled/quit
```

Vendor states are normalized as follows:

| Vendor state | COH result |
|---|---|
| `QUEUED`, `PARSING`, `RUNNING`, `FINALIZING` | `running`, no page |
| `DONE` | terminal complete; first finalized page may be fetched |
| `INTERNAL_CANCEL`, `USER_CANCEL`, `BAD_INPUT_CANCEL`, `QUIT` | terminal incomplete with a stable reason |
| `FAILED` | terminal failed with a stable reason |
| `PAUSE` or an unknown state | unsupported/denied; no rows |

State may stay equal or advance. Regression from a later observed state,
terminal-state substitution, malformed counters, or changed SID identity is
semantic drift and fails closed. Polls faster than the configured minimum
cadence are served from the last validated local record or denied without a
vendor call. Concurrent identical polls coalesce, and replay returns the same
validated result.

Every vendor access checks current deadline and retained authority. Timeout or
deadline exhaustion starts bounded cancellation. Outage leaves the last
validated nonterminal state intact but releases no rows; recovery requires the
same live handle and authority and resumes with a fresh status call.

## Finalized paging and completeness

Only a locally observed `DONE` job may call `/results`. The first poll can
return page one; later pages use adapter-private cursor state. A page handle
binds the job handle, query and attempt, authority, next offset, page number,
cumulative counters, result-chain digest, and expiry. Offset, count, or SID is
never caller controlled.

Splunk's `isFinalized` property means the job was explicitly finalized, not
that a naturally completed result set is ready. COH therefore requires `DONE`
and rejects `isFinalized=true` as potentially partial.

Each page is strict bounded JSON. Field names must be unique, admitted by the
validated projection, and within configured limits. Rows, nesting, scalar
types, encoded bytes, and response bytes are bounded before publication.
Unknown structures, duplicate keys, messages indicating loss, invalid fields,
or a count exceeding the requested page size deny the page.

Cumulative returned rows, bytes, pages, duration, and cost may never exceed the
query limits or adapter hard limits. The page size is the minimum of remaining
row allowance, configured page size, and vendor count ceiling. A short page or
an offset reaching the vendor-confirmed result count ends paging. A caller
cannot increase limits through `NextPage`.

Completeness is `complete` only when `DONE` is vendor confirmed, all expected
rows have been retrieved within bounds, the result count is stable, and no
vendor warning or truncation indicator exists. Cancellation, failure, unstable
counts, vendor truncation, or exhausted COH bounds is explicitly partial or
truncated with reason codes; hidden partial success is forbidden.

Statistics bind validated vendor `scanCount`, `eventCount`, `resultCount`, and
`runDuration` to cumulative COH rows, bytes, and pages. Counters must be
nonnegative, monotonic, internally consistent, and within integer bounds.
Statistics and result/provenance digests contain no SID, native text, row data,
credential, URL, or vendor body.

## Cancellation, revocation, and uncertainty

Caller cancellation, deadline expiry, workflow timeout, policy revocation, and
E-stop all converge on the same typed cancel operation. Before dispatch, they
remove retained validation without a vendor call. After dispatch, COH sends one
bound `action=cancel` request and then confirms a documented terminal state
within a bounded cancellation window.

A confirmed terminal cancel returns `confirmed`. A missing job that was
previously terminal may be confirmed from retained evidence. Network failure,
malformed response, or inability to observe a terminal state returns
`uncertain`; it never reports success. Repeated cancellation is idempotent and
cannot switch attempts or SIDs. Revocation prevents future poll/page release
even when cancellation confirmation is uncertain.

## Hard limits and compatibility

All dispatch ceilings are derived downward from `queryconnector.Limits` and
the qualified adapter configuration. V1 additionally fixes one active vendor
job per attempt, a bounded adapter record count, a nonzero minimum poll
interval, a bounded cancellation confirmation window, and a maximum page size
no larger than the remaining row/byte budget. Zero or overflowing bounds are
invalid; vendor defaults never widen a COH limit.

Sanitized deterministic fixtures cover qualified Splunk 9.4 and 10.0 response
shapes. A deployment still requires the CYB-95 live qualification gate.
Additional job states, endpoints, fields, modes, result formats, namespaces,
or wider bounds require a reviewed contract revision and new adversarial
evidence.

## Test and release trajectory

Task 2 publishes versioned lifecycle contracts and fixtures. Task 3 implements
the four typed transport calls. Tasks 4 through 6 implement dispatch, private
SID ownership, polling, finalized paging, completeness, and statistics. Task 7
adds cancellation/revocation and adversarial coverage. Task 8 publishes the
conformance packet and runs the clean baseline.

Rollback disables new lifecycle admission, revokes connector credential
leases, attempts bounded cancellation of retained nonterminal jobs, blocks all
further row release, and preserves redacted receipts and encrypted evidence.
Discovery and parser validation may remain available independently.
