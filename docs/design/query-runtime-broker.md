# Query runtime broker: paging, slicing, cancellation, and rates

| Field | Value |
|---|---|
| Issue | COH-E12-04 / CYB-87 |
| Requirements | FR-047, FR-048, FR-054, NFR-008 |
| Upstream contracts | COH-E12-01 connector SPI, COH-E12-02 bounds admission, COH-E12-03 schema cache |
| Authority boundary | COH-E05 policy, approvals, audit, E-stop |
| Evidence boundary | COH-E10 immutable provenance and custody |
| Decision | Every external call reserves rate, consumes a monotonic bounded budget, and publishes explicit completeness |

## Boundary and threat model

The runtime broker orchestrates already admitted, read-only connector work. It
does not parse or rewrite native query text, create authority, fetch credentials,
or expose a generic transport. Its inputs are immutable CYB-85 lifecycle records
and a verified allowed CYB-84 decision bound to the exact query digest.

| Threat or ambiguity | Fail-closed invariant |
|---|---|
| Limit widening after admission | Effective limits are the component-wise minimum of the admitted query, trusted runtime profile, and any current authoritative cap. No transition may increase them. |
| Vendor over-return | Cumulative rows, bytes, duration, pages, slices, and cost are checked before a page is released. An offending page is withheld, cancellation is attempted, and the outcome is explicit `partial/truncated`. |
| Hidden partial result | Broker completeness combines vendor status with broker cap/cancellation state. `complete` is possible only when the vendor confirms completion and every broker invariant holds. |
| Rate race or process fan-out | A narrow authoritative rate-reservation port performs atomic tenant/source/actor/mode reservation. An in-process counter is not production authority. |
| Page replay or substitution | Session identity binds organization, tenant, case, query, decision, execution, profile, limits, and prior transition digest. Exact page replay is idempotent; changed reuse of a page number or handle is conflict. |
| Cancellation race | One canonical cancellation intent is idempotent. Completion and cancellation reconcile from validated vendor records; uncertainty is retained and never relabeled complete. |
| Timeout or caller cancellation | The caller stops promptly. A short detached cancellation attempt may limit vendor work, but no late page is published to the canceled call. |
| Invalid cumulative statistics | Statistics must be monotonic, internally consistent, and bound to the exact query/attempt. Regression, overflow, or impossible completeness denies the transition. |
| Unsafe slicing | The broker never mutates an admitted query. It plans exact non-overlapping half-open intervals; every derived slice query must be independently validated and admitted before execution. |
| Excessive or empty slices | Slice count is positive, no greater than the effective cap, and cannot exceed the interval's nanosecond width. Slices cover the parent interval exactly with no gap or overlap. |
| Secret disclosure | State and errors retain IDs, counters, bounded reasons, times, and digests only—never native query text, rows in audit state, credentials, URLs, handles' opaque values, or raw vendor errors. |

## Runtime profiles and effective budgets

`interactive` and `export` are explicit trusted profiles, not request-chosen
permission levels. Each profile defines maximum rows, bytes, duration, pages,
slices, cost, and requests per minute. Export may be larger than interactive,
but both remain bounded by CYB-84-admitted query limits and current authority.

The broker records an immutable initial budget and monotonic cumulative usage.
Vendor statistics are v1 cumulative totals for one exact query attempt. Each
accepted transition must be greater than or equal to prior usage, while staying
within the initial budget. Integer overflow, counter regression, inconsistent
rows, or an elapsed broker duration beyond the cap fails closed.

## Paging and completeness

Every `Poll` and `NextPage` call first reserves one request from the exact
tenant/source/actor/profile rate key. Page numbers advance by one. Handles must
remain source-, attempt-, expiry-, and prior-transition-bound. A page becomes
caller-visible only after its record, cumulative statistics, completeness, and
provenance are validated and the next canonical broker transition is formed.

Broker outcomes are:

- `running`: no final result exists and another bounded operation is allowed;
- `complete`: vendor-confirmed completion with no broker or vendor partial flag;
- `partial`: some bounded result was released but collection is incomplete;
- `truncated`: a declared cap withheld further results or the vendor truncated;
- `canceled`: vendor cancellation is confirmed;
- `uncertain`: cancellation or vendor completion cannot be confirmed; and
- `failed`: a terminal validated vendor failure with no complete claim.

Reason codes are closed and redacted. Vendor `unknown`, partial, or truncated
status can only preserve or reduce completeness; the broker cannot upgrade it.

## Safe slice planning

Slice planning accepts the parent canonical query identity, its exact UTC
half-open interval, an effective slice cap, and a requested count. It emits only
descriptors containing parent digest, index/count, exact `[start,end)` bounds,
and a canonical plan digest. Division is deterministic at nanosecond precision;
remainder nanoseconds are assigned by index so concatenation exactly reproduces
the parent interval.

A descriptor is not executable authority. The caller must construct a derived
CYB-85 query, validate it, and obtain a fresh CYB-84 admission. The broker then
verifies the admitted slice has identical non-time scope/native query identity,
matches its descriptor exactly, and retains the parent/plan binding. If policy
or approval does not authorize derived slices, slicing is denied rather than
implicitly inheriting the parent allow.

## Cancellation, replay, and recovery

Cancellation intent binds query ID, attempt ID, current handle, session digest,
reason, and request time. The first intent is retained; exact retries reconcile
the same operation. A changed intent for the same session conflicts. If a page
or cap transition races cancellation, serialized session state selects one next
revision and retains the other observation as explicit uncertainty where needed.

On timeout, outage, or restart, recovery loads the last immutable session record
and re-polls using a current rate reservation and fresh external authority. It
never infers success from a lost response. Durable session/evidence persistence
is owned by COH-E12-05; this leaf defines and enforces the runtime transition
contract without treating process memory as durable authority.

## Compatibility and rollback

Changing profile meaning, cumulative-stat semantics, rate-key scope, slice
division, cap accounting, page ordering, completeness precedence, cancellation
reconciliation, or canonical identity requires a new major contract and
adversarial migration evidence. Rollback stops new sessions, attempts bounded
cancellation of active work, and preserves prior records without relabeling
partial, truncated, canceled, uncertain, or failed outcomes.
