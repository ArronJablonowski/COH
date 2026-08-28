# CYB-96 Splunk search-job lifecycle report

| Field | Value |
|---|---|
| Issue | COH-E14-03 / CYB-96 |
| Parent | COH-E14 / CYB-21 |
| Requirements | FR-051, FR-054 |
| Implementation commits | `6b8a8ab` through `7492149` |
| Focused verification | `scripts/verify_splunk_lifecycle.sh` |
| Full CI evidence | Recorded in the CYB-96 closure comment and attached quality report |
| Residual production condition | Independent security architecture review before first production release |

## Delivered boundary

The Splunk adapter implements the complete common query-connector lifecycle
behind one qualified, fail-closed trust boundary. It creates only asynchronous
historical jobs from a self-verifying parser plan. The typed client exposes
exactly four lifecycle operations: create, status, finalized results, and
cancel. There is no generic REST passthrough, real-time mode, preview release,
caller-supplied SID, caller-supplied offset, mutation endpoint, or raw native
query entry point.

Execution revalidates the exact query, validation, parser plan, capability,
schema, scope, resource, authority, time range, and limits. It coalesces exact
concurrent replay, registers one adapter-private SID owner, and returns only an
opaque expiring COH job handle. Dispatch uncertainty cannot cause a blind
duplicate search.

Polling enforces a 500 ms minimum vendor cadence, monotonic states and counters,
terminal-state immutability, current deadline and authority, and stable failure
or partial reason codes. Only a validated natural `DONE` state may release
results; Splunk's manually finalized flag is rejected because it can represent
partial output.

Finalized paging uses adapter-private cursors and a 1,000-row transport ceiling.
Every page verifies the exact offset, count, total, admitted logical fields,
receipt, result shape, authority, attempt, expiry, and revocation. Cumulative
rows, encoded bytes, pages, duration, result-chain digest, provenance, and
statistics remain bounded. Exhaustion is explicit partial/truncated output,
never hidden completion. Exact replay returns the same validated page without
another vendor call.

Caller cancellation, active deadline expiry, workflow timeout, and policy
revocation converge on one typed cancel path. COH sends at most one bound
`action=cancel` and confirms a terminal state inside a five-second window.
Outage, malformed evidence, missing acknowledgment, or confirmation timeout is
`uncertain`, never confirmed. Result release is blocked even when cancellation
cannot be confirmed. Revocation attempts cancellation once and continues to
deny retained poll/page access.

## Compatibility and conformance

| Deployment | Recorded lifecycle fixture | Live gate | Outcome |
|---|---|---|---|
| Splunk Enterprise 9.4 search head | create/status/results/cancel | CYB-95 identity, TLS, capability, index and field qualification | Supported after qualification |
| Splunk Enterprise 10.0 search head | create/status/results/cancel | Same exact gate | Supported after qualification |
| Splunk Cloud | None | No qualified inventory/lifecycle boundary | Unsupported |
| Unknown minor, state, field, endpoint, mode, or response shape | None | Contract revision required | Denied/unsupported |

The recordings are sanitized deterministic representations of documented
Splunk management REST shapes, not claims of a live deployment. The real typed
HTTP decoder replays both minor families. A deployment must still pass CYB-95
live qualification, use the dedicated read-only principal, and bind the current
capability/schema digests before lifecycle admission.

The lifecycle-specific capability snapshot advertises read-only discovery,
validation, polling, paging, cancellation, and statistics. The common
`queryconnector.Connector` compile-time assertion prevents the adapter from
silently dropping a required lifecycle method.

## Adversarial, recovery, and privacy evidence

Coverage includes invalid plans and bindings; operation, resource, authority,
query, attempt, handle, SID, offset, count, projection, receipt, and result
tamper; unknown/manual-finalized/real-time/preview states; vendor warnings and
multivalue output; row, byte, page, duration, response and record-capacity
bounds; monotonic regression; fast-poll abuse; stale capability/schema;
revocation; caller and deadline cancellation; missing/malformed cancel proof;
confirmation timeout; outage and recovery; failed-dispatch replay safety; SID
collision/theft; cursor theft; deterministic replay; and 32-way execute, poll,
page, and cancellation coalescing under the race detector.

The denial corpus contains 13 executable references and fails if a referenced
test disappears. Contract decoders reject unknown and duplicate keys. Public
capability, status, page, cancellation, error, trace, and CI evidence contain no
credential, bearer token, native SPL, vendor body, SID, or result row. Vendor
recordings contain only fixed synthetic values and declare no sensitive data.

## Rollout, migration, recovery, and rollback

- Start disabled. Require a fresh CYB-95 qualification and complete schema,
  then enable the exact `splunk-1.0.0` adapter and parser-policy versions.
- Existing discovery-only capability snapshots remain historical evidence and
  are not upgraded in place. Consumers must obtain a fresh lifecycle-capable
  snapshot before dispatch; no storage or database migration is introduced.
- A grammar, endpoint, state, response, bound, paging, cancellation, evidence,
  configuration, or supported-minor change requires a reviewed contract
  revision, compatibility assessment, new recordings, and adversarial replay.
- Lost process-local state is unavailable/uncertain and never reconstructed
  from caller input. Requalification and a new authorized attempt are required.
- Rollback disables new lifecycle admission, revokes credential leases and
  policy decisions, attempts bounded cancellation of retained nonterminal jobs,
  blocks further row release, restores the prior reviewed binary/configuration,
  and preserves redacted receipts and durable evidence. Discovery and parser
  validation may remain enabled independently after fresh qualification.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Bounded non-real-time jobs, private SIDs, safe polling, finalized paging, timeout cancellation, statistics | Runtime, typed transport, contracts, lifecycle tests | Pass |
| Typed allowlist, capability/resource bounds, cancellation, redaction, explicit partial/unsupported behavior | Capability snapshot, policy, hostile transport and runtime suites | Pass |
| Invalid input, denial, timeout/cancel, outage and recovery preserve provenance and policy | Denial corpus, adversarial trace, cancellation/recovery tests | Pass |
| Success/failure automation and CI/race/architecture/secret/license/dependency/size gates | Focused verifier and clean full baseline attachment | Pass |
| Recorded fixtures, capability snapshot, conformance report and redacted trace cross-reference COH-E14-03 and FR-051/FR-054 | This packet, verifier and checksums | Pass |

No CYB-96 blocking finding remains. The approved non-blocking product-level
follow-up is unchanged: obtain an independent security architecture review
before the first production release.
