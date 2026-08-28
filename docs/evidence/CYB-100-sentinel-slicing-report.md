# CYB-100 Sentinel slicing, dedupe, and PartialError evaluation report

| Field | Value |
|---|---|
| Issue | COH-E14-06 / CYB-100 |
| Parent | COH-E14 / CYB-21 |
| Requirements | FR-052, FR-054, EVAL-016 |
| Implementation commits | `02e8347` through `42275fc` |
| Focused verification | `./scripts/verify_sentinel_slicing.sh` |
| Locked corpus | `docs/evidence/CYB-100/corpus-manifest.json` |
| Pinned environment | `docs/evidence/CYB-100/environment-report.json` |
| Trial count | 11 tasks × 5 deterministic trials = 55 |
| Threshold | Passed; every rate 1.0, zero false-complete and zero denied-row release |
| Residual production condition | Independent security architecture review before first production release |

## Delivered boundary

COH now has a typed Microsoft Sentinel Logs Query API runtime behind the
qualified Sentinel discovery adapter and Kusto validator. The transport exposes
only the public-cloud `POST /v1/workspaces/{workspace-id}/query` operation. The
workspace, source, scope, authority, capability, schema, qualification,
validation, canonical KQL, audit decision, TLS identity, deadlines, limits, and
absolute `timespan` are digest-bound before credential use. No caller-controlled
URL, method, audience, workspace, cross-workspace target, management-plane
operation, ingestion surface, or generic HTTP client is exposed.

The exact audited KQL is never rewritten for a slice. Each request binds an
absolute vendor `timespan`; the runtime also enforces the qualified logical
half-open interval locally before releasing rows. PartialError, malformed,
duplicate-key, oversize, schema-drift, binding-drift, deadline, cancellation,
and vendor-unavailable responses cannot produce a complete page.

Authoritative vendor references used for the design freeze:

- [Azure Monitor Logs API overview and authorization](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview)
- [Azure Monitor Logs query resource endpoint](https://learn.microsoft.com/en-us/rest/api/logsquery/query-resource/query-resource?view=rest-logsquery-2022-10-01)
- [Azure Monitor Logs API response format and PartialError](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/response-format)
- [Azure Monitor query time range behavior](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/timeouts)

## Slicing, ordering, and result safety

The planner bisects canonical nanosecond UTC intervals at deterministic
midpoints and records a versioned slice plan. Leaf intervals must be contiguous,
non-overlapping, cover the exact original range, and all complete. Threshold
responses are never released. Minimum duration, maximum slices, row, byte, and
duration exhaustion fail closed; retry replays the exact unreleased request.

Every qualified resource supplies an identical timestamp and ordered stable-key
profile. Rows are checked for local interval membership and nondecreasing typed
`(timestamp, stable-key)` order. Typed comparison avoids treating JSON lexical
order as numeric order. Null, missing, unsupported, or inconsistent keys deny
release as ambiguous. An identical cross-slice identity and canonical row
collapses to one row while retaining every response digest. The same identity
with different row content is conflicting evidence and denies the result.
Inclusive vendor boundary rows are accepted only provisionally: the adjacent
slice must independently return the identical row. An orphan boundary row is
outside the logical half-open interval and is withheld.

The released page binds the complete slice-plan digest, slicing-semantics
digest, all request and leaf-response digests, row lineage, validation,
canonical KQL, audit proof, merged result, completeness, and aggregate
statistics. Cancellation fences release and clears unreleased responses.

## Locked evaluation and evidence

The evaluator re-hashes five public contracts and four sanitized fixtures before
loading any task. Runtime identity is pinned to Go 1.26.7 on darwin/arm64, a
logical clock, no randomness, and disabled network. Corpus-to-recording identity,
boundary, fault, expectations, trajectory, and the complete recording-set digest
must match exactly.

Each of the 11 locked tasks runs five times. The evaluator derives successful
row counts and dedupe outcomes from sanitized recording steps, independently
classifies denied, canceled, and unknown faults, grades exact outcome and
trajectory, proves all nine required boundaries, and requires byte-identical
replay. Artifacts are written atomically and then re-read through strict decoders
and their manifest hashes.

Published evidence:

- `docs/evidence/CYB-100/corpus-manifest.json`
- `docs/evidence/CYB-100/environment-report.json`
- `docs/evidence/CYB-100/trial-traces.jsonl`
- `docs/evidence/CYB-100/grader-report.json`
- `docs/evidence/CYB-100/threshold-result.json`
- `docs/evidence/CYB-100/artifact-manifest.json`
- `docs/evidence/CYB-100/reproduction.txt`
- `docs/evidence/CYB-100-artifacts.sha256`

The dedicated verifier covers strict schema and pin checks, sensitive/network
marker denial, focused tests repeated ten times, race, vet, static analysis,
architecture, file size, CLI build, two byte-identical evaluator runs, artifact
self-verification, and exact 100% thresholds. Direct transport/runtime tests add
mandatory bounds, malformed/oversize/schema drift, stable-key conflict and
ambiguity, orphan boundary, PartialError, cancellation, timeout, outage,
recovery, exact retry, replay, tamper, redaction, and concurrent evaluation.

The clean `42275fc` baseline passed all 18 required stages with
`vcs_modified:false`, including repository-wide unit/race, worktree/history/
evidence secret scans, license inventory, locked offline dependency and
vulnerability checks, SBOM, supply-chain reproducibility, and provenance. Final
clean CI for this checksummed packet is recorded in the CYB-100 closure comment.

## Rollout, migration, recovery, and rollback

- Start disabled. A deployment must use a dedicated least-privilege identity,
  exact workspace and TLS pins, fresh discovery qualification, the matching
  validator/runtime contract versions, and an authorized live semantics canary.
- The sanitized evaluator qualifies the algorithm; it is not evidence of access
  to a live tenant. Obtain the already-recorded independent security architecture
  review before the first production release.
- Any workspace, endpoint, audience, identity, schema, KQL validator, stable-key,
  timestamp precision, slicing rule, limit, error, or dedupe change requires a
  new reviewed contract version and fresh qualification. Existing evidence is
  immutable and is never upgraded in place.
- An outage, timeout, PartialError, uncertain retry, incomplete slice plan, or
  lost process-local job state releases no page. Recovery begins a new authorized
  attempt or replays only the exact recorded unreleased request; stale bodies,
  credentials, qualifications, and handles are never reused.
- Rollback disables the source, revokes credential leases and policy decisions,
  expires qualification/capability/job state, restores the prior reviewed binary
  and configuration, and preserves only immutable redacted evidence.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Mandatory timespan, adaptive half-open slicing, stable-key dedupe, ambiguity, cancellation, and PartialError rejection | Runtime, transport, adversarial tests, locked recordings | Pass |
| Pinned corpus/environment, tasks, five trials, traces, outcome/trajectory graders, thresholds, reproducible artifacts | Published CYB-100 evidence directory | Pass |
| Invalid input, denial, timeout/cancel, recovery preserve policy and provenance | Focused transport/runtime/evaluator coverage | Pass |
| Applicable CI, race, architecture, secret, license, dependency, vulnerability, reproducibility, and size gates | Dedicated verifier and clean 18-stage baseline | Pass |
| Checksummed corpus, environment, traces, graders, threshold, reproduction command cross-reference COH-E14-06, FR-052, FR-054, EVAL-016 | This report and artifact manifest | Pass |

No CYB-100 blocking finding remains. The approved non-blocking product-level
follow-up remains: obtain an independent security architecture review before
the first production release.
