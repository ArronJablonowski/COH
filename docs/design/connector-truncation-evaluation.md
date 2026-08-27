# Connector truncation evaluation protocol

| Field | Value |
|---|---|
| Issue | COH-E13-05 / CYB-89 |
| Requirements | FR-054, EVAL-016 |
| Dependencies | CYB-16, CYB-91, CYB-94, CYB-90 (Done) |
| Decision | Run a separate locked deterministic fixture evaluator through real Elastic and Security Onion completeness rules; reuse the CYB-44 artifact/grade pattern without changing its frozen corpus |

## Purpose and claims

The release gate proves that connector responses never become more complete
than the evidence permits. It covers schema drift, partial responses, repeated
stable-sort keys, PIT rotation/expiry, Security Onion backend limits,
cancellation, recovery, and adaptive-slicing decisions. It does not contact a
live target, hold a credential, waive a threshold, infer undocumented behavior,
or claim that sanitized fixtures qualify a new vendor version.

Each task identifies one vendor family, connector mode, fixture sequence,
expected terminal outcome, exact completeness record, and required ordered
trajectory. At least five deterministic trials run per task. Corpus,
environment, task, fixture, trace, grader, and threshold digests are included in
the evidence. Two independent runs must produce byte-identical artifacts.

## Threat model

The evaluator assumes a malicious or drifted fixture may attempt to:

- omit, repeat, reorder, or add response members;
- substitute schema, target, query, range, limits, PIT, sort keys, or authority;
- hide shard/backend errors behind HTTP success;
- fill a declared or undocumented cap without a continuation;
- expire or rotate PIT state between pages;
- exploit repeated sort keys to lose or duplicate rows;
- turn cancellation, timeout, close failure, or lost local state into success;
- weaken expected completeness or release thresholds;
- cherry-pick trials, environment versions, or favorable traces; or
- place credentials, tokens, native queries, literals, rows, or vendor bodies
  in public evaluation artifacts.

Strict versioned decoding, exact task registration, fixture digests, locked
trial counts/thresholds, ordered trajectory grading, and redaction checks deny
these cases. The runner accepts no caller threshold override and executes no
network operation.

## Completeness lattice and grader

The evaluator recognizes these terminal decisions:

| Decision | Required evidence |
|---|---|
| `complete` | Vendor-confirmed full coverage under the connector contract |
| `partial` | Some valid rows exist but full coverage is not proven |
| `truncated` | A row/page/event/metric/backend ceiling was reached |
| `unknown` | Outcome or vendor state cannot be established safely |
| `denied` | Input, identity, schema, response, or policy failed closed |
| `canceled` | Cancellation is confirmed at the boundary claimed |

The outcome grader compares the complete observed terminal record to the locked
expectation. The trajectory grader independently checks ordered boundary events,
monotonic statistics, absence of release before validation/evidence, exact
replay, bounded cleanup, and the rule that no transition upgrades
`partial|truncated|unknown|denied|canceled` to `complete` without new
vendor-confirmed coverage.

Release thresholds are exact and non-waivable: zero false-complete outcomes,
zero duplicate or missing released rows where stable paging is claimed, 100%
expected-outcome grades, 100% trajectory grades, 100% replay determinism, and
complete required-boundary coverage. A missing trial or task is denial, not a
smaller denominator.

## Adaptive slicing decision

Adjacent time slicing is enabled only for a fixture family that proves all of:

1. half-open `[start,end)` vendor semantics;
2. deterministic stable event identity and sort order;
3. monotonic coverage as intervals shrink;
4. exact cross-slice deduplication;
5. no hidden backend cap below the requested limit; and
6. cancellation/retry cannot skip or duplicate an accepted slice.

Until every proof exists, the expected evaluator result is
`adaptive_slicing_unsupported`; the safe operator action is a new bounded query
or smaller explicitly admitted interval. In particular, the current Security
Onion Connect contract has no stable continuation or proven half-open boundary,
so adjacent responses cannot be upgraded to a complete export.

The v1 corpus qualifies adaptive slicing only for the sanitized Elastic fixture
family. Its proof uses explicit `gte`/`lt`-equivalent half-open intervals,
stable event identity plus tie-breaker sort keys, contiguous interval coverage,
exact cross-slice deduplication, and per-slice total/count agreement below the
requested limit. Any missing proof field, gap, overlap, duplicate identity,
hidden continuation, partial response, cancellation, or retry uncertainty
denies the completeness upgrade.

## Pinned environment and artifacts

The environment pins Go/toolchain/platform, connector contract versions, public
fixture/checksum manifests, logical clock, randomness policy, and network mode
`disabled`. Generated evidence consists of a normalized corpus manifest,
environment report, repeated JSONL trial traces, outcome/trajectory grader
report, threshold result, reproduction command, artifact manifest, and SHA-256
ledger. No wall time, hostname, absolute output path, secret, native query,
literal, result row, or vendor body enters deterministic metadata.

The evaluator will live separately from `internal/workflow/replayeval` because
the CYB-44 corpus and its compiled digests are already a frozen release record.
It may reuse the same bounded-file, strict-JSON, atomic-artifact, double-run,
and exact-threshold design, while task simulation and graders remain specific
to connector completeness.
