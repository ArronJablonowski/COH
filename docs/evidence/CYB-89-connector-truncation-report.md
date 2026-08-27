# CYB-89 connector truncation evaluation report

| Field | Value |
|---|---|
| Issue | COH-E13-05 / CYB-89 |
| Parent | COH-E13 / CYB-20 |
| Requirements | FR-054, EVAL-016 |
| Implementation baseline | `9bc3c672b61361a7bf6d1f0fab26cafc2935f03a` |
| Corpus | `coh.connector-truncation-corpus/v1` / `1.0.0` |
| Corpus digest | `sha256:1a341c2824118f4ba0014a273e15a64068db4bd893d9c0441e4e746751ee7ef0` |
| Environment digest | `sha256:3090ae88736726c8a5bb8c08a48ef58a5db608b23fd478d0960bc06b6e3349c3` |
| Focused verification | `scripts/verify_connector_truncation.sh` passed |
| Focused evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/CYB-89/run.Akv838` |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.KJw0Ge` |
| CI outcome | 18/18 stages passed; promotable; VCS clean |
| CI report digest | `19942be51198285099aac3a48e228d0830d2580d6d1d75506c8e0a7fcd2f4d48` |
| CI report SHA-256 | `ba1578a19947a6406437ba440640a257358ad40f8997b89e56c13c5111ec6227` |

## Evaluated boundary

The release gate replays 21 sanitized semantic transport recordings five times
each without network access, credentials, endpoints, native query text, or
production events. Elastic coverage includes schema drift, shard partiality,
stable repeated sort keys, PIT rotation and expiry, one-row lookahead,
cancellation, uncertain PIT close, durable-cursor recovery, and qualified
adaptive slicing. Security Onion coverage includes undocumented event caps,
total/count mismatch, aggregation bucket omission, unconfirmed metric
completion, embedded errors, confirmed and uncertain cancellation, outage,
recovery, confirmed empty results, and unsupported adaptive slicing.

Every corpus, environment, contract, recording, task, and trace is digest-bound.
The evaluator requires exactly 105 ordered trials and 21 distinct required
boundaries. Missing or altered tasks, expectations, trials, environment pins,
recordings, or thresholds deny the result rather than reducing a denominator.

## Grader and threshold result

| Metric | Required | Observed |
|---|---:|---:|
| Tasks | 21 | 21 |
| Trials | 105 | 105 |
| Required/covered boundaries | 21 / 21 | 21 / 21 |
| False-complete decisions | 0 | 0 |
| Duplicate rows | 0 | 0 |
| Missing expected rows | 0 | 0 |
| Replay determinism | 100% | 100% |
| Exact outcome grade | 100% | 100% |
| Exact trajectory grade | 100% | 100% |
| Boundary coverage | 100% | 100% |

The threshold outcome is `passed`. The writer accepts only a fresh deterministic
replay result, writes atomically, and emits a corpus manifest, environment
report, 105 JSONL traces, grader report, threshold result, exact reproduction
command, and self-verifying artifact manifest. A second independent evaluation
is byte-identical.

## Adaptive slicing decision

Elastic adaptive slicing is qualified only for the v1 sanitized fixture family
whose intervals prove contiguous half-open coverage, stable event identity and
tie-breaker sort, exact per-slice totals below the requested limit, in-range
timestamps, and cross-slice deduplication. A closed boundary, gap, overlap,
duplicate ID, hidden continuation, partial response, or unstable identity
denies the completeness upgrade.

Security Onion adaptive slicing remains explicitly unsupported. The current
Connect/OQL contract has neither stable continuation nor proven half-open range
semantics, so adjacent responses must never be upgraded to a complete export.

## Migration, recovery, and rollback

- Adoption is additive: existing connector contracts remain unchanged, while
  promotion automation may call the new evaluator as a release-blocking gate.
- Corpus, environment, schema, or recording changes require a new version and
  digest qualification. Editing the locked v1 bytes is rejected.
- Elastic lost-state recovery may resume only from a durable stable cursor with
  exact deduplication. PIT expiry or unconfirmed close remains unknown until a
  separately authorized recovery proves the terminal state.
- Security Onion outage recovery replays the durable bounded request only after
  operator authorization. Missing cancellation state remains uncertain and is
  never automatically retried as success.
- Rollback removes the promotion-gate invocation; it does not reinterpret or
  delete retained evidence and cannot waive a failed threshold.

## Adversarial evidence

Tests reject duplicate JSON keys, unknown fields, manifest/environment drift,
missing tasks or trials, altered expectations, weakened or inconsistent
thresholds, fractional-metric ambiguity, duplicate/missing replay rows,
nondeterministic output, invalid adaptive proofs, artifact tampering, sensitive
fixture markers, and incorrect reproduction commands. Cancellation, denial,
timeout/outage, lost state, recovery, partiality, truncation, and confirmed
completion paths retain exact provenance and fail closed where evidence is
insufficient.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Required Elastic/Security Onion fixture boundaries and exact completeness | Locked recording families, corpus, design record | Pass |
| Pinned versions, tasks, repeated trials, traces, graders, thresholds, reproducible artifacts | Evaluator, schemas, artifact manifest, focused evidence | Pass |
| Invalid input, denial, timeout/cancel, and recovery preserve policy/provenance | Adversarial suite and exact trajectory grades | Pass |
| Applicable CI, race, architecture, secret, license, dependency, and size gates | Focused verifier and clean 18/18 full CI | Pass |
| Evidence cross-references COH-E13-05, FR-054, and EVAL-016 | This report, public contract, checksums, retained artifacts | Pass |

## Residual release condition

No CYB-89 blocking finding remains. The product-level non-blocking follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
