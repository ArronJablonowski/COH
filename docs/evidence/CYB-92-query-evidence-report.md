# CYB-92 query evidence and provenance report

| Field | Value |
|---|---|
| Issue | COH-E12-05 / CYB-92 |
| Requirement | FR-053 |
| Implementation baseline | `696827df4872d7c9fa98053a621d2e9b98d25ff2` |
| Full CI evidence | `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.qxVQA2` |
| CI outcome | 18/18 stages passed; VCS clean |
| CI report digest | `96694609cf75cd9d07a325ec5acd1dc6c8dedad9071b6d0880de42ee4cb84f8d` |
| CI report SHA-256 | `a3ad72a0930ef8e2460d52463f58e37a972bac803b10c14af54efc6f617b27d3` |

## Delivered boundary

- Exact native query text is accepted only as a cancellation-aware stream and
  routed through COH-E10 encrypted, case-scoped evidence ingestion.
- The durable query record contains only redacted identities, closed outcomes,
  cumulative statistics, timestamps, and exact artifact/provenance digests.
- Genesis binds organization, tenant, case, query, source, actor, admission,
  execution, validator, UTC bounds, resource scope, native-query artifact, and
  the signed CYB-87 runtime session.
- Every successor binds the previous provenance digest, next revision, exact
  signed runtime-session revision/digest, result digest/artifact when present,
  completeness, statistics, and cancellation intent/outcome.
- The production repository adapter atomically compares the expected head and
  writes both the new head and idempotency recovery record. Exact lost-response
  replay is recovered; changed replay, stale heads, forks, gaps, substitutions,
  noncanonical bytes, and record tampering fail closed.
- CYB-87 runtime sessions now carry signed `case_id`; this closes the persistence
  integration gap and prevents unsafe side lookups when the recorder is called.

## Verification

Focused verification (`scripts/verify_query_evidence.sh`) passed repeated unit
tests, race detection, vet, static analysis, architecture policy, canonical
fixture decoding, schema assertions, plaintext-field checks, and file-size
policy. `scripts/verify_query_runtime.sh` also passed after the case binding was
added to the runtime contract.

Adversarial coverage includes native-text leakage, missing and substituted
artifacts, changed idempotency intent, chain forks, stale and concurrent heads,
statistics regression, unknown completeness, partial/truncated/uncertain/failed
outcomes, confirmed and uncertain cancellation, caller cancellation, dependency
outage, lost-response recovery, durable restart recovery, repository tampering,
strict unknown-field rejection, and canonical digest tampering.

The full clean baseline passed format, file-size, workflow, worktree/history
secret scans, architecture, quality contract, vet, static analysis, unit, race,
fuzz seeds, license, dependency/vulnerability, SBOM, supply-chain, evidence
secret scan, and provenance stages.

## Residual release condition

No CYB-92 blocking finding remains. The product-level non-blocking follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
