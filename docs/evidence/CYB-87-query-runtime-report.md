# CYB-87 governed query-runtime verification

| Field | Value |
|---|---|
| Stable key | COH-E12-04 |
| Requirements | FR-047, FR-048, FR-054, NFR-008 |
| Implementation commits | `85b8b53`, `78f9396`, `cff6cc5`, `1f7f5ae`, `bb9902f` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `91044bde2549986d7d9c9b07e8918bb5c30996036b1b9f8a07cc628411b558a7` |
| CI report file SHA-256 | `aaf109380f07c087f4d67e5d417b8f1bcaa18496e6f56e98ff3835fbeeaf7a01` |
| Canonical session fixture digest | `sha256:be5ee732472726d9b0796fed5c5a35d0485fe90d6b6241b59e6f266f472778fd` |

## Evidence locations

- Public runtime schema: `contracts/query-runtime/v1/query-runtime.schema.json`
- Canonical session fixture: `contracts/query-runtime/v1/fixtures/session.canonical.json`
- Contract documentation: `contracts/query-runtime/v1/README.md`
- Threat model: `docs/design/query-runtime-broker.md`
- Focused evidence: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB87.NQ4Vci`
- Adversarial trace: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB87.NQ4Vci/adversarial.log`
- Lifecycle/backoff trace: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB87.NQ4Vci/lifecycle.log`
- Focused race report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB87.NQ4Vci/race.log`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.agxcWm/quality-report.json`

The hashes in [`CYB-87-artifacts.sha256`](CYB-87-artifacts.sha256) identify the
contract, focused, and baseline evidence.

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Interactive/export row, byte, duration, rate, cost, page, and slice caps are enforced with explicit truncation/partial status. | Trusted profiles can only narrow CYB-84-admitted limits. The adversarial matrix independently exceeds every cumulative cap and proves the offending page is withheld, protective cancellation is attempted, and the recorded session is `truncated`. Exact-cap pages may be released only with explicit terminal truncation when more vendor data exists. |
| Interfaces are narrow, typed, cancelable, idempotent, and cannot bypass policy or execution. | `Adapter` contains only `Poll`, `NextPage`, and `Cancel`; `RateGate`, `Recorder`, and `Clock` are separate narrow ports. `Start` requires a verified allowed CYB-84 decision and exact CYB-85 execution. Typed errors, exact transition replay, bounded detached recording/cancellation, and authority-preserving connector requests are tested. |
| Invalid input, denial, timeout/cancellation, and recovery retain provenance and completeness. | Tests cover admission/execution substitution, statistics regression, page sequence change, stale/substituted/exhausted rate reservations, hidden unknown completeness, expired handles, adapter timeout/recovery, caller cancellation, recorder outage/recovery, uncertain cancellation, and changed cancellation. Session revisions bind prior digest, vendor provenance, rate reservation, cancellation intent, and completeness. |
| Paging, slicing, polling backoff, and concurrency are deterministic and bounded. | Page numbers and cumulative statistics advance monotonically. Exact replays return the same transition without another adapter call. Slice plans cover the parent nanosecond UTC interval exactly but grant no authority. Digest-bound capped exponential polling delay rejects early calls before rate or adapter I/O. Concurrent exact polls converge on one adapter operation. |
| Automated tests and repository gates pass. | Focused verbose/adversarial/lifecycle, 10-repeat, race, vet, static, architecture, file-size, and contract-verifier checks passed. Clean commit `bb9902f` passed all 18 baseline stages, including secrets, licenses, vulnerabilities, SBOM, supply-chain, and provenance. |
| Required evidence cross-references the issue and requirements. | This report, retained logs, public schema/fixture, checksums, design record, and verifier identify COH-E12-04, CYB-87, FR-047, FR-048, FR-054, and NFR-008. |

## Authority, rates, and page release

The broker cannot execute or validate a query. A session begins only from an
exact validated query, allowed bounds decision, and matching execution record.
Every vendor operation requires a fresh canonical reservation from the atomic
tenant/source/actor/profile rate authority. Stale, changed, unavailable, or
exhausted reservations fail before adapter I/O.

A page becomes caller-visible only after identifiers, sequence, cumulative
statistics, completeness, provenance, and all budgets validate and the redacted
session transition is durably accepted. Recorder failure returns neither a page
flag nor a page wrapper. Unknown vendor completeness never releases a page.

## Slicing, backoff, cancellation, and recovery

Slice descriptors partition the parent half-open UTC interval exactly at
nanosecond precision. They are not authority: every derived query requires its
own CYB-85 validation and fresh CYB-84 admission.

Successful running or uncertain polls record their exact next-poll time and
double the delay only to the trusted profile maximum. Early calls consume no
rate reservation and perform no adapter operation. Cancellation is canonical
and idempotent; unavailable, mismatched, expired, or unconfirmed cancellation
remains explicit `uncertain`. Budget exhaustion attempts a separately rate-
reserved protective cancellation and never publishes an over-limit page.

## Privacy, migration, and rollback

Session records contain IDs, revisions, counters, bounded reasons, times, and
digests only—never native query text, result rows, credentials, URLs, raw
handles, or vendor errors. Process-local sessions are capacity bounded and only
terminal state may be released; CYB-92 owns durable session/evidence storage.

Profile meaning, statistics semantics, rate keys, slice division, poll backoff,
cap accounting, page ordering, completeness precedence, cancellation
reconciliation, and canonical identities are security-sensitive. Changes
require a new major contract and adversarial migration evidence. Rollback
preserves prior partial, truncated, canceled, uncertain, and failed records.

No unresolved blocking finding remains. An independent security architecture
review remains required before the first production release.

## Verification summary

The focused and baseline evidence proves all CYB-87 acceptance criteria at
clean commit `bb9902fc8df0a409b4f4a4b337ae59b56540d20d`.
