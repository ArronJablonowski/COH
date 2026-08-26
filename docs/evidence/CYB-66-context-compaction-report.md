# CYB-66 evidence-safe context compaction verification report

| Field | Value |
|---|---|
| Issue | COH-E08-05 / CYB-66 |
| Requirements | FR-027, SEC-016 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `78fbb33364b99a4a24ffc1d8befd06deb3f2c103` |
| Aggregate result | Pass |

## Outcome

COH now replaces large workflow context with a reference to a separately
stored immutable JSON summary without discarding or rewriting the evidence
manifest. Durable state and the workflow result retain every ordered source's
case-resolvable evidence ID and digest, source and normalized time, timezone,
precision, clock uncertainty, ordering confidence, result state,
completeness, uncertainty, and fixed `untrusted_evidence` label.

The controller resolves every source ID and digest in the bound case before it
persists intent. It then persists `writing` before invoking the data-only
summary writer. The writer has no policy, approval, broker, executor, tool, or
connector authority. Only a validated immutable artifact reference is added
to completed state.

The exact source list is independently bound by a canonical manifest digest.
The workflow replacement boundary recomputes that digest and denies a changed,
reordered, or substituted manifest even if all replacement descriptors are
individually valid.

## Short-task completion mapping

| Task | Authoritative evidence | Result |
|---|---|---|
| 1. Freeze v1 records | `coh.context-compaction/v1` schema, Go request/result types, canonical intent/state fixtures, strict versions and bounded fields | Pass |
| 2. Model ordered sources | Source descriptors require resolvable ID/digest, both times, timezone, precision, clock uncertainty, order, result, completeness, and uncertainty | Pass |
| 3. Build narrow compactor | `Compactor`, `Store`, `EvidenceResolver`, and `SummaryWriter` are single-purpose ports; public-boundary and import checks forbid authority capabilities | Pass |
| 4. Persist before summarizing | Tests prove `writing` is durable before the writer runs and only the returned artifact reference enters durable state | Pass |
| 5. Bind exact identities | Intent, idempotency, source-manifest, and provenance digests cover scope, run/task, policy, route, ordered sources, summary, revision, and prior state | Pass |
| 6. Enforce untrusted data | Fixed trust labels, reference-only records, forbidden-field reflection tests, schema checks, and import checks | Pass |
| 7. Fail closed and recover | Exact replay, changed-input denial, in-progress conflict, uncertain recovery, lost commit response, writer failure, cancellation, timeout, malformed reference, and tamper tests | Pass |
| 8. Expose safe replacement | `ReplacementReferences` admits only a completed untrusted summary with a valid, exact source-manifest digest and retains all source metadata in `Result` | Pass |
| 9. Add adversarial tests | Success, decoding, negative/gap/incomplete/uncertain semantics, ordering, scope, replay, tamper, cancellation, timeout, concurrency, and recovery pass | Pass |
| 10. Run gates and publish evidence | Focused/repeated/race/vet/static/architecture/size/link checks and all 18 clean baseline stages pass | Pass |

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Summaries are separate while resolvable evidence identity, time precision, order, negative results, uncertainty, and completeness remain | Controller success test, canonical fixtures, source-manifest binding, schema, and design decision | Pass |
| Narrow Go interface, typed errors, cancellation, idempotent boundaries, and no policy/executor bypass | Public-boundary reflection test, forbidden import verifier, typed errors, exact replay, writer cancellation/timeout tests | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance without policy bypass | Strict validation, fixed transition reasons, chained provenance, durable uncertainty, scope/identity mutation and ambiguous-commit tests | Pass |
| Success and failure paths pass applicable CI, race, architecture, secret, license, dependency, and size gates | Focused verifier and the 18-stage clean baseline at the verified checkpoint | Pass |
| Unit/integration, race, trace, and architecture evidence cross-reference COH-E08-05, FR-027, and SEC-016 | Retained logs, clean quality report, this report, and checksum manifest | Pass |

## Contract and trust boundary

The public schema is
`contracts/workflow/v1/context-compaction.schema.json`, SHA-256
`d7b36e36843dfb9769831b258bef644cdaf2b80dc39a2b7ae01ffcddb35e5b21`.
It freezes canonical intent and durable state, including state-dependent
summary, revision, prior-provenance, and reason-code constraints. Runtime
decoding recursively rejects unknown, duplicate, missing, nested-missing,
trailing, malformed, oversized, unsupported, or noncanonical records.

Records and public inputs carry references and typed metadata only. They do
not carry evidence bodies, prompts, instructions, credentials, callbacks,
functions, approval or policy authority, tool authority, connectors,
executors, or raw dependency errors. Sources and the derived summary remain
explicitly `untrusted_evidence` and cannot become instructions or authority.

`EvidenceResolver` receives only the exact case, evidence ID, and immutable
digest and returns no content. `SummaryWriter` receives only case/run/task
identity, the ordered reference manifest, and deadline. Concrete adapters may
read evidence within their own boundary but cannot obtain broker capabilities
through the compactor.

## Ordering, provenance, and replacement proof

Source sequences must be contiguous, evidence IDs unique, all typed semantic
fields valid, and the list bounded to 512 entries. The intent digest binds the
organization, tenant, case, run, task, compaction ID, policy digest, provider
route, source list, creation time, and deadline. A separate source-manifest
digest lets the result validate the exact list without possessing authority or
reloading content.

Durable state permits only these v1 transitions: revision 1 `writing` with no
prior digest, followed by revision 2 `completed` or `uncertain` with a fixed
reason and exact prior digest. Every load recomputes the intent, manifest, and
provenance digests. Tests alter scope, run, task, policy, provider route,
idempotency, source order, source metadata, result manifest, revision, and
stored provenance and prove fail-closed denial.

## Replay and recovery proof

An exact completed replay returns the same summary and provenance without
calling the writer. Changed bytes are denied. A concurrent exact replay while
the first writer is active returns retryable `compaction_in_progress` without
modifying state.

If a begin response is lost after `writing` commits, restart does not repeat
the potentially external summary operation; once the durable deadline passes,
state becomes `uncertain`. If the completed-save response is lost after commit,
restart loads the completed state and returns it without a second write.
Writer failure, invalid output, cancellation, and timeout also create a fixed,
redacted, durable uncertain result through a bounded cleanup context.

## Focused verification and adversarial trace

The checkpoint passed `scripts/verify_context_compaction.sh`. Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/context-compaction.fuzlaO/context-compaction.log
SHA-256 93b08ba260aecd3b7a333d968902e61046d9439e9eab77f1ade874ba0c2716ee
```

The verifier checks schema and fixtures, forbidden fields and imports,
focused tests once and three times, race detection, vet, static analysis,
architecture, file size, documentation links, and diff hygiene. It records
commit `78fbb33364b99a4a24ffc1d8befd06deb3f2c103` with
`modified:false`. Architecture verification reports 65 allowed packages, zero
violations, and contract digest
`ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.

The verbose trace names success, preservation, exact and changed replay, scope
and identity mutation, source reordering, result-manifest substitution,
concurrent in-progress behavior, ambiguous commits, invalid inputs, writer and
resolver denial, store tamper, cancellation, timeout, and durable uncertainty:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/context-compaction-trace.6CQm6x/adversarial-recovery.log
SHA-256 522bbf8ab37041d9ea36f90ba26c2dd851b3e354a2482f96830eaa33b2aedc24
```

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.2tTJzj/quality-report.json
```

Embedded report digest:
`31118d2eec109ae2fda2f4ea84d163efbfdebcb0c4e709a57c3c0395a7b6560b`.
Report-file SHA-256:
`93fa20d95a9abdd605107e284a1041e15f11f0fdbb0b4ed2c3d601adb9af2ca5`.
Provenance records 1,011 source files, source digest
`581278c4fa7bedf7996860e886f5a79a87284993494d4b5cc6be8325ead88377`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_context_compaction.sh
./scripts/run_ci_quality.sh baseline
```

## Migration and residual scope

- Context compaction is a new side record. Existing histories stay pinned to
  their workflow definition and are not retroactively compacted. Adoption
  requires a new workflow definition/version and retention of side-record
  provenance.
- Generic SQLite/PostgreSQL metadata layouts need no DDL change. Deployments
  must compose durable begin/compare-and-save, evidence-resolution, and
  immutable summary-writer adapters at the defined ports.
- An uncertain external write is intentionally not retried automatically;
  operators reconcile the orphan possibility rather than risk duplicate or
  contradictory summaries.
- Independent security architecture review remains the production-release
  gate under CYB-173.
