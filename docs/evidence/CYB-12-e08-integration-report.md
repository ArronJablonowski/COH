# CYB-12 E08 agent-orchestration integration verification report

| Field | Value |
|---|---|
| Issue | COH-E08 / CYB-12 |
| Requirements | FR-011, FR-012, FR-013, FR-014, FR-015, FR-017, FR-018, FR-027, FR-039, FR-041, NFR-010, SEC-002, SEC-016, EVAL-004 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `83703e8ccda306bf2b03192538afb546bd0de8d3` |
| Aggregate result | Pass |

## Outcome

All six COH-E08 leaves are Done and now pass one cross-boundary integration
gate. Agent work is represented by strict, reference-only durable run/task
records and a bounded `plan → act → observe → review` graph. Every task reserves
worst-case capacity before scheduling and settles actual use before a successor
can begin. Planning reaches only the bounded model port; consequential action
reaches only the broker's typed, policy/approval/audit-gated action authority.

Crash and restart behavior is explicit. Safe planning work resumes from durable
state. Dispatch without a broker receipt, a lost provider response, an
indeterminate external effect, an ambiguous cancellation acknowledgment, and
an interrupted compaction write become durable uncertainty rather than
automatic retry or success. Confirmed action and provider work is never
duplicated on exact replay.

Context compaction writes a separate immutable, untrusted summary reference
while retaining the complete ordered source manifest beside the result. Source
identity/digest, source and normalized time, timezone, precision, clock
uncertainty, ordering confidence, negative/gap state, completeness, and
uncertainty remain resolvable and digest-bound after replacement.

## Child completion audit

| Child | Deliverable | Linear status | Evidence |
|---|---|---|---|
| CYB-60 / COH-E08-01 | Durable agent loop | Done | `CYB-60-agent-loop-report.md` and checksum manifest |
| CYB-68 / COH-E08-02 | Typed plan/act/observe/review phases | Done | `CYB-68-agent-phases-report.md` and checksum manifest |
| CYB-69 / COH-E08-03 | Broker-only tool routing | Done | `CYB-69-broker-tool-routing-report.md` and checksum manifest |
| CYB-65 / COH-E08-04 | Run and task budgets | Done | `CYB-65-run-task-budgets-report.md` and checksum manifest |
| CYB-66 / COH-E08-05 | Evidence-safe context compaction | Done | `CYB-66-context-compaction-report.md` and checksum manifest |
| CYB-67 / COH-E08-06 | Recovery, cancellation, and provider fallback | Done | `CYB-67-recovery-control-report.md` and checksum manifest |

The integration verifier refuses to run if any child report, checksum manifest,
verifier, or aggregate Pass result is missing.

## Integration acceptance mapping

| Integration criterion | Authoritative evidence | Result |
|---|---|---|
| Agent runs survive restart, remain bounded, and cannot bypass the broker | Injected durable-boundary crashes, recovery adapter, retained workflow replay, bounded phase-cycle/retry policy, pre-schedule budget reservations, broker-route tests, import/surface guards | Pass |
| Compaction preserves resolvable evidence, timestamps, ordering, negative results, and completeness | Compaction controller, canonical fixtures, exact source-manifest digest, replacement validation, scope/order/substitution tests | Pass |
| Cancellation, provider failure, budget exhaustion, and ambiguous action outcomes terminate in explicit durable states | Cancellation tree and deadline tests, provider outcome/fallback matrix, every budget-dimension denial, dispatch crash/invalid receipt uncertainty, restart tests | Pass |

## Cross-boundary proof

`scripts/verify_e08_integration.sh` reruns all six leaf verifiers and then
executes focused paths across their seams:

- agent-loop restart at each durable boundary, budget reservation/settlement,
  exhaustion before scheduling, broker receipt loss, and invalid-receipt
  uncertainty;
- typed phase completion, bounded review/retry exhaustion, and action crash
  without redispatch;
- broker policy/approval/audit binding, exact replay, dispatch ambiguity, and
  cancellation/timeout containment;
- context compaction semantic preservation, exact manifest validation, and
  ambiguous commit recovery without repeat summary work; and
- safe-only workflow recovery, ordered child/tool cancellation, approved
  equivalent fallback, non-fallback terminal outcomes, and lost provider
  response uncertainty.

Repository-wide surface checks prove workflow, provider, transport, UI, and
command packages cannot import directly into connector, executor, runner,
credential, or secret implementations. Architecture, static analysis, file
size, documentation links, and diff hygiene also pass.

The clean integration run finished with:

```text
E08 integration summary: children=6 restart=durable phases=plan+act+observe+review broker=bypass-denied budgets=pre-schedule+settled compaction=evidence-manifest-preserved recovery=safe-only cancellation=child+tool+uncertain fallback=approved+equivalent+nonbroader failures=0
```

Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/e08-integration/run.6Jf1Yp/e08-integration.log
SHA-256 a3ef83d41937626962e641ce5bd541d33f8aeb40456967abde1d9f49975e7b78
```

It records checkpoint `83703e8`, `modified:false`, Go 1.26.7 on darwin/arm64,
66 allowed packages, zero architecture violations, and architecture contract
digest `ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.

## Durable states and no-duplication guarantees

The integrated state model distinguishes pending, running, dispatching,
waiting, succeeded, failed, denied, canceled, timeout, and uncertain outcomes.
Planning can resume only after durable `running`. Action is durable
`dispatching` before the broker call, so missing receipt is uncertain and never
redispatched. Budget settlement is replayed and rebound after interruption
without repeating model or broker work.

Recovery control separately seals safe-resume, cancellation, route decision,
and provider attempts. Cancellation acknowledgments are evidence-bound and
ordered; provider fallback occurs only after definitive primary unavailability
and only onto a current, policy-approved, capability-equivalent route with
equal-or-narrower exposure. Failed, denied, canceled, timed-out, and uncertain
states cannot be promoted to success.

## Evidence and context preservation

Agent and phase records contain immutable references and digests rather than
prompts, evidence bytes, tool output, credentials, or callbacks. Context
compaction verifies every evidence identity/digest in the bound case before
writing a summary. The separately stored summary remains
`untrusted_evidence`; replacement returns only its digest while the full source
manifest and its digest remain in the result and durable state.

This preserves negative results, gaps, truncation, precision, ordering overlap,
and clock uncertainty rather than smoothing them into an authoritative
narrative. A changed source, order, manifest, scope, or replacement is denied.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.UhNolg/quality-report.json
```

Embedded report digest:
`296ecdd21ad9f012342448ed97c4d838c66ef3c7524f8c821759b0d24cca3ccc`.
Report-file SHA-256:
`2c0eb2d795b05ce7ec3c8a94373c31a24e879051516ec60871799651f4316576`.
Provenance records 1,039 source files, source digest
`85b1846abaa849a3d37df09deedcf0f7ddc8ca869a867a9bc4bbbd94182f2fa1`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_e08_integration.sh
./scripts/run_ci_quality.sh baseline
```

## Migration and residual scope

- The planning payload cutover uses `coh.agent-loop.plan.v2`; queued v1
  planning activities drain on the old worker while retained v1 lifecycle
  histories remain replayable.
- Deployment composition must provide the durable store, artifact, workflow,
  route, provider, and cooperative tool-job adapters behind the verified narrow
  ports. Distributed deployment claims require appropriately shared durable
  implementations.
- Durable uncertainty requires operator reconciliation and is deliberately not
  an automatic retry authorization.
- Independent security architecture review remains the hard
  first-production-release gate under CYB-173.
