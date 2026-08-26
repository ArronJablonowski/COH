# CYB-68 typed agent phases verification report

| Field | Value |
|---|---|
| Issue | COH-E08-02 / CYB-68 |
| Requirements | FR-012, FR-041 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `2683b07ec097289d4f7bf3b2bb0cc8e90676ff13` |
| Aggregate result | Pass |

## Outcome

COH now coordinates a versioned `plan → act → observe → review` graph over
the durable agent loop. Each phase has strict `coh.agent-phase/v1` input and
output records bound to the run, case, actor, policy, provider route, trace,
cycle, deadline, exact input set, prior immutable output, and deterministic
step identity.

The coordinator exposes only the existing typed `ModelProvider`,
`ActionAuthority`, durable `StateStore`, immutable result resolver, and clock.
The plan phase binds one exact `ToolIntent` digest. The act phase can submit
only that intent through `ActionAuthority` and accepts only the broker receipt
and evidence reference. Observe records completeness and negative-result
state. Review returns typed claims and findings with evidence,
counterevidence, confidence, unknowns, recommended next steps, and an
accepted/revise disposition.

Raw prompts, model output text, finding text, evidence bytes, provider
payloads, and tool payloads remain behind immutable artifact references.

## Short-task completion mapping

| Task | Authoritative evidence | Result |
|---|---|---|
| 1. Freeze versioned records and strict decoding | Public JSON Schema, canonical encoders, unique-key decoder, explicit required-field enforcement, fixtures, unknown/duplicate/missing/trailing tests | Pass |
| 2. Define graph and guards | `nextPhase`, deterministic phase identity validation, terminal/revise guards, and skipped-phase/binding denial tests | Pass |
| 3. Build a narrow coordinator | `Dependencies`, `Coordinator`, reflection/import architecture test, immutable run bindings inherited from the durable loop | Pass |
| 4. Implement plan | Versioned phase input, typed plan output and intent digest, running/terminal persistence, success trace | Pass |
| 5. Implement act | Plan-bound `ToolIntent`, `ActionAuthority`, broker receipt/evidence-only output, dispatch-loss uncertainty, no redispatch test | Pass |
| 6. Implement observe | Evidence-reference input, completeness and negative-result fields, immutable observation output, trace/input binding | Pass |
| 7. Implement review | Typed claims/findings, ordered evidence sets, counterevidence, confidence, unknowns, next steps, disposition, source-output binding | Pass |
| 8. Bound retry/revision | Phase-attempt and review-cycle ceilings of 1–8, deterministic retry identity, deadline preservation, review-only revision, exhaustion tests | Pass |
| 9. Preserve typed provenance and recovery | Durable denial/cancellation/timeout/failure/uncertainty, malformed-output terminalization, trace drift denial, start replay, crash/restart test | Pass |
| 10. Test, verify, and publish evidence | Focused/repeated/race tests, vet, static analysis, architecture, file-size, links, all 18 clean baseline stages, this report and manifest | Pass |

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Versioned phase inputs/outputs, guards, traces, reviewer findings, and bounded retry | Schema, runtime validation, deterministic step IDs, coordinator graph, typed review records, retry/revision tests | Pass |
| Narrow Go interfaces, typed errors, cancellation, idempotency, and no policy/executor bypass | Dependency surface, typed errors, durable agent-loop idempotency, cancellation/timeout tests, architecture boundary test | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance without bypass | Strict decoder, broker-denial test, malformed/trace-drift tests, cancellation/timeout tests, crash uncertainty and replay tests | Pass |
| Success and failure tests pass all applicable quality gates | Focused verifier and all 18 clean baseline stages at the verified checkpoint | Pass |
| Unit/integration, race, trace, and architecture evidence cross-reference COH-E08-02, FR-012, and FR-041 | Retained focused log, verbose phase trace, clean baseline report, this report and checksum manifest | Pass |

## Contract and phase semantics

The public schema is
`contracts/workflow/v1/agent-phase.schema.json`, file SHA-256
`a5e0e128222387f37a0541994b83a87f92f05cc2068ee459bd76738ac0e9846b`.
It freezes strict input and output objects with no unknown properties,
required fields at every nesting level, sorted/unique reference sets enforced
by Go, and maximum phase-attempt and review-cycle values of eight.

Runtime decoding additionally rejects duplicate keys, missing top-level or
nested required fields, malformed records, non-canonical values, trailing
data, invalid timestamps, unsorted or duplicate references, and records over
one MiB. Published input and review fixtures decode through the same runtime
path.

Each step ID is deterministically derived from run ID, trace ID, cycle, and
phase. Session validation recomputes the full identity and the retry-control
digest, then verifies the immutable run reference. A phase output must match
the expected phase, trace, cycle, input-set digest, and artifact digest before
it can schedule a successor.

## Side-effect, retry, and recovery guarantees

Only plan, observe, and review call the model provider. Act is a distinct
authorized-action step and requires the exact plan-bound intent digest. Its
result is synthesized from a broker receipt and immutable evidence reference;
model content cannot represent action success.

Model phases may resume from a persisted running state up to the configured
attempt ceiling. Consequential action is never redispatched after a persisted
`dispatching` state with a missing receipt: recovery durably records
`uncertain`. Broker denial remains denied, malformed semantic output is
terminalized as denied, cancellation and timeout retain their distinct
statuses, and retry/review exhaustion becomes a durable failure.

Review may schedule a new plan cycle only with an explicit `revise`
disposition and only below the configured review-cycle ceiling. `accepted`
completes the run. No transition skips a phase.

## Focused verification and trace

The clean checkpoint passed `scripts/verify_agent_phases.sh`. Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/agent-phase.nPxktr/agent-phase.log
SHA-256 0ee9650ed17779a22be59df3ab9ea774c8b5e3e0177c4315b1a50fca94c13045
```

The verifier runs focused tests once and three times, race detection, vet,
static analysis, architecture, file-size, documentation-link, schema/fixture,
forbidden-import, and diff-hygiene checks. Architecture verification reports
62 packages, zero violations, contract digest
`ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.
Provenance records the exact checkpoint and `modified=false`.

The verbose phase trace covers the full accepted path, replay, bounded
revision, denial, malformed output, guard drift, retry exhaustion,
cancellation, timeout, crash/restart uncertainty, strict decoding, and the
no-bypass boundary:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/agent-phase.nPxktr/phase-trace.log
SHA-256 2d2e798753ec1dc04a939e3225111c6711543cd38536e7b5a552078b0c38b0aa
```

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.Qz6uMh/quality-report.json
```

Embedded report digest:
`4e3050c214adad28564dcc48efdee4112c9716e599214025bc969d5152990242`.
Report-file SHA-256:
`7c426287fc8b3cd7701bdd3ad6a5972c8dca028e6b9427741fbcf6ca50506557`.
Provenance records 955 source files, source digest
`6456b6fd5d64434b06ad1e0ea6f436215ca63ea59aa47a7e8acd53770112fd91`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_agent_phases.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- Later COH-E08 issues add broker-only routing enforcement, budgets/context
  compaction, and recovery/provider fallback around these phase semantics.
- An indeterminate authorized-action dispatch deliberately requires
  reconciliation; CYB-68 does not guess or risk duplicating the action.
- Incompatible contract or phase-graph changes require a new version and
  migration/replay evidence.
- Independent security architecture review remains the production-release
  gate under CYB-173.
