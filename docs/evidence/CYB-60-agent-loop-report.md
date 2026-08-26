# CYB-60 durable agent loop verification report

| Field | Value |
|---|---|
| Issue | COH-E08-01 / CYB-60 |
| Requirements | FR-011, FR-012, FR-014 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `04c204ca07c93f4d9b029c12526b14e9a85d930a` |
| Aggregate result | Pass |

## Outcome

COH now has an engine-neutral, durable `coh.agent-loop/v1` state machine.
Every run starts with one pending typed step. Planning is persisted as
`running` before model inference; consequential work is persisted as
`dispatching` before the broker is called. Successful steps leave the run
in `waiting` for another step or explicit completion.

Run and task state is stored as canonical `coh.domain/v1` common envelopes.
The payloads validate against both the shared domain contract and the narrower
agent-loop schema. Each transition atomically writes the run, current task,
and one deterministic `agent_loop.transition` outbox event through the
guarded repository with optimistic revisions and an idempotency key.

Workflow state contains only bounded identities, immutable artifact
references, digests, statuses, revisions, deadlines, and timestamps. It does
not retain prompts, evidence bytes, credentials, connector responses, raw
provider/tool payloads, or executable callbacks.

Planning is available only through the typed
`coh.agent-loop.plan.v1` activity and `ModelProvider`. Consequential work
is available only through `coh.agent-loop.authorized-action.v1` and
`ActionAuthority`. The latter binds the exact `ToolIntent` digest and
returns only a broker-owned receipt. There is no direct connector, executor,
runner, credential, shell, HTTP, policy-engine, or generic callback surface.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Persist run/step state, resume after restart, and separate planning from authorized execution through typed workflow activities | Canonical repository store, `Loop.Start/Execute/Schedule/Complete/Resume`, typed `Activities.Plan/Act`, exact Temporal activity registration, restart and dispatch-loss tests | Pass |
| Narrow interfaces, typed errors, context cancellation, idempotent boundaries, and no direct policy/executor bypass | `StateStore`, `ModelProvider`, `ActionAuthority`, bounded request/result records, typed error codes, cancellation/timeout persistence, reflection/import boundary tests | Pass |
| Invalid input, denial, timeout/cancellation, conflicts, and recovery preserve provenance and fail closed | Invalid/corrupt-state tests, legal-transition enforcement, denial and ambiguous-outcome tests, injected crash matrix, chained transition digests, missing-receipt uncertainty | Pass |
| Applicable CI, race, architecture, secret, license, dependency, and size gates pass | Focused verifier plus all 18 clean baseline stages at the verified checkpoint | Pass |
| Unit/integration output, race report, relevant trace, and architecture evidence cross-reference CYB-60 and FR-011/FR-012/FR-014 | This report, retained focused log, retained recovery trace, clean quality report, contract and replay-fixture checksums | Pass |

## Durable contract and state machine

The public schema is
`contracts/workflow/v1/agent-loop.schema.json`, file SHA-256
`f5ef4075aa8b8b5da3dd497a0afc5164f88922d0533eefe752eade8707ae7523`.
It freezes:

- eight run states: running, waiting, succeeded, failed, denied, canceled,
  timeout, and uncertain;
- nine step states: pending, running, dispatching, succeeded, failed, denied,
  canceled, timeout, and uncertain;
- planning steps with an empty intent digest and authorized-action steps with
  a required SHA-256 intent digest;
- sorted, unique, bounded reference arrays;
- exact contract, workflow, revision, scope, timestamp, and provenance fields;
- strict common envelopes and payload objects with no unknown properties.

The repository accepts only the initial running/pending state and legal
subsequent transitions. It rejects identity drift, scope drift, immutable
input drift, revision or sequence conflicts, provenance mismatches, skipped
states, active-run rescheduling, output removal, and incompatible run/step
status pairs.

## Side-effect and recovery guarantees

Planning work may be retried after a crash because it returns only an immutable
artifact reference. An authorized action is never automatically retried after
the durable state reaches `dispatching`. If the process loses the broker
receipt, recovery persists `uncertain` and requires reconciliation instead
of risking a duplicate consequential effect.

The injected crash suite covers:

- create failure before the initial commit;
- failure before exposing a planning activity;
- failure after a planning result but before terminal persistence;
- failure while scheduling a new step;
- failure after broker dispatch/receipt but before receipt persistence;
- failure while completing a waiting run;
- safe planning retry, idempotent terminal return, and no action replay.

Broker denial, cancellation, timeout, failed outcome, invalid receipt, and
ambiguous dispatch failure remain distinct durable outcomes. None is converted
to success.

## Temporal compatibility

The existing `WorkflowEngine` accepts the immutable
`coh.agent-loop.v1` definition only when it is bound to operation kind
`agent_loop`. The Temporal adapter starts that exact registered definition,
registers both typed activities under immutable v1 names, and rejects a
mismatched definition in the workflow input.

The retained three-event replay fixture carries only case/operation
identifiers and digests. Its SHA-256 is
`028ba6ab2e0f96b928a7410fc8f7f0bb30d876d24248a762d1021ca0b9ae821d`.
Both operation-v1 and agent-loop-v1 histories replay under repeated tests.

## Focused verification

The clean checkpoint passed `scripts/verify_agent_loop.sh`. Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/agent-loop.j2aND2/agent-loop.log
SHA-256 6d04c27494b75cdfbc565b0ddc494c9e8ff02e5efc97ba6b7b2aac05b0f5db0c
```

The verifier checks both schemas, the bounded replay payload, forbidden
dependency imports, domain-payload validation, unit tests, three repeated
runs, race detection, vet, static analysis, architecture, file sizes,
documentation links, and diff hygiene. Architecture verification reports 61
packages, zero violations, contract digest
`ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.

The focused success, denial, cancellation, timeout, uncertainty, and
crash/restart trace is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/agent-loop.j2aND2/recovery-trace.log
SHA-256 33a97758ff05bb2362d210ad47fa736ab00dfac825878350832b0fcb43eb2411
```

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.UTfXde/quality-report.json
```

Embedded report digest:
`cb6333303b85d9d266dab4a982ac77b1baf72d40d991c6b0df67f08118bf2b69`.
Report-file SHA-256:
`d423b96f3ca286ea6b177484a07934a9985b2e910e5355a97674bccb7c5bfff0`.
Provenance records 935 source files, source digest
`0021415acb77fc743d01201b02a9ce33532c89923e68d8692d15033f2f536541`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_agent_loop.sh
./scripts/verify_temporal_adapter.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- Later COH-E08 issues add phase semantics, broker-only routing enforcement,
  budgets, context compaction, and provider fallback on top of this durable
  foundation.
- A missing authorized-action receipt deliberately requires reconciliation;
  CYB-60 does not guess whether an external effect occurred.
- Incompatible state-machine or Temporal changes require a new contract and
  workflow definition plus migration and retained-history evidence.
- Independent security architecture review remains the production-release
  gate under CYB-173.
