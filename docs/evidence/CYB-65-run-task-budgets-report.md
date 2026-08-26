# CYB-65 run and task budgets verification report

| Field | Value |
|---|---|
| Issue | COH-E08-04 / CYB-65 |
| Requirement | FR-017 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `66e3e12c18bc08ac7013eb0f99e9cd4efcc9fbb5` |
| Aggregate result | Pass |

## Outcome

COH now enforces run and task budgets outside the model before an initial or
successor agent-loop task can be scheduled. The narrow `runbudget.Authority`
atomically reserves worst-case capacity for tokens, cost micros, elapsed
nanoseconds, tool calls, query rows, evidence bytes, delegation depth, fanout,
and concurrency through a durable begin/compare-and-save ledger.

Cumulative claims remain charged after settlement, preventing retries or
ambiguous commits from refunding and spending capacity twice. Only active
concurrency is renewable and it is released exactly once after terminal task
state is durable. Root/child depth and parent fanout are reconstructed from the
ledger rather than trusted as model-supplied counters.

The agent loop binds the plan digest to the run and reservation/settlement
digests to every task. Lost reservation or settlement responses replay exact
durable results. Recovery completes an interrupted settlement binding without
repeating model or broker work.

## Short-task completion mapping

| Task | Authoritative evidence | Result |
|---|---|---|
| 1. Freeze budget records | `coh.run-budget/v1` schema, canonical plan/ledger fixtures, strict wire decoder, domain-separated digests | Pass |
| 2. Validate all limits | Integer vectors and per-layer validation for all nine dimensions, zero/overflow/binding rejection | Pass |
| 3. Build narrow durable authority | `runbudget.Authority`, private controller dependencies, begin-if-absent and compare-and-save `Store` contract | Pass |
| 4. Reserve before scheduling | Agent-loop start/schedule call the authority before state creation/save; exhaustion creates no schedulable task | Pass |
| 5. Bind exact reservation | Plan, case, run, task, parent, activity, policy, route, deadline, vectors, and idempotency digests | Pass |
| 6. Settle exact actual usage | Actuals cannot exceed claims; cumulative usage remains charged; only concurrency releases; changed replay is denied | Pass |
| 7. Integrate recovery boundaries | Start, schedule, execute, terminate, resume, and settlement-binding transitions enforce budget state | Pass |
| 8. Preserve typed/redacted outcomes | Invalid-input, denial, conflict, cancellation, timeout, unavailable, and internal codes; no raw causes in records | Pass |
| 9. Add adversarial tests | Success, every dimension, hierarchy, concurrent CAS, replay, tamper, overflow, crash/restart, cancellation, timeout | Pass |
| 10. Run gates and publish evidence | Focused/repeated/race/vet/static/architecture/size/link checks and all 18 clean baseline stages | Pass |

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Token, cost, elapsed-time, tool-call, query-row, evidence-byte, delegation-depth, and fanout budgets are enforced before scheduling | Reservation occurs before `StateStore.Create`/`Save`; per-dimension and agent-loop integration tests prove no task state on denial | Pass |
| Narrow Go interface, typed errors, cancellation, idempotency, and no policy/executor bypass | `Authority` exposes only reserve/settle; verifier forbids action/infrastructure imports; exact replays and context tests pass | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance and policy binding | Strict validation, immutable policy/route/plan bindings, chained ledger provenance, ambiguous-commit and restart tests | Pass |
| Automated success/failure tests pass applicable CI, race, architecture, secret, license, dependency, and size gates | Focused verifier plus 18-stage clean baseline at the verified checkpoint | Pass |
| Unit/integration, race, trace, and architecture evidence cross-reference COH-E08-04 and FR-017 | Retained logs, clean quality report, this report, and checksum manifest | Pass |

## Contract and trust boundary

The public schema is `contracts/workflow/v1/run-budget.schema.json`, SHA-256
`1aa5eb9241817e798297c48889c9ef780a9f545709f42258695cdc0f7e7526c3`.
It freezes plan and ledger records with exact versions, UUIDv7 scope, bounded
tokens and signed-64-bit-compatible integer limits, canonical timestamps,
typed outcomes, and explicit state-dependent settlement fields.

The decoder recursively rejects unknown, duplicate, missing, malformed,
trailing, oversized, unsupported, or noncanonical input. Durable records
contain resource counters, identifiers, timestamps, typed outcomes, and
digests only. They contain no prompt, evidence body, target, tool argument,
credential, price text, provider response, policy body, executor, connector,
callback, or raw dependency error.

The agent-loop boundary receives only `runbudget.Authority`; it cannot access a
controller or ledger store. Model phase contracts do not contain budget-plan,
task-limit, claim, parent-authority, or settlement controls. Policy and
provider route are inherited from trusted run state for every successor.

## Accounting and hierarchy proof

Reservation charges the worst-case cumulative claim before returning. Ledger
validation reconstructs charged totals and active concurrency from every
reservation, recomputes plan/reservation/settlement/provenance digests, and
denies any mismatch. A concurrent test starts two reservations against a
single concurrency slot and proves exactly one succeeds and only one durable
record exists.

Root reservations require an empty parent and depth zero. A child must name an
existing durable parent and its depth must equal the parent depth plus one.
Child counts are reconstructed and denied when the parent's fanout claim is
exhausted. Elapsed enforcement rejects expired plans, deadlines after run
expiration, and deadlines farther away than the task wall-time claim.

Settlement records actual usage only within the reserved vector. Lower actual
usage does not reduce cumulative charges. Active concurrency releases once;
an exact settlement replay returns the same digest, while a different key,
actual vector, outcome, task, scope, or reservation digest is denied.

## Replay, crash, and workflow recovery proof

The ledger store contract serializes creation and updates with durable
begin-if-absent and optimistic compare-and-save operations. Tests simulate a
persisted reservation whose response is lost, reconstruct the controller, and
prove the same reservation is returned without a second charge. They repeat
the scenario for settlement and prove concurrency is not released twice.

The agent loop persists terminal task state before settlement. If settlement
succeeds but binding its digest to the task is interrupted, `Resume` reloads
the terminal state, replays the deterministic settlement, writes the missing
binding, and leaves model/tool call counts unchanged. A successfully scheduled
successor also replays exactly after a lost response; changed input or budget
claims are denied.

## Focused verification and adversarial trace

The checkpoint passed `scripts/verify_run_budgets.sh`. Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/run-budget.9mpwjt/run-budget.log
SHA-256 70b848412b5b2381bb465050a18060dd1f00ad87c1999403dc992aa2f5429708
```

The verifier checks schemas and fixtures, capability/import boundaries,
focused tests once and three times, race detection, vet, static analysis,
architecture, file size, documentation links, and diff hygiene. Architecture
verification reports zero violations and contract digest
`ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.

The verbose trace names the reservation/settlement replay, concurrent CAS,
elapsed/depth/fanout/concurrency denial, tamper/scope/overflow, crash/restart,
cancellation/timeout, pre-schedule agent-loop denial, and settlement-recovery
cases:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/run-budget-trace.I9UHl0/adversarial-recovery.log
SHA-256 9eb3b3044f9e3c3058dafd152fa3ee3be0d380cfd339ea7bd498b813673cd2aa
```

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.nMp7oi/quality-report.json
```

Embedded report digest:
`a0908c37387e2c5a6fb59417b0ba92f40eb37f688b25337e43364d2c6c3ae01f`.
Report-file SHA-256:
`5005978488bab1c44db1455429c283b5cfaf9bffa7c4452ccab9e5c5cddd1598`.
Provenance records 994 source files, source digest
`062d034093ee55f6fe614372912771aa14b60c8ca10d90e41f7af52086c9cc7b`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_run_budgets.sh
./scripts/run_ci_quality.sh baseline
```

## Migration and residual scope

- Budget-bound agent-loop records are a fail-closed pre-alpha cutover. Old
  in-flight records without budget digests must be drained or canceled and
  required work restarted with a reviewed plan; capacity is never invented.
- Generic SQLite/PostgreSQL metadata layouts need no DDL change. Concrete
  deployments must supply a durable store implementing the atomic ledger port.
- Capacity lost to an unresolved durable-store failure is conservative and
  requires operator reconciliation; the controller never guesses that it is
  safe to refund.
- Independent security architecture review remains the production-release
  gate under CYB-173.
