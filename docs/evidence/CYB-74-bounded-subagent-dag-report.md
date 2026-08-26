# CYB-74 bounded subagent DAG verification

| Field | Value |
|---|---|
| Stable key | COH-E09-05 |
| Requirements | FR-016, FR-040, FR-041 |
| Implementation commit | `1dd7ce1fbd800fb965e3768f5c63272ff1e052c8` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI report digest | `b1d5b29bb1d0efee74938ca8f2c42fbc8e85eb4f2ea26a2f908698621db42719` |
| CI report file SHA-256 | `22e5e3cd0d99cb2d5cadc55bca8ac5229d02e064c167182633fca2fc1e6b5f00` |
| Focused verifier log SHA-256 | `e26dbc5866028134e0d480a1fd4d0875e61402742920e0360004ddde54cb0290` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.MO3AU8/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB74.dkPbuh/bounded-subagent-dag.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.MO3AU8/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.MO3AU8/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.MO3AU8/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.MO3AU8/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.MO3AU8/ci-provenance.json`

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Strict v1 records | `subagent-dag.schema.json` closes graph, task, edge, cancellation, decision, claim, finding, result, artifact, receipt, and limit objects. Contract tests compare every canonical wire field, version, operation, and role to the published schema. |
| Closed role catalog | The only roles are coordinator, alert triage, SIEM query, timeline/correlation, hunting, CTI/ATT&CK, detection, vulnerability, validation, IR planner, reviewer, and report writer. Tests delegate every specialized role and validate typed results for all 12 roles. |
| Exact scope and graph bounds | Creation and delegation bind organization, tenant, case, run, graph, task, actor revision, policy, route, inputs, parents, assignment, and deadline. Tests deny invalid requests, foreign parents, cycles, depth, fanout, concurrency, total-task capacity, deadline, and graph limits greater than the run-budget plan. |
| External run-budget authority | The controller depends only on `runbudget.Authority`. Root and child reservations occur before schedulable persistence, plan/reservation digests are bound into graph/task provenance, concurrent losing reservations are never prematurely refunded, and only durable terminal tasks are settled. The real run-budget controller denies an over-budget child in SQLite integration. |
| Durable optimistic store | The `subagent_dag` repository uses exact case-scoped keys, canonical envelopes, strict decoding, prior revision plus provenance comparison, immutable graph identity, append-only tasks/edges/receipts/cancellations, legal task transitions, and idempotent transactions. Tests deny stale state, cross-scope reads, destructive yet internally valid rewrites, changed replay, duplicate receipts, corrupt cancellation bindings, and lost-response replay. |
| Narrow runtime | `Runtime.RunChild` receives only graph ID, task ID, closed role, immutable input digests, assignment digest, and deadline. Reflection and import gates prohibit actor, policy, approval, credential, connector, broker, tool, executor, shell, HTTP, callback, transport, provider, and policy capability exposure. |
| Structured evidence results | Every successful result binds the exact task and role to an immutable JSON artifact and at least one claim or finding. Evidence, counterevidence, basis-point confidence, unknowns, recommended next steps, completeness, negative-result status, runtime digest, and result digest are bounded and validated. Malformed output becomes a durable denied terminal task. |
| Cancellation and recovery | Cancellation durably records the complete subtree before calls, orders deepest descendants first, binds every acknowledgement to the resulting task, blocks new work beneath active cancellation, settles terminal tasks, and resumes interrupted exact plans. Dispatching work recovers as uncertain without rerun; pending work remains safe to schedule. |
| Cancellation and timeout semantics | Explicit cooperative cancellation is the only path to `canceled` and requires evidence/provenance acknowledgement. Caller cancellation persists `uncertain`, since it cannot prove an external child stopped. Elapsed child deadlines persist `timeout` without runtime dispatch. |
| Crash, replay, and concurrency | SQLite close/reopen tests recover completed results without redispatch and recover a persisted dispatching child as uncertain after a simulated lost process response. Repeated and race tests cover concurrent delegation conflicts and exact recovery of the reserved losing child. |
| Documentation and migration | The design documents scheduling, authority, budget accounting, typed outputs, cancellation, crash recovery, storage, cutover, and fail-closed rollback. Generic SQLite/PostgreSQL metadata storage requires no DDL change; older binaries reject the new kind. |

## Requirement trace

- **FR-016:** delegation is a durable case-scoped DAG with configurable maximum
  depth, fanout, concurrency, task count, graph/task deadlines, and an external
  total run-budget binding.
- **FR-040:** the catalog contains exactly the 12 required analytical roles;
  every child uses the same narrow data-only runtime capability.
- **FR-041:** all roles return bounded typed claims/findings carrying evidence,
  confidence, counterevidence, unknowns, recommended next steps, completeness,
  and immutable result/provenance bindings.

## Verification summary

The focused verifier passed strict schema and wire synchronization, all-role
delegation/results, identity and every graph bound, real budget denial, narrow
runtime reflection/import checks, malformed/tampered/stale/changed input,
lost responses, concurrent scheduling, cancellation, caller cancellation,
deadline timeout, recovery, two SQLite restart paths, repeated execution, race
detection, vet, static analysis, architecture, file-size, link, and clean-diff
checks.

The clean baseline then passed all 18 required stages: format, file-size,
workflow, worktree/history/evidence secret scans, architecture, quality
contract, vet, static analysis, unit, race, fuzz seeds, license,
dependency/vulnerability, SBOM, supply chain, and provenance. The report binds
the exact clean implementation commit and is promotable. No unresolved
blocking finding remains for CYB-74.
