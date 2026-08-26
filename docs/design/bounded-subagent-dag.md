# Bounded subagent DAG

| Field | Value |
|---|---|
| Issue | COH-E09-05 / CYB-74 |
| Requirements | FR-016, FR-040, FR-041 |
| Contract | `coh.subagent-dag/v1` / `1.0.0` |
| Boundary | `internal/workflow/subagentdag` |

## Decision

COH represents analytical delegation as one durable, case-scoped directed
acyclic graph. The graph fixes maximum depth, fanout, active concurrency, total
tasks, and a graph deadline. A child can be scheduled only after current
authorization and an external `runbudget.Authority` reservation. The graph
stores only immutable input and output references, canonical digests, typed
state, and provenance; it never gives a child direct broker, connector,
credential, policy, approval, tool, shell, or network authority.

The closed role catalog is coordinator, alert triage, SIEM query,
timeline/correlation, hunting, CTI/ATT&CK, detection, vulnerability,
validation, IR planner, reviewer, and report writer. There is exactly one root,
and it is the coordinator. Every other task has one or more existing parents.
Its depth is derived as one more than the deepest parent, every parent consumes
one fanout slot, and the stored edge set must exactly equal the parent lists.
These rules make cycles, detached tasks, hidden edges, and model-selected limit
changes invalid records rather than scheduler preferences.

## Scheduling and authority

Create, delegate, execute, cancel, and recover requests bind organization,
tenant, case, graph, task, actor revision, policy digest, exact assignment, and
deadline into canonical authorization intents. Returned decisions are
recomputed and must match every requested field, current time, revocation
digest, and operation. A denial or malformed, expired, canceled, timed-out, or
unavailable decision creates no child work.

The coordinator reserves its run-budget plan before the graph exists. Each
child reserves its worst-case claim before it becomes schedulable. A known
optimistic graph conflict never refunds the losing reservation: its cumulative
claim remains charged and its concurrency remains conservatively occupied
until an exact retry can bind the task or the run expires. This fail-closed
choice avoids treating an ambiguous commit or a settled reservation as fresh
capacity. Exact retry reloads durable state. Terminal tasks bind their external
settlement digest after the terminal state is durable, and recovery repairs a
missing settlement without rerunning the child.

`Runtime.RunChild` receives only graph ID, task ID, closed role, immutable input
digests, assignment digest, and deadline. It cannot authorize, approve, route,
or execute tools. The caller deadline is applied to the runtime. If the caller
is canceled, COH records the child as uncertain because cancellation alone
cannot prove that an external child stopped. Only the explicit cancellation
protocol can record `canceled` with a typed acknowledgement.

## Typed analytical results

Every role returns the same strict `StructuredResult`. It binds the task and
role to an immutable JSON artifact and at least one typed claim or finding.
Each claim and finding carries evidence references, counterevidence,
basis-point confidence, explicit unknowns, and recommended next steps.
Completeness and negative-result fields prevent absence of output from being
silently interpreted as success. Results with unknown fields, unsorted or
duplicate references, missing evidence or next steps, invalid confidence,
wrong role/task binding, non-JSON artifacts, or an invalid canonical digest are
durably denied and never released as successful output.

## Cancellation and recovery

Cancellation first persists the complete affected subtree and reason as an
active cancellation plan. Targets are ordered deepest descendant first, then
by task ID, so dependents are stopped before their parents. Each narrow
`Canceler` call produces a typed acknowledgement with evidence and provenance;
the acknowledgement and task transition are persisted before the next target.
Dependency failure leaves the active plan durable, and an exact retry resumes
at the first unacknowledged target. A completed plan is either fully completed
or explicitly uncertain.

A task is persisted as `dispatching` before runtime invocation. After a crash,
`pending` means the runtime was never invoked and remains safe to schedule;
`dispatching` means the result is indeterminate and recovery changes it to
`uncertain` without redispatch. Succeeded, failed, denied, canceled, timed-out,
and uncertain tasks are terminal. Exact receipts prevent an external operation
from being applied twice, while every task and graph transition chains its
previous provenance digest.

## Durable storage and rollout

The repository stores one canonical `subagent_dag` metadata record under the
exact organization, tenant, case, and graph identity. Writes require the exact
prior revision and provenance digest, preserve immutable graph configuration,
and reject noncanonical, unknown, oversized, cross-scope, stale, or corrupt
records. The generic SQLite/PostgreSQL metadata layout needs no DDL change.
SQLite integration closes and reopens the database after a successful child
and proves exact replay returns the durable result without redispatch.

Cutover must enable the `subagent_dag` kind, contract, run-budget authority,
authorization implementation, runtime, and canceler together. No prior record
can be upgraded in place because it lacks the frozen graph and provenance
bindings. Rollback disables new delegation and drains or cancels active graphs
before running an older binary. Older binaries reject the unknown record kind,
so retained records fail closed and remain available for forward recovery.

## Verification

`scripts/verify_bounded_subagent_dag.sh` checks schema closure and the exact
12-role catalog, narrow dependency surfaces, persistence integration, contract
synchronization, all-role results, bounds, replay, malformed output, deadlines,
caller cancellation, descendant-first cancellation, recovery, concurrent
reservation conflicts, SQLite restart, repeated execution, race detection,
vet, static analysis, architecture, file-size, links, and clean diffs.
