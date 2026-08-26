# Durable agent loop

This package owns the engine-neutral `coh.agent-loop/v1` state machine. A run
starts with one pending typed activity, persists `running` or `dispatching`
before invoking an external port, and persists the resulting reference,
receipt, denial, failure, cancellation, timeout, or uncertainty before the
state is returned as complete.

Successful steps leave the run in `waiting`; another typed step may be
scheduled or the run may be completed. Planning can safely resume from a
persisted `running` state. An authorized action in `dispatching` without a
durable receipt becomes `uncertain` on recovery and is never automatically
replayed. Completed and terminal runs return idempotently.

The loop calls only the narrow `runbudget.Authority` capability before it
persists an initial or successor task. Run records bind the immutable budget
plan digest; task records bind reservation and terminal settlement digests. A
successor cannot be scheduled until the prior task is terminal and its
settlement is durable. Recovery completes a missing settlement binding without
repeating model or tool work.

State is stored as canonical run/task metadata through the guarded repository.
Each optimistic transaction writes the run plus current task and one outbox
event atomically. Only bounded immutable references and digests are retained.
The records use the strict `coh.domain/v1` common envelope and validate against
both the domain run/task payload contract and the narrower agent-loop schema.
The repository rejects illegal state transitions in addition to revision and
scope conflicts.

`Activities` exposes exactly two versioned Temporal-compatible methods:
`coh.agent-loop.plan.v2` invokes `ModelProvider` with the exact durable run,
operation, policy, provider-route, input-reference, budget-reservation, and
time bindings needed by recovery-controlled provider routing, and
`coh.agent-loop.authorized-action.v1` submits a digest-bound `ToolIntent` to
`ActionAuthority`. The Temporal adapter registers those exact immutable names.
There is no connector, runner, credential, shell, HTTP, generic callback, or
policy-engine dependency in this package.

Budget-bound records are a fail-closed workflow cutover. Records written by the
earlier alpha shape without budget digests are rejected rather than assigned
invented capacity. Before enabling this build against a non-empty pre-alpha
store, operators must drain or cancel old in-flight runs and restart required
work with a reviewed `coh.run-budget/v1` plan. No SQL migration is required;
the generic metadata adapters already persist canonical run/task records.

The planning activity v2 cutover does not change the frozen agent-loop record
shape or the replay-stable `coh.agent-loop.v1` lifecycle workflow. Operators
must drain `coh.agent-loop.plan.v1` activity tasks on the old worker before
deploying workers that register v2. New and resumed planning work then uses v2;
v1 payloads are never widened by inventing missing policy, budget, route, or
deadline bindings.

`coh.agent-loop.skill-discovery.v1` is the separate progressive skill activity.
Its only dependency exposes compact search, exact detail expansion, and exact
resource resolution. Each method preserves the discovery controller's
case/task/policy/deadline and idempotency boundaries. The activity cannot
promote, revoke, execute, fetch arbitrary content, or reach a connector. The
older exact `skill-lookup` adapter remains a registry integration boundary but
is not the agent-facing discovery route.
