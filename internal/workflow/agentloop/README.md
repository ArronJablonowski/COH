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

State is stored as canonical run/task metadata through the guarded repository.
Each optimistic transaction writes the run plus current task and one outbox
event atomically. Only bounded immutable references and digests are retained.
The records use the strict `coh.domain/v1` common envelope and validate against
both the domain run/task payload contract and the narrower agent-loop schema.
The repository rejects illegal state transitions in addition to revision and
scope conflicts.

`Activities` exposes exactly two versioned Temporal-compatible methods:
`coh.agent-loop.plan.v1` invokes `ModelProvider`, and
`coh.agent-loop.authorized-action.v1` submits a digest-bound `ToolIntent` to
`ActionAuthority`. The Temporal adapter registers those exact immutable names.
There is no connector, runner, credential, shell, HTTP, generic callback, or
policy-engine dependency in this package.
