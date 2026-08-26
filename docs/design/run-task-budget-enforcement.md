# Run and task budget enforcement

| Field | Value |
|---|---|
| Issue | COH-E08-04 / CYB-65 |
| Requirement | FR-017 |
| Contract | `coh.run-budget/v1` / `1.0.0` |
| Boundary | `internal/workflow/runbudget` |

## Decision

Every agent-loop task obtains a durable reservation from the narrow
`runbudget.Authority` capability before it is persisted as schedulable. The
authority, not the model or provider, enforces integer limits for tokens, cost
micros, elapsed nanoseconds, tool calls, query rows, evidence bytes, delegation
depth, fanout, and concurrency.

A run starts with an immutable, case-scoped plan bound to its policy digest and
provider route. A task supplies limits no greater than the run limits and a
worst-case claim no greater than its task limits. The controller atomically
charges that claim through a durable compare-and-save ledger before returning a
reservation. A failed or ambiguous reservation never authorizes scheduling.

## Accounting model

Tokens, cost, tool calls, query rows, and evidence bytes are cumulative. Their
worst-case claims remain charged after settlement, even when actual use is
lower. This deliberately trades utilization for a fail-closed guarantee:
retries, crashes, and lost commit responses cannot refund capacity and then
spend it again.

Elapsed time is enforced by both the immutable run expiration and a task
deadline no later than the run expiration and no farther away than the task's
wall-time claim. Concurrency is renewable: it is charged by reservation and is
released exactly once after the terminal task state is durable. The ledger
recomputes active concurrency from active reservations on every load.

Delegation depth and fanout are derived from the durable task hierarchy rather
than accepted as independent counters. Root reservations have no parent and
depth zero. A child must reference an existing parent and have depth exactly
one greater. The number of durable children cannot exceed the parent's fanout
claim, and every claim remains bounded by task and run limits.

## Binding and recovery

Canonical SHA-256 digests bind the complete plan, claim, reservation,
settlement, idempotency key, and ledger transition. A task ID can replay only
with the exact original scope, plan, claim, parent, route, deadline, and
idempotency key. Settlement can replay only with its exact original actuals,
outcome, and idempotency key.

The store port requires begin-if-absent and optimistic compare-and-save. A
commit conflict cannot produce two valid reservations. When a commit response
is lost, restart reloads the durable ledger and returns the exact replay instead
of charging or releasing again. The agent loop persists a terminal task before
settlement; if the settlement binding save is interrupted, recovery settles
and binds it without rerunning model or tool work.

Each ledger revision includes the previous provenance digest and a recomputed
digest over all scope, plan, accounting, hierarchy, status, outcome, time, and
revision fields. Invalid totals, hierarchy, ordering, digests, or transitions
fail closed before scheduling.

## Contract and exposure

`contracts/workflow/v1/run-budget.schema.json` freezes strict plan and ledger
records. Decoders reject duplicate, missing, unknown, trailing, malformed, and
oversized data recursively. Published fixtures are exact canonical bytes. The
agent-loop record contract requires only budget plan, reservation, and
settlement digests; it never embeds raw plan or ledger contents.

The public records contain bounded identifiers, tokens, integer counters,
timestamps, typed outcomes, and digests. They contain no prompts, credentials,
provider payloads, tool arguments, targets, policy bodies, callbacks, or raw
dependency errors.

## Workflow cutover

Adding mandatory budget bindings changes the pre-alpha agent-loop record
shape. Existing records without a plan or reservation digest cannot be safely
assigned capacity after the fact, so readers reject them. Before enabling this
build against a non-empty pre-alpha store, operators must drain or cancel old
in-flight runs and restart required work with a reviewed budget plan. The
generic SQLite and PostgreSQL metadata layouts need no DDL change because they
already store canonical run/task bytes and revisions. A future change to either
versioned contract requires a new workflow definition plus replay and migration
evidence.

## Enforcement

- `internal/workflow/agentloop` depends only on `runbudget.Authority` and cannot
  access the controller's durable store.
- Scheduling occurs only after a successful reservation and refuses to advance
  until the prior task's settlement is durably bound.
- Runtime tests cover every dimension, hierarchy derivation, concurrency,
  exact replay, tamper, overflow, cancellation, timeout, corrupted ledgers,
  ambiguous commits, restart recovery, and settlement after terminal state.
- `scripts/verify_run_budgets.sh` verifies contracts and fixtures, repeats the
  focused tests under the race detector, and runs repository static,
  architecture, file-size, link, and diff gates.
