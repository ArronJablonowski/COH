# Emergency-stop containment

## Purpose and requirements

CYB-57 implements FR-076, SEC-029, and EVAL-008. A global or case stop must
revoke execution authority without relying on a workflow, model, runner, or
tool to cooperate. The control is fail-closed and keeps the stop active when
any containment hook, audit delivery, or acknowledgement fails.

The timing objectives are measured with monotonic elapsed time from each
control invocation: lease authority in one second, runner egress in two,
remote jobs and durable workflows in five, and cooperative execution in ten.

## Activation boundary

`internal/broker/estop.Controller` accepts a canonical command and a separate
trusted authority snapshot. The command cannot assert actor state,
authorization, or policy. The store atomically creates an immutable,
monotonically increasing stop epoch and reserves its activation audit/outbox
record. This makes the stop effective before audit delivery or containment
fan-out can fail.

Activation is exact-replay idempotent. Reusing the idempotency key with a
changed command conflicts. A different activation cannot replace an already
active stop. v1 intentionally provides no deactivation operation.

`SQLiteStore` persists stop epochs, state, activation replay records, control
acknowledgements, and the audit outbox atomically for single-node deployments.
It refuses startup unless SQLite is configured for WAL journaling, FULL
synchronous durability, and a bounded busy timeout. `MemoryStore` remains a
process-local reference implementation. A multi-replica deployment must use a
durable, linearizable implementation of the same store contract before it can
claim production qualification.

## Authority denial and revocation

Credential and runner-lease brokers require an authoritative `StopGuard` in
their constructors. They read current global/case state before issuance and
again after atomically claiming an outstanding capability. A stop-state
outage is unavailable, never allowed. Claimed capabilities are consumed before
the callback or credential resolver can run.

Activation controls bulk-revoke every outstanding credential and runner lease
in the exact scope. Repeated application is idempotent and emits the same
evidence digest for a scope and epoch.

## Egress containment

The OCI executor requires `ContainmentNetworkBroker`, so an arbitrary network
broker cannot bypass registration. Every broker-owned network lease is
registered before runtime execution and wrapped in one-time cleanup. A second
stop read after registration closes the acquire/activation snapshot race.

The egress control selects exact global/case entries, invokes cleanup
independently of the runner, waits only until its two-second context deadline,
and records a digest of the affected lease identifiers. Cleanup failure or
timeout produces an incomplete containment acknowledgement.

## Remote jobs and workflows

Remote-worker dispatch registers the active callback with a private cancellable
context. The remote-job control cancels affected contexts within the five-second
fan-out. The cooperative control waits for callback completion until its
ten-second deadline. Dispatch rechecks stop state before recording success, so
a callback that ignores cancellation cannot turn a stopped operation into a
successful completion.

`workflow.GuardedEngine` requires current stop state and a `WorkflowIndex`,
tracks active durable workflow targets, and closes the start/activation race.
Its workflow control sends an `emergency_stop` signal and then cancellation to
every exact-scope target. Regular cancellation remains usable while a stop is
active.

`SQLiteWorkflowIndex` persists active targets for supported single-node
deployments and rejects unsafe SQLite durability configuration. Restart tests
reconstruct the guarded engine and prove that a workflow started by the prior
process is still enumerated, signaled, canceled, and removed. Multi-replica
deployments must provide a linearizable implementation of the same index port.

## Cooperative native and OCI execution

Native and OCI constructors require an `executionstop.Tracker`. The tracker
checks stop state before and after registration, supplies the context used by
the execution boundary, and cancels exact-scope contexts on activation. It
waits for cleanup/completion until the ten-second deadline. Both executors
recheck authoritative state before recording success.

## Audit, evidence, and recovery

Every activation and control acknowledgement is redacted and digest-bound to
the scope and epoch. Audit append uses a bounded context independent of caller
cancellation. Failed delivery remains in the outbox and is recovered through
`RecoverAudit`; audit consumers must deduplicate on decision digest because a
mark-delivered failure can cause safe redelivery.

Control acknowledgements report `applied`, `failed`, or `timeout`, their
monotonic elapsed nanoseconds, objective nanoseconds, and an evidence digest
only for applied controls. Partial containment never rolls back activation.

## Verification

`scripts/verify_estop.sh` validates the public schemas, executes unit, repeat,
race, vet, architecture, and file-size gates, and runs the timing conformance
tests. The harness inspects all 1/2/5/10-second deadlines and exercises an
actual one-second timeout using monotonic elapsed time.

SQLite covers the supported single-node restart path for both stop state and
active workflow enumeration. Multi-replica deployments require linearizable
implementations of the `estop.Store` and `WorkflowIndex` ports before making a
multi-replica production claim.
