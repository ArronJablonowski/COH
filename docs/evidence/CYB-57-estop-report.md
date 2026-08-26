# CYB-57 containment and E-stop verification report

| Field | Value |
|---|---|
| Issue | COH-E06-05 / CYB-57 |
| Requirements | FR-076, SEC-029, EVAL-008 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `a7ea676d96c917c148a81a3fd12ccfadf96e0eb1` |
| Aggregate result | Pass |

## Outcome

COH now has an authenticated, policy-authorized, immutable global/case
emergency stop whose epoch and audit outbox are committed atomically before
containment fan-out. An active stop independently rejects new credential and
runner leases, revokes outstanding leases, cuts broker-owned OCI egress,
cancels remote jobs, signals and cancels durable workflows, and cancels
cooperative native, OCI, and remote execution contexts.

The control does not depend on a model, workflow, tool, or runner granting
authority. Every consequential constructor requires current stop state or a
containment-aware dependency. Missing or unavailable stop state fails closed.
Activation, control execution, and audit records bind the exact organization,
tenant, global/case scope, and monotonic epoch.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Reject new leases within 1s, cut egress within 2s, signal workflows within 5s, terminate cooperative work within 10s | Controller deadlines, mandatory guards/trackers, timing acknowledgements, deterministic deadline probes, and actual one-second timeout test | Pass |
| Default-deny actor/scope binding, redaction, fail-closed audit, replay/tamper/stale/revocation handling | Strict command schema/decoder; separate trusted authority; immutable epoch; atomic SQLite state/outbox; typed errors; exact replay/collision, audit outage, scope, and corruption tests | Pass |
| Invalid input, denial, timeout/cancellation, partial failure, and recovery preserve provenance | Adversarial controller tests, control acknowledgement decisions, incomplete-containment result, audit recovery, capability consumption, and SQLite restart tests | Pass |
| Success and failure automation passes applicable CI, race, architecture, secret, license, dependency, supply-chain, and size gates | Dedicated verifier plus all 18 clean baseline stages at `a7ea676` | Pass |
| Evidence cross-references COH-E06-05 and FR-076/SEC-029/EVAL-008 | This report, public contract, design record, retained verifier log, baseline report, and checksum manifest | Pass |

## Canonical command and authority

`contracts/estop/v1` freezes strict schemas for command, state, control
acknowledgement, and decision output. The Go decoder canonicalizes input,
rejects unknown/duplicate/trailing fields, bounds size, and validates exact
global/case scope. The command cannot assert actor activity, actor revision,
authorization, policy, or freshness. Those facts are separate trusted
control-plane inputs.

Activation verifies the actor and exact scope, current authorization and
policy decisions, and a freshness-bounded observation. It atomically writes
an immutable active state with a monotonically increasing epoch and reserves
the activation audit record. Exact retries return the original decision;
changed reuse conflicts. An active stop cannot be replaced. v1 intentionally
has no deactivation operation.

E-stop activation does not require a model- or workflow-provided approval.
Operator authentication, authorization, and policy are mandatory, and their
decision digests are persisted in state and every audit-facing decision.

## Independent containment controls

Credential and runner-lease brokers require an authoritative stop guard.
Issuance checks before capability creation. Use checks after atomic claim, so
an outstanding capability presented after activation is consumed before any
secret resolution or runner callback. Activation controls also bulk-revoke
all outstanding leases in the exact scope.

The OCI executor requires a containment-aware network broker. Every acquired
network lease is registered and wrapped in idempotent cleanup; a second state
read closes the acquisition/activation race. The egress control invokes
cleanup independently and reports failure or timeout rather than assuming the
runner complied.

Remote dispatch registers a private cancellable context. Separate remote-job
and cooperative controls request cancellation and wait for completion. A
callback that ignores cancellation cannot record success because dispatch
rechecks current stop state before its terminal decision.

The guarded durable workflow engine requires both current stop state and a
workflow index. It records targets before returning from start, closes the
start/activation race, and sends an `emergency_stop` signal followed by
cancellation. Native and OCI constructors similarly require a cooperative
execution tracker whose context reaches the sandbox/runtime boundary.

## Timing conformance

The controller uses a fresh deadline and monotonic elapsed timer for every
independent control. The conformance harness verifies:

| Control kind | Objective | Result |
|---|---:|---|
| credential / lease | 1 second | Pass |
| egress | 2 seconds | Pass |
| remote job / workflow | 5 seconds | Pass |
| cooperative termination | 10 seconds | Pass |

All acknowledgement `objective_nanos` values match the contract. Applied
controls complete below their deadline. A deliberately blocking credential
control is cut off at the one-second deadline, records `timeout` and
`control_timeout`, and leaves the stop active with `containment_incomplete`.

## Audit, denial, and partial failure

Activation audit reservation is in the same atomic store transaction as the
active epoch. Each control acknowledgement produces a redacted, digest-bound
decision with objective and monotonic elapsed time. An audit delivery outage
does not undo activation or skip containment; pending activation and control
records recover from the durable outbox. Audit delivery is retry-safe by
decision digest.

Tests cover denied/stale authority, invalid and duplicate command input,
changed idempotency collisions, concurrent activation, caller cancellation,
audit outage and recovery, control failure, control timeout, invalid evidence,
global/case isolation, stop-store outage, capability replay, and callbacks or
executions that fail to cooperate.

## Restart durability

The supported single-node implementation stores E-stop epochs, active state,
activation replay records, control acknowledgements, and audit outbox entries
in SQLite. It refuses startup unless WAL, FULL synchronous durability, and a
bounded busy timeout are active. Restart tests prove:

- the stop remains effective with the original epoch and request digest;
- exact activation replay returns the original decision without rerunning
  controls;
- every pending activation/control audit is delivered once and marked;
- subsequent activation advances the epoch; and
- corrupt persisted state fails closed.

The SQLite workflow index likewise survives guarded-engine reconstruction and
enumerates, signals, cancels, and removes a workflow started by the prior
process. Unsafe configuration fails closed.

## Focused verification

The clean checkpoint passed `scripts/verify_estop.sh`. The retained log is:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/estop.aI6tk0/estop.log
SHA-256 f61ae4e649ebe803240c3306c880b34f0756480d3fb8e441ce878722e263afc9
```

It includes unit, three repeated runs, race, vet, schema/secret checks,
54-package architecture verification with zero violations, file-size checks,
and the dedicated timing harness. Provenance records `a7ea676`,
`modified:false`, Go 1.26.7, and darwin/arm64.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.5x3xZG
```

The embedded report digest is
`c6a565c6701b7473d24b61e35aea0b5473aa381ce8810aa22fad3d3371eaa306`;
the report-file SHA-256 is
`2afb4fb78fcd3baab54352520e388d924ba49334c931cdb8abb31659e4ee5c0e`.
Provenance records 721 source files, source digest
`16d55d6a99c90112b39dd2f2417318beaaf01aa5864ac0f7800e33a89fc18890`,
Go 1.26.7 on darwin/arm64, and the exact clean revision.

## Reproduction

```sh
./scripts/verify_estop.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- SQLite is the supported durable single-node profile. Multi-replica
  deployment requires linearizable implementations of `estop.Store` and
  `WorkflowIndex`; the code does not claim SQLite is a distributed consensus
  boundary.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
