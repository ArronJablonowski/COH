# Recovery, cancellation, and provider fallback

Status: CYB-67 / COH-E08-06 design freeze

Contract: `coh.recovery-control/v1`

Requirements: FR-013, FR-014, FR-015, FR-039, NFR-010

## Purpose

COH must recover interrupted workflow work without turning an unknown external
effect into a retry, cancel a run across child tasks and tool jobs while
retaining evidence, and use a fallback model provider only when a policy-owned
route decision proves that the alternative is qualified, equivalent, and no
more exposed than the primary route.

The controller is orchestration, not authority. It accepts narrow capabilities
for durable storage, workflow inspection/resume, child cancellation, tool-job
cancellation, route approval, and provider invocation. It has no connector,
credential, policy evaluator, shell, network, or generic callback capability.

## Durable control record

One strict tagged union records recovery, cancellation, or fallback. Every
record binds:

- organization, tenant, case, run, task, control, and idempotency identities;
- the exact request intent and policy digest;
- canonical nanosecond UTC timestamps and a bounded deadline;
- monotonically increasing revision and chained provenance digests; and
- only bounded references, digests, classifications, decisions, attempts, and
  acknowledgments—never prompts, evidence bytes, credentials, or callbacks.

The decoder rejects unknown, duplicate, missing, malformed, oversized, and
trailing data. The store validates every loaded record and every transition.
Changed requests cannot reuse a control identity or idempotency identity.

## Recovery classification

The controller first inspects the exact case, run, task, expected provenance,
and intent. It then applies this fail-closed classification:

| Observed state | Side effect | Result |
| --- | --- | --- |
| terminal | any valid terminal evidence | Preserve the terminal state; never resume |
| pending/running | indeterminate | Persist `uncertain`; require reconciliation |
| pending/running | confirmed | Preserve the receipt; never duplicate the effect |
| pending/running | none | Persist `recovery_prepared`, then resume idempotently |

Recovery may not convert failed, denied, canceled, timed-out, or uncertain work
to success. A resumed result must retain the original identities, intent,
provenance relationship, and any confirmed receipt. If the state save response
is lost, replay loads the durable result instead of invoking resume again.
If the recovery deadline has elapsed after preparation, the controller persists
uncertainty and does not call resume.

## Durable cancellation tree

Cancellation receives an already ordered list of child-task and tool-job
targets. Target sequence, identity, kind, and expected provenance are part of
the cancellation intent. The complete intent is persisted as
`cancellation_active` before any cancellation command leaves the controller.

Each command carries an exact deterministic idempotency key, root run/task
binding, reason digest, target binding, and deadline. Each acknowledgment binds
its target, outcome, evidence, and provenance. Acknowledgments are persisted in
order before the next target is contacted. Lost save responses therefore
resume at the next unacknowledged target rather than repeating acknowledged
work.

Definitive `canceled` and `already_terminal` acknowledgments are retained.
Malformed, ambiguous, or failed acknowledgments become `uncertain`, and the
controller continues to later targets. If the deadline is exhausted, every
remaining target receives a durable uncertain acknowledgment. The aggregate
result is complete only when every target is definitive; otherwise it is
uncertain and requires reconciliation. Existing audit and evidence references
remain intact.

## Policy-approved provider fallback

The workflow supplies a trusted model request containing the exact durable run,
operation, policy digest, requested route, sorted input references, budget
reservation digest, creation time, and deadline. A route authority—not the
controller—returns the primary and fallback routes, approval digest, validity
window, and validated capability and qualification records for both providers.

The controller independently re-admits both qualifications at the current
time, recomputes their durable profiles, and denies the route before invocation
unless all of these invariants hold:

- decision, policy, requested route, approval, and validity window are bound;
- primary and fallback routes differ;
- neither capability nor qualification is expired or malformed;
- the primary does not require provider-managed conversation state;
- the fallback supports every primary role, content kind, state mode, feature,
  and minimum limit required by the operation;
- fallback cancellation is supported; and
- fallback data exposure is equal or narrower: `air_gapped < local <
  approved_external`.

The approved profiles, qualification digests, operation, input references,
budget reservation, and decision are written before provider invocation. The
attempt identifier is deterministic from control ID, sequence, route, and
capability digest.

Only a definitive primary `unavailable` outcome permits fallback. Denial,
cancellation, timeout, failure, an invalid receipt, or an indeterminate result
never crosses to the fallback route. A persisted pending attempt is reported as
in progress before its deadline. If no durable response exists after the
deadline, it becomes uncertain and is not invoked again. A lost success-save
response replays the stored success without provider duplication.

## Agent-loop integration and migration

The recovery adapter inspects and resumes the existing durable agent loop. An
authorized action still passes through `ActionAuthority`; recovery never calls
a connector directly. Dispatch without a durable broker receipt is
indeterminate. Child cancellation delegates to the loop's terminal transition,
and dispatching action cancellation becomes uncertain rather than pretending
the external action stopped.

The routed model maps the agent loop's trusted model request into fallback
control. The expanded payload is registered as `coh.agent-loop.plan.v2`. The
persisted `coh.agent-loop/v1` record and replay-stable `coh.agent-loop.v1`
lifecycle workflow do not change. Operators drain queued `plan.v1` activities
on the old worker before registering v2. Missing v1 bindings are never
fabricated, and retained lifecycle histories continue to replay.

## Verification and operations

`scripts/verify_recovery_control.sh` checks the strict schema and representative
records, forbidden fields and imports, exact integration behavior, repeated and
race-enabled tests, vet, static analysis, architecture, file-size policy,
documentation links, and whitespace. Adversarial tests cover crash windows,
changed replay, receipt mutation, cancellation ambiguity, lost save responses,
concurrent attempts, expired approvals and qualifications, provider-managed
state, broader exposure, capability downgrade, route tampering, and every
outcome that must not fall back.

An uncertain result is an operational reconciliation item, never an automatic
retry authorization. Production rollout must also satisfy the independent
security architecture review tracked as the first-release gate.
