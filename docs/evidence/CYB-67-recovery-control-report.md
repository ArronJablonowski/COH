# CYB-67 recovery, cancellation, and provider fallback verification report

| Field | Value |
|---|---|
| Issue | COH-E08-06 / CYB-67 |
| Requirements | FR-013, FR-014, FR-015, FR-039, NFR-010 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `8c703889e1a0713380b37560d888ea8c70e06c08` |
| Aggregate result | Pass |

## Outcome

COH now has a strict `coh.recovery-control/v1` controller for safe workflow
recovery, durable ordered cancellation, and policy-approved provider fallback.
Recovery resumes only work whose side effect is not indeterminate, preserves
terminal and confirmed outcomes, and makes expired or ambiguous recovery
uncertain rather than successful.

Cancellation persists the entire ordered child-task/tool-job target tree before
propagation. It binds each cooperative command and acknowledgment to exact
scope, provenance, reason, deadline, evidence, and deterministic idempotency.
Missing, invalid, expired, or ambiguous acknowledgments become durable
uncertainty without preventing later targets from receiving cancellation.

Provider routing obtains a policy-owned decision over the exact operation,
input references, budget reservation, route, and time bounds. It re-admits
current qualifications, prevents provider-managed primary state, proves
capability equivalence and equal-or-narrower data exposure, and permits fallback
only after definitive primary unavailability. Every attempt is durable before
invocation and exact replay never duplicates a recorded or indeterminate call.

## Short-task completion mapping

| Task | Authoritative evidence | Result |
|---|---|---|
| 1. Freeze v1 records | Strict schema, Go union, canonical recovery/cancellation/fallback fixtures, bounds, canonical timestamps, intent/idempotency/provenance digests | Pass |
| 2. Classify recovery | Safe resume, terminal preservation, confirmed receipt retention, indeterminate and expired recovery uncertainty tests | Pass |
| 3. Persist cancellation tree | Complete ordered target intent is sealed and stored before any child or tool-job call | Pass |
| 4. Propagate and acknowledge | Narrow child/task ports, exact commands, ordered evidence acknowledgments, ambiguous/lost/deadline tests | Pass |
| 5. Approve provider routes | Route authority receives exact scope, operation, inputs, budget, requested route, and time bounds; decision and qualification digests are durable | Pass |
| 6. Enforce equivalence/exposure | Broader route, downgrade, provider-managed state, policy mismatch, expired approval, and expired qualification are denied before invocation | Pass |
| 7. Persist attempts/replay | Deterministic attempts precede calls; concurrent/lost-begin/lost-save/restart tests prove no duplication | Pass |
| 8. Integrate workflow boundaries | Agent loop recovery adapter, routed model, budget/input/provenance propagation, broker-only action path, and `plan.v2` migration | Pass |
| 9. Add adversarial tests | Strict decoding, recovery, cancellation, routing, outcomes, timeout, tamper, concurrency, and crash windows pass | Pass |
| 10. Run gates and publish evidence | Focused/repeated/race/vet/static/architecture/size/link checks and all 18 clean baseline stages pass | Pass |

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Recovery resumes safe work; cancellation propagates to child tasks/tools; fallback requires approved equivalent route | Controller and agent-loop integration tests plus canonical durable records | Pass |
| Narrow Go interfaces, typed errors, context cancellation, idempotency, no direct policy/executor bypass | Public-boundary reflection test, forbidden-import verifier, deterministic identities, typed dependency errors | Pass |
| Invalid input, denial, timeout/cancellation, and recovery retain provenance without bypass | Strict decoder and validation, chained provenance, durable uncertainty, terminal preservation, route and receipt tamper tests | Pass |
| Success/failure tests pass applicable CI, race, architecture, secret, license, dependency, and size gates | Focused verifier plus 18-stage clean baseline at the checkpoint | Pass |
| Unit/integration, race, trace, and architecture evidence cross-reference the issue and requirements | Retained artifacts, this report, and checksum manifest | Pass |

## Contract and trust boundary

The public schema is
`contracts/workflow/v1/recovery-control.schema.json`, SHA-256
`73f55743e584e3f07f79290bc16ad30a7dabd3d2f76d8b49a3eb324af3eb3622`.
It freezes the union, strict variants, bounded arrays, capability profiles,
route decisions, attempts, work snapshots, cancellation acknowledgments,
artifact references, revisions, and provenance fields. The runtime decoder
recursively rejects unknown, duplicate, missing, nested-missing, trailing,
malformed, oversized, unsupported, or noncanonical records.

Public records carry typed metadata and immutable references only. They contain
no prompt, instruction, raw evidence, credential, secret, connector, executor,
generic callback, or policy/tool authority. The controller owns no direct
external capability; it can call only its store, workflow, cancellation, route,
and provider ports. Authorized tool execution remains behind the agent loop's
broker-owned `ActionAuthority`.

## Recovery and cancellation proof

Recovery inspects the exact case/run/task/provenance/intent before sealing a
decision. Terminal work returns unchanged. An indeterminate effect becomes
uncertain without resume. Safe work first becomes `recovery_prepared`; resume
must preserve identities, intent, and any confirmed receipt. Lost result-save
responses replay the durable result without a second resume. An elapsed
deadline creates durable uncertainty without calling resume.

Cancellation seals all ordered targets before the first call. Each target gets
an exact idempotency key and bound deadline. Acknowledgments are validated and
saved in sequence. A lost save response resumes at the next unacknowledged
target. Ambiguous results and all uncontacted targets after deadline receive
deterministic uncertain evidence/provenance, while later targets still run when
time permits.

## Provider fallback and migration proof

Both primary and fallback capability snapshots and qualifications are admitted
at decision time and retained by digest and durable profile. Fallback must
include every primary role, content kind, state mode, required feature, and
minimum limit; it must support cancellation and cannot broaden exposure from
`air_gapped` to `local` or `approved_external`. Provider-managed primary state
is denied because it cannot move safely between providers.

The primary attempt is durable before invocation. Only typed, definitive
`unavailable` starts a separately persisted fallback attempt. Denied, canceled,
timed-out, failed, invalid-receipt, and indeterminate primary outcomes do not
fall back. An in-flight replay reports conflict; a missing response after the
deadline freezes uncertainty; a persisted success replays without another call.

The expanded planning payload is registered as `coh.agent-loop.plan.v2`. The
frozen agent-loop record and replay-stable lifecycle definition remain v1.
Operators drain queued `plan.v1` activities on their old worker before
registering v2; missing policy, budget, route, input, or time bindings are never
invented. Existing retained lifecycle histories continue to replay.

## Focused verification and adversarial trace

The checkpoint passed `scripts/verify_recovery_control.sh`. Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/recovery-control/run.xNuqmY/recovery-control.log
SHA-256 685ce676f0d5998006f161b6bc59f19566b3172108e5256b13af20c104c2e270
```

The verifier checks schema and fixtures, forbidden fields/imports, the v2
migration binding, focused tests once and three times, race detection, vet,
static analysis, architecture, file size, documentation links, and diff
hygiene. It records the checkpoint with `modified:false`. Architecture reports
66 allowed packages, zero violations, and contract digest
`ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.

The verbose trace names safe/terminal/uncertain recovery, changed intent and
receipt rejection, recovery/cancellation deadlines, ordered child/tool
cancellation, ambiguous and lost acknowledgments, exact route bindings,
exposure/capability/qualification denial, every non-fallback outcome,
concurrent replay, lost commits, tamper, strict decoding, and agent-loop crash
boundaries:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/recovery-control-trace/run.OD7Uhx/adversarial-recovery.log
SHA-256 3764d5358e2eecd637e5cac575ad271e7c39f55ce3eb2153b5eec98f596767ba
```

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.SF0Uuh/quality-report.json
```

Embedded report digest:
`c6ca44eb3944b488572acb6f3dcb569a16baaf7ccebda74358a4968f10e0ca08`.
Report-file SHA-256:
`790788a37944ad73dbe083f7f92f2188a890c8ec6ac4f958bfb9f84489aed81b`.
Provenance records 1,036 source files, source digest
`e33d0125056fdd565fb6c51fc43037fb70d433216a92344c9ab3064d7f742dca`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_recovery_control.sh
./scripts/run_ci_quality.sh baseline
```

## Migration and residual scope

- Deployments must compose durable store, workflow, tool-job cancellation,
  route-authority, and provider-invocation adapters at the narrow ports.
  Generic SQLite/PostgreSQL metadata layouts require no schema migration.
- An uncertain external effect or acknowledgment is intentionally not retried
  or upgraded; operators reconcile it from retained evidence.
- Queued `plan.v1` activities must drain on the old worker before the v2
  activity registration cutover.
- Independent security architecture review remains the first-production-release
  gate under CYB-173.
