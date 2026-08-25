# CYB-44 replay, idempotency, and crash-fault verification report

| Field | Value |
|---|---|
| Issue | COH-E03-06 / CYB-44 |
| Requirements | FR-013, FR-014, EVAL-010, EVAL-011, EVAL-015 |
| Verification date | 2026-08-25 |
| Implementation checkpoints | `a8e2d47`, `8c22121`, `5db19c3` |
| Corpus | `coh.replay-fault-corpus/v1` 1.0.0 |
| Corpus digest | `sha256:fe2079b238cabb3c0ba358cf9f3da6993cd1e22e965d36c86c1bcc1fc4a7b8cb` |
| Environment digest | `sha256:4a08b5f6bb3cdcaca95557821dabaae658169a0cb41f7f6f1aa59da7df170752` |
| Review status | Local technical evidence complete |

## Outcome

The M1 control plane now has a versioned, default-deny replay and crash-fault
evaluation. It runs real Temporal, SQLite, and PostgreSQL recovery/race tests
and a credentialless deterministic consequential-action state model. The
corpus contains 31 tasks with five repeated trials each, covering every current
workflow/storage/outbox boundary and every normative PRD §3.3 action-state edge.

All 155 committed trials passed. The results contained zero duplicate confirmed
effects, zero false-success states, 100% reconciliation requirements on every
applicable path, 100% replay success, and 100% outcome and trajectory grades.
Every generated evaluation artifact was reproduced byte-for-byte in an
independent output directory.

No trial contacted a target, loaded a credential, invoked a connector, or
relaxed a threshold. Later broker and connector implementations must adopt this
same corpus with their real dispatch and reconciliation adapters before a
production release.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Every workflow/action boundary covered | Exact 31-task corpus, complete boundary registry, missing-boundary denial test | Pass |
| Exactly-once confirmation | 155 traces; duplicate-confirmed metric 0; confirmation-before-response replay does not dispatch | Pass |
| Uncertain-state handling | Every post-dispatch indeterminate/cancel path persists `uncertain`, freezes retry, and requires reconciliation | Pass |
| Deterministic replay | Retained Temporal history test plus two independent byte-identical artifact generations | Pass |
| Pinned corpus/environment | Corpus and environment versions plus compiled source digests and exact dependency/image versions | Pass |
| Tasks and repeated trials | 31 named tasks, five trials each, 155 JSON Lines traces | Pass |
| Outcome/trajectory graders | Independent exact-outcome and invariant-based trajectory grades recorded per trace | Pass |
| Locked thresholds | Zero/100% exact thresholds validated in code and JSON Schema; weaker-threshold mutation denied | Pass |
| Invalid input/tamper | Unknown fields, changed expected result, changed source bytes, missing boundary, and unsupported mode deny loading | Pass |
| Denial | Policy-denial trial persists denial with zero dispatch/effect | Pass |
| Timeout/cancellation | Pre/post-dispatch timeout and cancellation trials plus guarded Temporal context tests | Pass |
| Recovery | Real retained-history, SQLite crash/reopen, PostgreSQL timeout/recovery, idempotency, and lease-reclaim suites | Pass |
| Applicable CI gates | Clean 18-stage baseline including unit, race, architecture, secrets, licenses, dependencies, SBOM, and provenance | Pass |

## Boundary coverage

Workflow tasks inject faults before and after acknowledgement for `Start`,
`Signal`, `Query`, `Cancel`, and `Replay`, plus retained-history worker loss.
Storage tasks inject failure around transaction commit, commit response, outbox
lease commit, and worker-loss lease recovery.

Action tasks cover:

`planned → policy_checked → awaiting_approval → prepared → executing → confirmation_pending → verified | compensated | uncertain | denied | cancelled`

They additionally separate dispatch-before-receipt,
receipt-before-confirmation persistence, confirmation-before-response,
pre/post-dispatch cancellation, and uncertain-state reconciliation. A crash
before dispatch may retry only after durable proof of no dispatch. Any
indeterminate post-dispatch path becomes `uncertain` and cannot retry
automatically. A durable confirmation is returned after restart without a new
dispatch.

## Trial and grader evidence

The clean evaluation run at checkpoint
`5db19c35df8d253b3bd4a6501cf7449b11633946` produced:

- 31 tasks and 155 trials;
- 0 duplicate confirmed effects;
- 0 false-success states;
- reconciliation rate 1.00;
- replay rate 1.00;
- outcome-grade rate 1.00; and
- trajectory-grade rate 1.00.

`artifact-manifest.json` binds the normalized corpus, environment report,
grader report, threshold result, reproduction command, and trace stream. The
relative `all-artifacts.sha256` ledger also binds the real adapter/race output.
All ledger entries reverified successfully.

## Real implementation evidence

Before grading the deterministic action model, the reproduction script runs the
race detector against:

- the guarded workflow engine and all invalid/denial/cancel/timeout recovery
  cases;
- the Temporal adapter, lifecycle idempotency, changed-signal denial, and
  retained `coh.operation.v1` history;
- SQLite abrupt-process recovery and shared storage conformance;
- PostgreSQL transaction/outbox concurrency, forced RLS, timeout recovery,
  backup denial, role denial, and shared conformance; and
- the evaluator's contract mutation, artifact checksum, and determinism tests.

The exact official PostgreSQL 16.14 Alpine image digest is part of the
environment contract. The test container uses a random loopback port and tmpfs
storage and is removed after the run.

## Baseline evidence

The clean implementation checkpoint passed all 18 baseline stages with report
digest `306830adf487462e65b058103d5ec5c051441a7d8570665711ad5de59a559194`
and `quality_gate_promotable=true`. The dependency stage approved 95 exact
modules and found zero vulnerabilities. The license stage approved all module
licenses and shipped inputs. The architecture gate covered 26 packages with
zero violations.

A final clean baseline and evidence attachment set are produced after this
report and its repository checksum ledger are committed.

## Reproduction

```sh
./scripts/verify_replay_faults.sh
```

## Residual scope

- This M1 harness establishes the action recovery contract but cannot substitute
  for real broker/connector dispatch tests. Those arrive in later epics and
  must execute the same versioned corpus before production qualification.
- Broader process, object-store, network, provider, runner, upgrade, RPO/RTO,
  and disaster-restoration coverage belongs to COH-E23-03.
- Independent security architecture review remains required before the first
  production release as the approved non-blocking follow-up.
