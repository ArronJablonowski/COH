# Replay, idempotency, and crash-fault evaluation

| Field | Value |
|---|---|
| Issue | COH-E03-06 / CYB-44 |
| Requirements | FR-013, FR-014, EVAL-010, EVAL-011, EVAL-015 |
| Corpus | `coh.replay-fault-corpus/v1`, version 1.0.0 |
| Corpus digest | `sha256:fe2079b238cabb3c0ba358cf9f3da6993cd1e22e965d36c86c1bcc1fc4a7b8cb` |
| Environment | `coh.replay-environment/v1`, version 1.0.0 |
| Environment digest | `sha256:4a08b5f6bb3cdcaca95557821dabaae658169a0cb41f7f6f1aa59da7df170752` |
| Status | Implemented; release evidence pending |

## Purpose and scope

The CYB-44 evaluation proves deterministic control-plane recovery properties at
the M1 workflow, storage, outbox, and consequential-action boundaries. It does
not claim token-identical model replay, contact a target, hold credentials, or
execute a connector. The production broker and connectors arrive in later
epics; this M1 suite establishes the versioned fault contract they must satisfy.

The evaluator combines two evidence layers:

1. Real adapter suites exercise the guarded workflow engine, retained Temporal
   history, SQLite crash/reopen behavior, the shared storage conformance suite,
   and PostgreSQL RLS/concurrency/recovery behavior with the race detector.
2. A credentialless deterministic state-machine harness exercises every
   declared action transition and grades the persisted trajectory after an
   injected crash, timeout, cancellation, denial, response loss, or worker loss.

The second layer is deliberately not a replacement for future connector and
broker tests. Those implementations must run this same corpus with their real
dispatch/reconciliation adapters before a production release.

## Pinned corpus

The corpus contains 31 tasks with five trials each, for 155 trials. Exact source
bytes are compiled into the evaluator by SHA-256 digest. Any byte change,
unknown field, version change, weaker threshold, missing boundary, unregistered
mode, or changed expected result denies loading until the evaluator and corpus
are reviewed together.

The workflow matrix covers the before/after acknowledgement boundary of start,
signal, query, cancel, and replay, plus retained-history replay. The persistence
matrix covers transaction commit acknowledgement, outbox lease commit, and
worker loss/reclaim.

The action matrix covers every state-machine edge declared by PRD §3.3:

`planned → policy_checked → awaiting_approval → prepared → executing → confirmation_pending → verified | compensated | uncertain | denied | cancelled`

Operational sub-boundaries distinguish dispatch-before-receipt,
receipt-before-confirmation persistence, confirmation-before-response,
pre/post-dispatch cancellation, and uncertain-state reconciliation.

## Recovery invariants

- A crash before dispatch may retry only after durable state proves no dispatch.
- A post-dispatch timeout or missing receipt becomes `uncertain`; automatic
  retry freezes and reconciliation is mandatory.
- A receipt recovered before durable confirmation is reconciled by immutable
  action identity and is never redispatched.
- A durable confirmation recovered before response is returned idempotently
  without another dispatch.
- Cancellation before dispatch produces `cancelled` with no effect.
- Cancellation after an indeterminate dispatch produces `uncertain`, not
  cancelled or success.
- Denial persists without dispatch.
- Reconciliation may produce `verified` when the exact effect is proven or
  `compensated` when absence/rollback is proven; uncertainty is never silently
  promoted to success.
- Workflow/storage retries reuse immutable identities and return the original
  execution, commit, signal, cancellation, or lease result where applicable.

## Graders and thresholds

Each trial produces an ordered event trace plus independent outcome and
trajectory grades. The outcome grader compares the observed terminal record to
the locked task expectation. The trajectory grader checks dispatch count,
effect/confirmation consistency, replay, uncertainty, reconciliation, and the
presence of a recovery path.

Release thresholds are exact and non-waivable in v1:

| Metric | Required |
|---|---:|
| Duplicate confirmed effects | 0 |
| False-success states | 0 |
| Reconciliation requirement on applicable trials | 100% |
| Replay success | 100% |
| Outcome grade | 100% |
| Trajectory grade | 100% |

The evaluator writes a denied threshold result before returning a non-zero exit
when any metric misses its requirement.

## Environment and reproducibility

The environment contract pins Go 1.26.7, Temporal SDK 1.45.0/API 1.62.12,
modernc SQLite 1.57.0, pgx 5.10.0, the qualified darwin/arm64 platform, logical
clock/no-randomness behavior, and the exact PostgreSQL 16.14 Alpine image digest.

`scripts/verify_replay_faults.sh` runs all real boundary suites, generates the
seven evaluation artifacts twice in independent directories, and byte-compares
every artifact. It then creates a relative SHA-256 ledger covering the real test
log and generated artifacts. The reproduction command is:

```sh
./scripts/verify_replay_faults.sh
```

The generated evidence consists of:

- actual boundary/race test output;
- normalized corpus manifest;
- environment report with source digests;
- 155 JSON Lines trial traces;
- outcome/trajectory grader report;
- threshold result;
- reproduction command; and
- artifact manifests and SHA-256 ledger.

No wall-clock timestamp, random seed, hostname, absolute path, credential, or
external response enters the deterministic evaluator artifacts.
