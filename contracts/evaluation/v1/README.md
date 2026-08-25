# Replay and crash-fault evaluation contract

This directory pins the COH-E03-06 / CYB-44 release-blocking corpus and its
qualified environment. The corpus covers every currently implemented workflow,
storage, outbox, and declared consequential-action boundary without contacting
an external target.

The v1 corpus contains 31 tasks, and each task runs five deterministic trials.
The fixed thresholds require zero
duplicate confirmed effects, zero false-success states, and 100% reconciliation,
replay, outcome-grade, and trajectory-grade success where applicable. Unknown
fields, versions, modes, boundaries, relaxed thresholds, missing coverage, or
changed expected outcomes deny the evaluation.

Run `scripts/verify_replay_faults.sh` to execute the real Temporal, SQLite, and
PostgreSQL recovery suites and generate the deterministic trial artifacts.
