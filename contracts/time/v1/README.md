# COH time normalization contract v1

`time-normalization.schema.json` freezes the public data contract for CYB-82 /
COH-E11-02, FR-024, and EVAL-017. It validates four independently durable
records:

- `coh.time-normalization-command/v1` binds the case, immutable evidence and
  normalized-event identities, exact source text, parser, timezone assertion,
  clock calibration, evidence state, completeness, idempotency key, and
  deadline;
- `coh.time-normalization-record/v1` retains the interpretation inputs,
  timezone/DST resolution, candidate UTC instants, normalized UTC when one is
  justified, inclusive uncertainty interval, and closed outcome/reason;
- `coh.time-comparison/v1` binds two record digests and returns a closed
  temporal relation with confidence, rationale, and an optional strict gap;
- `coh.time-normalization-receipt/v1` makes command handling, audit, provenance,
  exact replay, and lost-response recovery durable.

Unknown or unresolved time uses an explicit unbounded interval and a null
normalized UTC value. The schema never uses a minimum/maximum timestamp as an
infinity sentinel. Canonical wire timestamps use exactly nine fractional UTC
digits. Signed clock skew is `source clock - reference clock`; normalization
subtracts that skew.

Compatibility, precision, DST, skew, comparison, privacy, migration, recovery,
and rollback semantics are frozen in
`docs/design/time-precision-and-uncertainty.md`.

