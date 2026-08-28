# Sentinel slicing evaluation contract v1

This is the locked deterministic evaluation contract for CYB-100 /
COH-E14-06 and FR-052, FR-054, EVAL-016. It is intentionally separate from
the frozen CYB-89 connector-truncation release record.

The corpus fixes every task, fixture digest, expected terminal outcome,
ordered trajectory, five-trial count, and exact non-waivable threshold. The
environment pins platform/toolchain, contract and fixture digests, logical
clock, no randomness, and disabled networking. Sanitized recordings model the
typed Sentinel boundary; they contain no credential, endpoint, workspace UUID,
KQL, literal, result row payload, vendor message, or native response body.

`sentinel-slicing-evaluation.schema.json` defines corpus, environment,
recording, trace, grader, threshold, and artifact-manifest records. All objects
are closed. Go readers additionally enforce relationships, ordering,
canonical timestamps, digest recomputation, complete task/trial coverage,
trajectory rules, bounded artifacts, redaction, and byte-identical replay.

The reproduction command is fixed as
`./scripts/verify_sentinel_slicing.sh`. A missing task, trial, boundary,
fixture, digest, or artifact denies the gate rather than reducing its
denominator.
