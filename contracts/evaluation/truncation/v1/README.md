# Connector truncation evaluation contract v1

These strict standalone schemas define CYB-89's release-blocking recordings and corpus,
qualified no-network environment, repeated trial trace, independent grader
report, non-waivable threshold result, and reproducible artifact manifest.

The corpus uses sanitized, digest-pinned Elastic and Security Onion semantic
transport recordings. Recordings contain no endpoint, credential, query text,
or production event content and declare network access disabled.
Five trials per task are mandatory. Release requires zero false-complete
decisions, duplicate rows, and missing rows plus 100% replay, outcome-grade,
trajectory-grade, and required-boundary coverage rates. Unknown fields,
versions, fixtures, expectations, thresholds, tasks, trials, or environment
pins fail closed.

Run `scripts/verify_connector_truncation.sh` to execute the locked 21-task,
105-trial corpus, compare two independent artifact sets, enforce the exact
thresholds, and retain checksummed evidence. The protocol and adaptive-slicing
proof requirements are frozen in
`docs/design/connector-truncation-evaluation.md`; qualification evidence is in
`docs/evidence/CYB-89-connector-truncation-report.md`.
