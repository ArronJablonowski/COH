# Connector truncation evaluation contract v1

These strict standalone schemas define CYB-89's release-blocking corpus,
qualified no-network environment, repeated trial trace, independent grader
report, non-waivable threshold result, and reproducible artifact manifest.

The corpus uses sanitized, digest-pinned Elastic and Security Onion fixtures.
Five trials per task are mandatory. Release requires zero false-complete
decisions, duplicate rows, and missing rows plus 100% replay, outcome-grade,
trajectory-grade, and required-boundary coverage rates. Unknown fields,
versions, fixtures, expectations, thresholds, tasks, trials, or environment
pins fail closed.

The executable corpus and verifier are added by the subsequent CYB-89 tasks.
The protocol and adaptive-slicing proof requirements are frozen in
`docs/design/connector-truncation-evaluation.md`.
