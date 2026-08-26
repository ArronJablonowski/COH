# Emergency-stop contract v1

This contract freezes the COH-E06-05 boundary for FR-076, SEC-029, and
EVAL-008. An authenticated, currently authorized operator may activate an
immutable global or case stop. Activation creates a monotonically increasing
epoch and reserves its audit/outbox record atomically before containment is
reported.

The command cannot assert authority. Actor status, actor revision,
authorization, policy, and observation time are trusted control-plane inputs
and are never accepted from command JSON. Global scope applies to every case
in one organization and tenant. Case scope applies only to the exact case.

An active stop independently prevents new credential and runner leases,
revokes outstanding leases, cuts broker-owned runner egress, cancels remote
jobs, signals and cancels durable workflows, and cancels cooperative native,
OCI, and remote execution contexts. The objectives are:

| Control | Objective |
| --- | ---: |
| credential and lease authority | 1 second |
| runner egress | 2 seconds |
| remote jobs and workflow signaling | 5 seconds |
| cooperative termination | 10 seconds |

Each control acknowledgement binds the exact scope and epoch, uses monotonic
elapsed time, records its objective, and contains only a digest of evidence.
Failure or timeout never clears the active stop. It produces an incomplete
containment result with a durable audit record for retry and reconciliation.
Exact activation and control replays are idempotent; changed use of an
idempotency key is denied.

The v1 contract intentionally has no deactivation command. Recovery from an
emergency requires a separately reviewed future contract and cannot mutate or
reuse an activation epoch.
