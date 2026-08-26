# Pre-dispatch integration gate

| Field | Value |
|---|---|
| Issue | COH-E05 / CYB-10 |
| Requirements | FR-005, FR-012, SEC-003, SEC-004, SEC-006 through SEC-009, SEC-020 through SEC-022, SEC-040, EVAL-005 through EVAL-007, EVAL-013 |
| Boundary | `internal/broker` only |
| Audit source | `coh.pre-dispatch/v1` |

## Purpose

COH-E05 composes its six completed child controls into the only path that can
produce consequential pre-dispatch authority. The result is an unexported,
non-serializable value. Workflows, transports, models, and composition roots
cannot construct it or receive the policy evaluator, approval consumer, ROE
proof verifier, or audit appender used to produce it.

The public `broker.Authority` implementation remains intentionally absent.
COH-E06 will make the isolated dispatch boundary consume the private result
directly. Exposing a partial workflow authority before that consumer exists
would create a route around the gate.

## Mandatory order

For every T2, T3, or T4 authorization attempt, the gate performs these steps:

1. Re-verify the canonical signed action envelope against the current requestor
   key authority. Any byte change produces no downstream call.
2. Validate the current requestor actor and evaluate the active signed policy
   with phase `pre_dispatch` and current runtime facts.
3. Verify the returned decision digest, exact action, policy, actor, signer,
   scope, and call-time timestamp. An intent decision is never dispatch proof.
4. When an ROE digest is present—and mandatorily for T4—obtain a fresh
   cryptographically verified proof for the exact digest and scope.
5. Rebuild the approval proof with the newly verified envelope, then atomically
   consume the exact approval. T4 consumption revalidates both enrolled human
   principals and denies either requestor or principal aliasing.
6. Durably append the final authorization reservation to the tenant audit
   chain. Only a successful append returns the private capability.

No later step runs when an earlier step fails. The final audit record binds the
manifest, intent decision, pre-dispatch decision, approval fingerprint and
revision, and applicable ROE digest. It contains no target bytes, arguments,
payload, credential, policy source, ROE document, public key, or secret.

## Temporary signed-ROE boundary

COH-E19-01 owns the actual signed ROE document schema and key-resolution
implementation. COH-E05 does not invent that schema early. Its broker-private
port accepts an exact digest/scope/time expectation and returns only a verified
proof containing:

- digest, organization, tenant, and case;
- ROE revision and exclusive validity window;
- exact broker verification time; and
- active Ed25519 signer key identity and revision.

The gate independently checks every returned field. The future COH-E19 adapter
must implement cryptographic document verification before returning this proof.
Until that adapter and the rest of T4 execution exist, no public dispatch
authority is available.

## Replay and failure semantics

Approval consumption happens before the final audit reservation because an
unused approval must never survive a possibly committed dispatch reservation.
If audit append fails after consumption, the gate returns no authority and the
approval stays consumed. A retry recovers the exact lifecycle result as
`replayed=true`; the gate treats that as denial, durably records the denial when
audit has recovered, and still returns no authority. A new manifest and
approval are required.

Cancellation after approval consumption follows the same conservative rule.
The gate uses a detached, bounded audit context to record the canceled terminal
result but returns no capability. Cancellation or timeout before verification
produces no downstream call. COH-E06 owns post-dispatch uncertainty and
exactly-once reconciliation; this gate cannot be reused as evidence that an
external effect happened.

## Verification

`scripts/verify_predispatch_gate.sh` runs real Ed25519 action verification, the
real approval-fingerprint engine, the durable approval lifecycle, T2–T4 success
tests, one-byte mutation, stale policy and identity, scope expansion, invalid
ROE, missing or colliding T4 approvers, approval replay, audit outage,
cancellation, timeout, race, vet, architecture, and file-size gates.
