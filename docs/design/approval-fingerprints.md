# Approval fingerprints

## Decision

COH-E05-03 defines a deterministic SHA-256 fingerprint over length-framed
canonical action-manifest bytes and canonical verified intent-policy decision
bytes. The contract is frozen in `contracts/approval/v1`.

The fingerprint is an approval identity, not approval authority. It does not
record a grant, approver, lifecycle state, remaining uses, or revocation
status. Those mutable controls belong to CYB-51 and CYB-48.

## Boundary inventory

| Input | Owner | Fingerprint use |
|---|---|---|
| Canonical signed action | `internal/domain/actionmanifest` | Supplies verified immutable bytes and action/scope bindings |
| Policy decision | `internal/policy` | Supplies verified positive intent decision and current actor/policy provenance |
| Credential reference | Signed action manifest | Class and opaque reference digest change action bytes |
| Tool and execution scope | Signed action manifest | Tool name/version/digest, execution zone, and isolation digest change action bytes |
| Validity and use count | Signed action manifest | Any time-window or maximum-use change creates a new fingerprint |
| Audit | E05 narrow port, finalized by CYB-49 | Creation/verification cannot succeed if its event cannot append |
| Approval state | CYB-51 | Must combine fingerprint match with current unused, unexpired, unrevoked grant state |

## Threat assumptions

Serialized fingerprint records, workflow/model claims, policy-decision structs,
and candidate approval state are attacker-controlled. The verified action
envelope, recomputed policy-decision digest, broker clock, and audit sink are
trusted only after their owning boundary validates them.

The adversary may reuse a valid fingerprint with changed action bytes, alter
one digest, substitute scope, replay a consumed grant, change a credential or
tool, exploit concatenation ambiguity, use a denied/pre-dispatch decision, race
verification with lifecycle changes, cancel the request, or fail audit.

Length framing and domain separation make the preimage unambiguous. Exact
replay remains exact identity by design but conveys no grant; lifecycle code
must atomically reject stale state after fingerprint verification.

## Safe output and redaction

The record repeats UUID scope, manifest and policy-decision digests, policy and
ROE digests, validity, and maximum use count for early mismatch detection and
audit. It never contains raw canonical inputs, targets, exclusions, arguments,
payloads, credential identifiers or values, policy source, prompts, evidence,
or signer key material.

## Follow-on composition

CYB-51 stores and consumes grants keyed by this fingerprint with optimistic
concurrency. CYB-48 adds two distinct eligible non-requestor approvers for T4.
CYB-47 must run again immediately before dispatch; the broker compares the
current action/policy bindings and current approval state before issuing a
credential lease. CYB-49 persists the resulting decision chain.
