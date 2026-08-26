# COH approval fingerprint contract v1

| Field | Value |
|---|---|
| Issue | COH-E05-03 / CYB-50 |
| Requirements | SEC-006, SEC-009, EVAL-005 |
| Fingerprint | `coh.approval-fingerprint/v1` / `1.0.0` |
| Hash | SHA-256 |

## Purpose

An approval applies to one exact verified action and one exact positive intent
policy decision. The approval fingerprint is stable for those inputs and
changes if either input changes. It contains only safe identifiers, digests,
bounded validity/use metadata, and no raw target, argument, credential,
payload, policy source, prompt, evidence, or secret material.

The signed action manifest already binds organization, tenant, case, requestor,
owner, action type/tier/operation, sorted targets and exclusions, arguments,
tool name/version/digest, payload, policy/revision, ROE, credential
class/reference digest, execution zone, isolation profile, validity, nonce,
maximum use count, rollback, and safety watcher. Fingerprinting its canonical
bytes therefore binds every approval-sensitive action field without copying
those fields into an approval record.

## Preimage

The v1 fingerprint is:

```text
SHA-256(
  "COH-APPROVAL-FINGERPRINT-V1\0" ||
  uint64be(len(canonical_manifest_bytes)) ||
  canonical_manifest_bytes ||
  uint64be(len(canonical_policy_decision_bytes)) ||
  canonical_policy_decision_bytes
)
```

The manifest must be a `coh.signed-action/v1` envelope reverified during the
operation against the fresh out-of-band signer key, revision, and active state.
The policy decision must be a self-consistent `coh.policy-decision/v1`
decision with a valid decision digest, outcome `allowed`, phase
`intent_created`, `approval_required=true`, and exact manifest,
policy/revision, requestor, organization, tenant, and case binding.

The fingerprint record repeats only safe scope and lifecycle fields so later
approval and audit code can reject cross-scope substitution before comparing
the fingerprint in constant time.

## Verification and lifecycle boundary

Verification recomputes the preimage from a fresh verified action envelope and
verified policy decision. Unknown fields, malformed digests, unsupported
versions, negative policy outcomes, pre-dispatch decisions, missing approval
requirements, scope mismatch, expired/not-yet-valid actions, and fingerprint
mismatch deny.

Exact input replay intentionally reproduces the same fingerprint; CYB-51 owns
request/grant state, idempotency, expiry, consumption, revocation, optimistic
concurrency, and use counters. CYB-48 adds two distinct approvers for T4.
Neither leaf may treat fingerprint equality as an unused grant.

Creation and verification are broker-owned operations with mandatory redacted
audit. Audit failure yields no usable success result. Cancellation or timeout
before completion fails closed; a fresh call may recompute the same
fingerprint because the operation has no hidden mutable state.
