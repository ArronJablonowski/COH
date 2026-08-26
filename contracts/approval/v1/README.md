# COH approval contract v1

| Field | Value |
|---|---|
| Issues | COH-E05-03 / CYB-50; COH-E05-04 / CYB-51; COH-E05-05 / CYB-48 |
| Requirements | FR-005, SEC-006, SEC-007, SEC-008, SEC-009, SEC-040, EVAL-005, EVAL-007 |
| Fingerprint | `coh.approval-fingerprint/v1` / `1.0.0` |
| Lifecycle | `coh.approval-lifecycle/v2` / `2.0.0` |
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

## Lifecycle record

CYB-51 introduced the lifecycle state machine. CYB-48 migrates its current
writer to `coh.approval-lifecycle/v2` so every grant also binds the manifest
action tier, stable human principal identity, and enrollment revision. The
record is persisted inside the registered
`coh.domain/v1` `approval` envelope. The payload schema is
[`approval-lifecycle.schema.json`](../../domain/v1/approval-lifecycle.schema.json),
and the executable transition contract is documented in
[`approval-lifecycle-state-machine.md`](approval-lifecycle-state-machine.md).

The record binds the approval identifier and exact fingerprint/manifest/policy
decision digests to organization, tenant, case, requestor actor and principal,
action owner/tier, validity window, approval threshold, and maximum use count.
Each transition records its optimistic revision and fresh acting identity
revision. Grant history is append-only and contains distinct actor and stable
human-principal identities plus enrollment revisions.

The domain registry mapping to the current lifecycle payload is the policy and
audit schema migration. Lifecycle v1 records lack stable-principal enrollment
proof and are never treated as T4 authority; they must be re-requested under
v2. Existing
SQLite and PostgreSQL stores require no DDL migration because their generic
versioned record and transactional outbox schemas already support the
registered `approval` kind. A deployment must apply the contract reader/writer
change before writing lifecycle records; no reader may reinterpret the legacy
provisional payload as an active grant.
