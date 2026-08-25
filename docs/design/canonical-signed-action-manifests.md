# Canonical signed action manifests

## Purpose

CYB-52 defines the immutable action identity that later E05 policy, approval,
audit, credential, and broker boundaries consume. The contract separates an
action's authorization-relevant facts from mutable workflow state and from raw
arguments, credentials, payloads, or target values.

The manifest schema is `coh.action-manifest/v1` / `1.0.0`; the detached
signature envelope is `coh.signed-action/v1` / `1.0.0`. Both use `COH-CJ-1`
canonical JSON.

## Boundary and ownership

The existing `coh.domain/v1` action record describes lifecycle state such as
planned, awaiting approval, executing, verified, or uncertain. It remains a
persisted operational record. The signed manifest instead defines the exact
immutable action to which policy decisions and approvals bind. Neither record
is silently converted into the other.

The manifest owns scope and requested capability facts: organization, tenant,
case, requestor, action owner, action type/tier/operation, targets, exclusions,
argument digest, tool/version/binary digest, payload digest, policy
digest/revision, ROE digest, credential class/reference digest, execution zone,
isolation profile, validity, nonce, use count, rollback, and safety watch.

Trusted runtime boundaries independently own current actor/key state, policy
bundle verification, approval eligibility/consumption, credential resolution,
zone attestation, audit durability, evidence health, E-stop state, and actual
dispatch. A signed manifest is necessary input, never bearer authority.

## Canonical identity

`Decode` bounds input to 64 KiB, rejects duplicate keys, unknown fields,
trailing data, excessive representation, non-integer JSON numbers, missing
required nullable fields, invalid identifiers/digests/timestamps, unsorted or
duplicate sets, and cross-field safety violations. It then returns defensive
copies of canonical bytes and a SHA-256 manifest digest.

Targets and exclusions are caller-supplied semantic sets. They must already be
sorted and unique and must be disjoint. Rejecting rather than silently sorting
preserves evidence that the writer understood the canonical contract and
prevents alternate input order from being mistaken for a separate approved
action.

Credentialless work uses `credential_class=none` with a null reference digest.
All other classes require an opaque reference digest. T2/T3 require rollback or
compensation. T4 additionally requires ROE, safety-watch, and exactly one use.
The maximum validity window is 24 hours; policy may require a shorter window or
one use for any tier.

## Signature authority

`Verify` signs the exact domain-separated bytes
`COH-SIGNED-ACTION-V1\0 || canonical_manifest`. Only Ed25519 is accepted in v1.
The envelope's manifest digest must match recomputation, and signer actor must
equal requestor. Current actor, key ID, key revision, active state, and public
key arrive through independent `SignerAuthority`; envelope fields cannot
manufacture them.

Validated and verified results keep internal ownership of slice-backed values
and byte buffers. Accessors return defensive copies so a caller cannot mutate
the object whose digest or signature succeeded.

## Downstream use

1. A durable workflow proposes and persists a canonical manifest.
2. Current signer authority verifies the detached envelope.
3. OPA evaluates the exact digest and bound fields at intent creation.
4. Approval fingerprints bind this digest plus current policy/ROE obligations.
5. Immediately before dispatch, the broker re-verifies signature/current
   authority, reevaluates policy, consumes applicable approval and use state,
   obtains audit/evidence reservations and scoped leases, and dispatches only
   through its typed adapter.
6. Any changed bound field creates a new manifest identity and requires fresh
   policy and approval.

FR-012 action-state transitions are persisted by the workflow and broker leaves;
the manifest freezes identity across those transitions. An uncertain or
dispatched action cannot acquire a new identity to justify automatic retry.

## Failure and recovery

Malformed or semantically denied input produces stable safe reason codes and no
canonical result. Signature, digest, signer, key revision, algorithm, and
requestor substitution deny. Cancellation and timeout publish nothing. A fresh
context may revalidate the same immutable input from the beginning; no partial
decoder or verifier state survives.

The contract contains no logging, network, process, filesystem, runtime, or
secret-resolution capability. A source-surface test enforces that property.

## Compatibility and migration

The explicit compatibility matrix denies unknown fields and versions. Optional
fields are not assumed safe merely because JSON permits omission. Canonical or
signature-domain changes are cryptographically breaking. Migration preserves
the original signed bytes and emits a separately signed new-version manifest
with lineage; it never rewrites approval history.

Syntactically bounded tool, target, credential-class, and execution-zone tokens
are preserved exactly, but signed policy must default-deny any unregistered
capability. Contract syntax is not a capability registry.

## Verification

Run:

```sh
./scripts/verify_action_manifests.sh
```

The verifier checks the schema bundle, canonical and signed fixtures, 24-case
denial corpus, compatibility matrix, unit/race/vet/static analysis, source
surface, and architecture contract.

## Residual scope

OPA evaluation, approval fingerprinting/lifecycle, T4 dual approval,
tamper-evident audit, and final broker composition are subsequent E05 leaves.
Independent security architecture review remains required before the first
production release.
