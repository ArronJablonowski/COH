# COH canonical signed action contract v1

| Field | Value |
|---|---|
| Issue | COH-E05-01 / CYB-52 |
| Requirements | FR-012, SEC-006, SEC-009 |
| Manifest schema | `coh.action-manifest/v1` / `1.0.0` |
| Envelope schema | `coh.signed-action/v1` / `1.0.0` |
| Canonical encoding | `COH-CJ-1` |

## Purpose

This contract is the immutable authorization input for a proposed action. It
does not itself authorize dispatch. The broker must still validate identity,
scope, signed policy, approvals, ROE, current credentials, execution-zone
health, audit, evidence, and E-stop state immediately before dispatch.

The existing `coh.domain/v1` action payload remains a lifecycle summary. It
cannot substitute for this approval-grade manifest and is never silently
upgraded into one.

## Bound fields

The manifest binds:

- manifest, workflow-task, organization, tenant, case, requestor, and action
  owner identity;
- action type, operation, T0–T4 tier, exact sorted target and exclusion digest
  sets, and canonical argument digest;
- tool name/version/binary digest and payload/module/image/recipe digest;
- signed policy bundle digest and positive revision;
- ROE digest when applicable;
- credential class and opaque credential-reference digest, using `none` and
  `null` together for credentialless work;
- execution zone and isolation-profile digest;
- validity start/end, one-use nonce, and maximum use count; and
- rollback/compensation digest and safety-watch actor when applicable.

Raw arguments, target values, credentials, capabilities, secret references,
payload bytes, policy content, ROE content, and private keys are not manifest
fields. Their canonical digests or opaque classifications bind them without
copying sensitive or executable content into approval, workflow, or audit
records.

## Canonicalization and signing

The manifest is strictly decoded, semantically validated, encoded with
`COH-CJ-1`, and hashed as `sha256:<lowercase hex>`. Schema-declared sets must
already be sorted and unique; readers reject alternate order rather than
normalizing caller-controlled authority.

The detached Ed25519 signature covers this exact byte sequence:

```text
COH-SIGNED-ACTION-V1\0<canonical manifest bytes>
```

The envelope carries the canonical manifest, its digest, signer actor, positive
signer-key revision, bounded key ID, algorithm `ed25519`, and raw-URL-base64
signature. The signer actor must equal the manifest requestor. Key lookup and
current actor/key authority are supplied by trusted broker composition; fields
inside the envelope cannot manufacture that authority.

Any byte-level change to the canonical manifest, including a changed digest,
target order, policy revision, credential binding, validity, or use count,
invalidates the signature and all downstream approval fingerprints.

## Cross-field rules

- `valid_until` is strictly after `valid_from`; the window is at most 24 hours.
- Target digests are non-empty, sorted, unique, and disjoint from exclusions.
- `credential_class=none` requires a null credential-reference digest; every
  other class requires a digest.
- ROE ID is not carried separately: the immutable ROE digest is the identity
  bound by policy and approval.
- `T4` requires non-null ROE, rollback, and safety-watch bindings and exactly
  one maximum use. T2 and T3 require rollback/compensation. T0 and T1 may bind
  one when policy requires it.
- A service actor may own an action only through separately authenticated actor
  authority; the manifest does not encode roles or permissions.

## Failure and recovery

Malformed, oversized, duplicate-key, unknown-field, non-canonical,
unsupported-version, invalid-scope, invalid-time, invalid-use, or signature
input is rejected before policy evaluation, approval, credential issuance, or
dispatch. Errors expose only stable reason codes and safe digests.

Cancellation or timeout publishes no manifest or signature result. A caller may
retry the same immutable bytes under a fresh context; recovery revalidates from
the beginning and cannot resume partially decoded or partially verified state.

## Compatibility

Compatibility decisions are normative in `compatibility-matrix.md`. Readers
accept only the exact schema pair and canonical profile. Unknown fields,
versions, algorithms, and optional-field reinterpretation deny. Migration
creates a new manifest and lineage record; it never rewrites original signed
bytes or relabels them as v1.

## Residual authority

This leaf defines and verifies the signed action contract. OPA evaluation,
approval fingerprints and lifecycle, T4 dual approval, tamper-evident audit,
and broker dispatch composition are subsequent E05 leaves. Independent
security architecture review remains required before the first production
release.
