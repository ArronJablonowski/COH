# Transactional scoped extension lifecycle v1

| Field | Value |
|---|---|
| Stable key | COH-E25-03 / CYB-184 |
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Signatures | Ed25519 over domain-separated canonical records |
| Requirements | FR-014, FR-015, FR-042, FR-043, SEC-018, SEC-020 |

This contract activates and revokes reviewed signed data-plane extensions as
durable transactions. An extension declares bounded registrations against the
closed capability graph from COH-E25-01 and the active profile from COH-E25-02.
It cannot replace, intercept, or register broker, policy, approval, audit,
credential, evidence, E-stop, runner, connector, or validator authority.

Production agents may resolve and use already-active capabilities through the
broker. They cannot install, activate, deactivate, modify, promote, review,
sign, roll back, or revoke an extension.

## Records

| Schema | Purpose |
|---|---|
| `signed-extension-manifest.schema.json` | Immutable manifest plus independent publisher, reviewer, and owner signatures |
| `extension-activation-intent.schema.json` | Administrator-signed activation/deactivation command bound to exact scope, permissions, mode, profile, policy, qualification, audit, and E-stop state |
| `extension-revocation-handle.schema.json` | Data-only owner-bound idempotent handle for one exact registration |
| `extension-registration-receipt.schema.json` | Durable effect result, ordering identity, scope, handle, and audit binding |
| `extension-lifecycle-transition.schema.json` | Digest-sealed activation/deactivation phase and reverse-unwind cursor |
| `active-extension.schema.json` | Atomic active pointer used to reconstruct the same graph after restart |

All objects are schema-closed. Readers reject duplicate JSON names, trailing
values, invalid UTF-8, excessive size or depth, missing or unknown fields,
unsupported versions, noncanonical timestamps, unsorted set-like arrays,
duplicate logical identities, invalid state/phase combinations, and digest or
signature drift.

## Signed manifest

The manifest is immutable and binds exact extension identity and SemVer,
data-plane kind, owner, artifact/SBOM/provenance/test/threat-model digests,
predecessor, validity, declared permissions and scopes, capability dependencies,
bounded registration declarations, and resource ceilings. Each registration
names one exact capability/version and one provider or consumer role. It carries
no implementation bytes, callback, function pointer, path, URL, endpoint,
credential, policy source, prompt, raw evidence, executor, connector, or mutable
authority object.

The manifest digest is:

```text
sha256("COH-EXTENSION-MANIFEST-V1\0" || COH-CJ-1(manifest))
```

Publisher, reviewers, and owner sign separate domains over the digest bytes:

```text
Ed25519.Sign(key, "COH-PUBLISHED-EXTENSION-V1\0" || manifest_digest_bytes)
Ed25519.Sign(key, "COH-REVIEWED-EXTENSION-V1\0" || manifest_digest_bytes)
Ed25519.Sign(key, "COH-OWNED-EXTENSION-V1\0" || manifest_digest_bytes)
```

All reviewers are independent of the publisher and owner. Verification resolves
current identity, key revision, approval/review revision, purpose, validity,
promotion, qualification, and revocation from command-root authority snapshots.
Identity inside the document never grants authority to its own signature.

## Admission and intent

Before any registration is published, the command root verifies the exact
manifest and all current authority, then binds an activation intent to:

- administrative actor and organization/tenant scope;
- active profile revision, composition digest, and capability graph digest;
- expected lifecycle and registry revisions and active predecessor;
- exact narrowed permission/scope digests and policy, promotion, qualification,
  audit-availability, and E-stop
  snapshots;
- startup, maintenance, upgrade, or separately authorized rollback mode; and
- a bounded drain deadline and idempotency identity.

The intent digest uses `COH-EXTENSION-LIFECYCLE-INTENT-V1\0` over the canonical
intent without its digest and signature. The administrative signature uses
`COH-SIGNED-EXTENSION-LIFECYCLE-V1\0 || intent_digest_bytes`. An E-stop other
than `armed`, unavailable audit, stale profile/registry/policy/qualification,
permission or scope widening, missing dependency, or model/agent actor denies
before the first effect.

## Transactional effects and reverse unwind

The controller persists a sealed `prepared` transition before applying effects.
Registrations are applied in manifest order. Each successful effect returns one
durable receipt and one data-only revocation handle bound to the owner extension,
manifest, transition, registration, scope, registry revision, and generation.
The handle is not callable authority and cannot revoke another owner's effect.

Publication is all-or-nothing. A failure or cancellation switches the durable
transition to `unwinding`; the controller revokes completed effects in strict
reverse ordinal order. Exact retries return the same receipt or handle. Changed
replay, missing receipt, owner mismatch, order mismatch, ambiguous response, or
failure to prove a completed unwind remains fail-closed and not active.

## Deactivation and recovery

Deactivation first prevents new admission for this extension. It then drains or
boundedly cancels owned active work, records terminal work outcomes, revokes only
the owner's registrations in reverse order, commits the terminal audit record,
and atomically removes the active pointer before reporting success. Other
extensions and control-plane services are untouched.

Restart loads the exact sealed transition, signed manifest, active profile, and
registration receipts. It re-verifies current signature, promotion,
qualification, policy, revocation, profile, capability graph, audit, and E-stop
state before replaying the next durable phase. It never infers success from
process memory and never persists executable callbacks or authority objects.

See `compatibility-matrix.md` for interruption, upgrade, rollback, and mixed
version behavior.
