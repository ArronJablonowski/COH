# COH signed OPA policy contract v1

| Field | Value |
|---|---|
| Issue | COH-E05-02 / CYB-47 |
| Requirements | SEC-003, SEC-004 |
| Policy bundle | `coh.opa-policy-bundle/v1` / `1.0.0` |
| Signed envelope | `coh.signed-opa-policy-bundle/v1` |
| Evaluation input | `coh.policy-input/v1` |
| Decision output | `coh.policy-output/v1` |
| OPA | `v1.17.0`, Rego v1 |

## Purpose

This contract makes one signed OPA policy bundle the active authorization
policy for one organization and tenant. The broker evaluates the same verified
canonical action when an intent is created and again immediately before
dispatch. Only the latter decision may authorize dispatch.

The policy engine cannot grant authority by itself. Fresh identity, capability,
validator, E-stop, action-manifest, policy-key, time, and scope checks execute
outside Rego and default-deny before the signed policy is evaluated.

## Qualified bundle profile

- one COH-CJ-1 canonical JSON envelope, at most 1 MiB, described by
  `signed-opa-policy-bundle.schema.json`;
- one nested policy bundle described by `opa-policy-bundle.schema.json`,
  containing 1–32 sorted, uniquely named Rego v1 modules, each at most 256 KiB,
  plus one bounded JSON data object;
- exactly one Ed25519 signature over
  `COH-SIGNED-OPA-POLICY-V1\0 || canonical_bundle_bytes`;
- a SHA-256 digest of those same canonical bundle bytes, and the fixed
  entrypoint `data.coh.authz.decision`;
- source Rego only: no Wasm, plan, archive extraction, filesystem loading,
  network access, runtime extension, or embedded trust material; and
- a closed deterministic builtin set. Network, time, random, UUID, JWT,
  tracing, print, crypto, DNS, GraphQL, and nondeterministic builtins do not
  compile.

COH rejects duplicate JSON keys, non-integer JSON numbers, unknown envelope or
bundle fields, malformed module paths, digest mismatch, and signature mismatch
before OPA parses or compiles Rego. The out-of-band Ed25519 trust root must be
active and match the envelope key ID and positive key revision. The active
snapshot stores no private key, signature, or raw envelope bytes.

## Activation and recovery

Loading is bounded, verifies the signature and bundle digest, validates exact
metadata and tenant scope, compiles the fixed entrypoint, and appends a safe
activation audit event before one atomic publication. A failed load leaves the
last-known-good bundle unchanged. Revision rollback, same-revision replay,
cross-tenant replacement, expired/future bundles, inactive keys, and changed
key revisions deny.

One engine instance is tenant-scoped after its first activation. A different
organization or tenant requires a separately composed engine instance.

## Evaluation

Every evaluation uses fresh broker time and fresh out-of-band signer authority.
Before Rego runs, COH requires:

- a verified `coh.signed-action/v1` envelope whose policy digest and revision
  exactly match the currently active canonical policy bundle;
- exact organization, tenant, case, requestor, and current actor scope;
- an active actor with sorted unique roles and permissions;
- a registered tool, authorized target set and tenant, authorized data route,
  known capability fields, qualified validator, and inactive E-stop; and
- current action and bundle validity windows.

The immutable input described by `policy-input.schema.json` contains only the
safe action manifest, exact digests, scoped identity metadata, current runtime
facts, and active bundle identity. It never contains raw targets, arguments,
credentials, policy source, private/public keys, prompts, or evidence bytes.

Rego must return exactly one object with exactly `allow`, `reason_code`, and
`approval_required`. Undefined, multiple, malformed, or evaluation-error output
denies or becomes unavailable. Every result receives deterministic input and
decision digests and must be appended to audit. Audit failure changes the
effective outcome to `unavailable`; an allowed Rego result cannot bypass it.

## Immediate pre-dispatch rule

An intent-phase decision is planning evidence only. Broker composition must
invoke the evaluator with phase `pre_dispatch` after loading all current
identity, policy-key, capability, validator, E-stop, approval, credential, and
execution facts. Dispatch consumes that fresh decision digest, not the
intent-phase result. Any bundle replacement or signer revocation makes an old
action manifest stale and forces a new manifest, policy decision, and approval.

## Residual authority

CYB-50 binds approvals to canonical manifest and policy-decision bytes. CYB-51
owns approval state, CYB-48 owns T4 dual approval, and CYB-49 owns the final
tamper-evident audit sink. Those controls compose with this evaluator; none may
weaken its default-deny preconditions.
