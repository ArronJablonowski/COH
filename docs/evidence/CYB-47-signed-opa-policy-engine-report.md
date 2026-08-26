# CYB-47 signed OPA policy engine verification

| Field | Evidence |
|---|---|
| Stable key | COH-E05-02 |
| Requirements | SEC-003, SEC-004 |
| Contract commit | `7a3f6a6c3256288308ed5cfb39c61aabbb9142ca` |
| Implementation commit | `195decef3888db7497e323129dec4bd516e4a141` |
| Qualified policy digest | `sha256:443fec8618e5f466af7fdfc95ab100ef36f075f61d78d824b02c1249bb0c2347` |
| Clean baseline evidence | `COH-toolchains/ci-artifacts/baseline/run.rEG1zv` |
| Baseline report digest | `06b20d6dd082a18fb9f6cb07476761de4ed7883fcaca38a90efad1326638d1e8` |
| Result | Passed |

## Verified boundary

The committed fixture is a bounded COH-CJ-1 JSON envelope containing one
tenant-scoped OPA/Rego v1 policy bundle. The envelope binds the canonical
bundle digest, current signer identifier and revision, Ed25519 algorithm, and
signature over the fixed `COH-SIGNED-OPA-POLICY-V1\0` domain.

Loading rejects duplicate keys, unknown fields, invalid metadata, malformed or
unsorted module paths, oversized input, invalid validity windows, wrong signer
authority, digest/signature mismatch, unsafe builtins, stale revisions, and
cross-tenant replacement. Rego compilation and activation occur only after
verification; the safe activation audit must append before atomic publication.
A failed candidate leaves the last-known-good snapshot active.

Evaluation rechecks current signer authority, time, actor state and scope,
verified action-manifest policy binding, tenant and case scope, registered
tool, authorized targets and route, capability completeness, validator state,
and E-stop status before OPA runs. Every intent or pre-dispatch result binds its
phase into the input and decision digests. Audit failure removes any usable
allow result.

## Adversarial test trace

| Test | Proven behavior |
|---|---|
| `TestSignedBundleLoadAndTwoPhaseEvaluation` | Signed load succeeds; intent and immediate pre-dispatch evaluations produce distinct digests; both decisions and activation append to audit. |
| `TestCommittedSignedBundleFixture` | The frozen envelope verifies under the frozen public key and activates at policy revision 7. |
| `TestDefaultDenyRuntimeAuthority` | Unknown tool, target, tenant, route, capability data, stale validator, active E-stop, and revoked actor all deny before Rego can allow. |
| `TestTamperRevocationStaleStateAndRecovery` | Byte tampering, duplicate JSON keys, signer revocation, revision replay, and stale action-policy state deny; a failed replacement preserves last-known-good operation. |
| `TestPolicyDenialTimeoutAndPreDispatchRevocation` | Policy denial, signer revision change, same-revision key replacement, timeout, and fresh-call recovery behave fail closed. |
| `TestConcurrentActivationCannotRollBackRevision` | Concurrent candidates cannot roll the active snapshot back to a lower revision. |
| `TestFailClosedPolicyOutputAuditAndContext` | Extra output fields, audit failure, cancellation, and recovery preserve provenance without an allow bypass. |
| `TestUnsignedWrongKeyUnsafeBuiltinAndAuditActivationDeny` | Incorrect signer, forbidden network builtin, and activation-audit failure prevent publication. |
| `TestSignedBundleData` | Signed canonical bundle data is available to Rego and remains covered by the bundle digest and signature. |
| `TestCapabilitySetExcludesSideEffectsAndNondeterminism` | Network, DNS, clock, random, UUID, runtime, tracing, and print capabilities remain unavailable. |

The successful two-phase trace returns `approval_required=true` and
`reason_code=policy_allowed` for the qualified inert T2 fixture. The
pre-dispatch decision has a new evaluation identity and decision digest; the
intent result is planning evidence and is not reusable as dispatch authority.

## Gate evidence

The clean baseline ran at implementation commit `195dece` with
`vcs_modified=false`. All 18 required stages passed: format, file size,
workflow, worktree/history secret scans, architecture, quality-contract, vet,
static analysis, unit, race, fuzz seeds, license, dependency/vulnerability,
SBOM, supply chain, evidence secret scan, and provenance.

The dependency stage verified all 183 approved modules and reported zero
vulnerabilities against the locked 2026-08-19 database. The license stage
verified all 183 module licenses, both SQLite notices, and both shipped
vulnerability-database attribution inputs.

## Follow-on bindings

CYB-50 consumes canonical action and policy-decision bytes for approval
fingerprints. CYB-51 owns grant lifecycle, CYB-48 owns T4 dual approval, and
CYB-49 replaces the narrow audit port with the append-only hash-chained sink.
Those leaves must preserve this evaluator's current-authority checks,
pre-dispatch phase binding, and fail-closed audit behavior.
