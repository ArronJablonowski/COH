# CYB-50 approval fingerprint verification

| Field | Evidence |
|---|---|
| Stable key | COH-E05-03 |
| Requirements | SEC-006, SEC-009, EVAL-005 |
| Contract commit | `f7cd2252d34a116dd7fc47d8685fad9ed109ffbb` |
| Implementation commit | `3da4144592e487aae8a39de2fb9f4e2cde6ce204` |
| Frozen fingerprint | `sha256:b28588e9813dfaa8413ba76190afdd78831a332a22a1baa577b3fa840df4d1f3` |
| Clean baseline evidence | `COH-toolchains/ci-artifacts/baseline/run.6tqrFC` |
| Baseline report digest | `cc08159ea1a21b022975dced85b50a2548d703283c6959a6a68e6072e93c2eef` |
| Result | Passed |

## Verified boundary

The approval identity is SHA-256 over a fixed domain plus independently
length-framed canonical action-manifest and canonical policy-decision bytes.
The action envelope is reverified against fresh signer key, revision, and
active state during every build and verification operation.

The manifest transitively binds organization, tenant, case, actors, action,
targets/exclusions, arguments, payload, credential reference, tool, policy,
ROE, execution/isolation, validity, nonce, rollback, safety watcher, and
maximum use count. The policy decision additionally binds evaluation identity
and time, actor revision, active policy bundle, outcome, reason, phase, input,
and approval requirement.

The safe fingerprint record repeats only scope identifiers, digests, validity,
and use count. It excludes canonical source bytes, raw targets/arguments,
credential identifiers or values, payloads, policy source, prompts, evidence,
and signing material. Mandatory audit failure prevents a usable build or
verification result.

## Adversarial trace

| Test | Proven behavior |
|---|---|
| `TestFrozenFingerprintBuildVerifyAndAudit` | Frozen fixtures reproduce exactly; build and verification are deterministic and audited. |
| `TestEveryApprovalSensitiveManifestChangeInvalidates` | Scope, owner, target, argument, payload, credential, tool, policy, ROE, validity, and use-count changes produce a different fingerprint and reject the old candidate. |
| `TestPolicyDecisionByteChangesInvalidate` | Actor revision, evaluation identity/time, and active bundle changes invalidate the old fingerprint. |
| `TestPolicyDecisionDenials` | Digest tamper, denied outcome, pre-dispatch phase, missing approval requirement, manifest/policy/actor mismatch, and future evaluation time deny. |
| `TestCancellationTimeoutAuditFailureAndRecovery` | Revoked action signer, cancellation, timeout, and audit failure return no usable fingerprint; a fresh valid call recovers. |
| `TestExpiredManifestAndConcurrentDeterminism` | Expired actions deny and concurrent builds produce one stable identity without races. |
| `TestDecodeStrictBoundedAndDetached` | Duplicate/unknown fields, invalid use count, oversized input, and cancellation fail closed. |
| `TestFrozenContractSchemaAndCorpus` | Strict Draft 2020-12 schema and all 25 named denial fixtures remain frozen and unique. |

Exact input replay intentionally produces the same identity. It is not a grant:
CYB-51 must combine fingerprint equality with current request/grant state,
expiry, remaining uses, optimistic concurrency, and revocation. This separation
prevents the deterministic identity from becoming replay authority.

## Gate evidence

The clean baseline ran at implementation commit `3da4144` with
`vcs_modified=false`. All 18 required stages passed: format, file size,
workflow, worktree/history secret scans, architecture, quality-contract, vet,
static analysis, unit, race, fuzz seeds, license, dependency/vulnerability,
SBOM, supply chain, evidence secret scan, and provenance.

The dependency stage verified 183 approved modules with zero vulnerabilities.
The license stage verified 183 modules, both required SQLite notices, and both
shipped vulnerability-database attribution inputs with zero denials.

## Follow-on bindings

CYB-51 owns the approval lifecycle and must store, grant, reject, expire,
consume, and revoke state against this exact fingerprint. CYB-48 adds distinct
eligible non-requestor dual approval for T4. CYB-47 remains mandatory
immediately before dispatch, and CYB-49 records the complete decision chain.
