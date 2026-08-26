# CYB-10 E05 policy, approvals, and audit integration report

| Field | Value |
|---|---|
| Issue | COH-E05 / CYB-10 |
| Requirements | FR-005, FR-012, SEC-003, SEC-004, SEC-006 through SEC-009, SEC-020 through SEC-022, SEC-040, EVAL-005 through EVAL-007, EVAL-013 |
| Verification date | 2026-08-26 |
| Design-freeze anchor | Product-owner approval at `8c6012d` |
| Integration checkpoint | `e0f43a61dce4311b1654998e0eb8c7d889d6fa9a` |
| Aggregate result | Pass |
| Review status | Local technical evidence complete |

## Outcome

All six E05 children are Done and their controls now compose in one
broker-private pre-dispatch gate. T2 through T4 authorization can return a
capability only after fresh Ed25519 action-envelope verification, an allowed
and digest-verified `pre_dispatch` policy decision, exact approval consumption,
applicable signed-ROE proof verification, and durable tenant audit append.

The capability and every dependency that can produce it are unexported. The
broker intentionally exposes no partial workflow `Authority` implementation
before COH-E06 supplies the isolated dispatch consumer. Consequently, the
current repository contains neither a bypass route nor a runnable
consequential dispatch route.

## Child completion audit

| Child | Deliverable | Linear status | Evidence |
|---|---|---|---|
| CYB-52 / COH-E05-01 | Canonical signed action manifests | Done | `CYB-52-signed-action-manifest-report.md` and checksum ledger |
| CYB-47 / COH-E05-02 | Signed OPA policy engine | Done | `CYB-47-signed-opa-policy-engine-report.md` |
| CYB-50 / COH-E05-03 | Exact approval fingerprints | Done | `CYB-50-approval-fingerprint-report.md` |
| CYB-51 / COH-E05-04 | Durable approval lifecycle | Done | `CYB-51-approval-lifecycle-report.md` |
| CYB-48 / COH-E05-05 | T4 dual-human approval | Done | `CYB-48-t4-dual-approval-report.md` |
| CYB-49 / COH-E05-06 | Tamper-evident audit and verification | Done | `CYB-49-tamper-audit-report.md` |

## Integration acceptance

| Criterion | Authoritative evidence | Result |
|---|---|---|
| All consequential actions traverse canonical manifest, policy, approval, and fail-closed audit paths | `preDispatchGate.authorize` is the only producer of the private capability; `TestPreDispatchT2ThroughT4SuccessAndMandatoryOrder` proves manifest short-circuit and policy → ROE → approval → audit order; broker surface and architecture checks pass | Pass |
| One-byte action change, stale policy, replayed approval, actor collision, or scope expansion is denied | `TestPreDispatchDeniesManifestPolicyIdentityAndScopeChanges`, `TestPreDispatchT4RequiresROEAndTwoFreshDistinctApprovers`, and `TestPreDispatchReplayAuditFailureCancellationAndTimeoutReturnNoAuthority` return zero capability for every named condition | Pass |
| T4 cannot pass without two distinct non-requestor approvers and a valid signed ROE | Real approval lifecycle requires two fresh enrolled human principals; the gate requires exact active Ed25519 ROE proof before consumption; missing, aliased, stale, or scope-mismatched authority returns no capability | Pass |
| Every E05 child is Done | Linear status was re-read for CYB-52, CYB-47, CYB-50, CYB-51, CYB-48, and CYB-49 on 2026-08-26 | Pass |

## Composition and binding proof

The gate receives raw signed-envelope bytes and re-verifies them directly. It
does not trust a caller-provided verified object. It independently requires an
active exact-scope requestor with `action.request`, then constructs the policy
request itself with phase `pre_dispatch`. The returned decision must have a
valid canonical digest and exactly match the evaluation identity, manifest,
policy revision, actor revision, active policy signer, audit scope, and the
gate's call-time interval.

Before approval consumption, the gate rechecks the intent decision and approval
fingerprint against the newly verified manifest. It rejects a current actor
revision older than the intent decision. The lifecycle then re-verifies the
fingerprint, consumes the exact optimistic revision, and—on T4—revalidates both
stored approver actor and stable-principal authorities. The gate checks the
resulting durable record again before using it.

The final audit reservation binds both policy-decision digests, the manifest,
approval fingerprint and revision, and applicable ROE digest. It contains only
safe identifiers, revisions, timestamps, and digests. A durable append failure
returns no capability after the approval has been consumed.

## Signed-ROE boundary

COH-E19-01 owns the concrete signed ROE document schema and key resolver. E05
therefore defines a narrow private proof port instead of inventing that later
contract. The verifier must resolve and cryptographically verify the exact
expected digest and return exact organization, tenant, case, revision,
validity, broker verification time, and active Ed25519 signer authority.

The gate independently validates every proof field. Until COH-E19 installs a
real verifier and the rest of T4 execution controls, no public dispatch path
exists; a missing verifier cannot degrade to an unsigned or inferred ROE.

## Replay, cancellation, and audit failure

Exact approval retry returns lifecycle state with `replayed=true`; the gate
explicitly denies that result and returns no capability. If final audit append
fails after successful consumption, a later retry still cannot dispatch. Once
audit recovers, the replay denial is durably recorded. A new action and
approval are required.

Cancellation after consumption uses a detached bounded context to append the
canceled terminal reservation while returning no capability. Cancellation or
timeout before manifest verification makes no downstream call. Post-dispatch
uncertainty and exactly-once external-effect reconciliation remain COH-E06
responsibilities.

## Focused verification evidence

The clean integration checkpoint passed the dedicated verifier with summary:

```text
predispatch summary: order=manifest-policy-roe-approval-audit tiers=T2-T4 manifest=ed25519 policy=fresh approval=single-use roe=T4-required audit=fail-closed replay=denied failures=0
```

The verifier log is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/predispatch/run.WGMxqr/predispatch.log`
with SHA-256
`cd1376dd2f87dd7abe90fa991eb43a87b44f2d93af0491b5d979da7edcbc230c`.
It includes focused and race tests, vet, 42-package architecture verification
with zero violations, and the file-size gate.

## Clean baseline evidence

The exact clean checkpoint `e0f43a61dce4311b1654998e0eb8c7d889d6fa9a`
passed all 18 required baseline stages with `quality_gate_promotable=true` and
`vcs_modified=false`. The evidence directory is
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.oboz8d`.

The embedded quality-report digest is
`23a4d403843340095c9112e16f86461c1e38137cf22279aa637b0fb41ed56c21`;
the report-file SHA-256 is
`024b2c3ad8a08916c1e06ede37bdd085879d03f6cfc21ace7d651f13cb6885b6`.
Provenance records 585 source files, source digest
`cd6a271998fe2e6bdd6156c39a9b95e6ed8499a6acb6f8e99e2dc4f813f1b424`,
Go 1.26.7 on darwin/arm64, 42 architecture packages with zero violations, and
183 approved modules with zero vulnerabilities.

## Reproduction

```sh
./scripts/verify_predispatch_gate.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- COH-E06 must consume the private capability immediately at the isolated
  execution boundary and qualify lease, E-stop, runner, and external-effect
  reconciliation behavior. It may not expose or serialize the capability.
- COH-E19 must implement and qualify the actual signed ROE document, key
  resolution, safety preflight, staffed watch, recipe runner, and T4 evidence.
- Independent security architecture review remains required before the first
  production release. This approved follow-up is not an unresolved E05
  implementation finding.
