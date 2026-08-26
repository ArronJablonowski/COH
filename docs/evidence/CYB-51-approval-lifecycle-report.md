# CYB-51 approval lifecycle verification

| Field | Evidence |
|---|---|
| Stable key | COH-E05-04 |
| Requirements | SEC-006, SEC-008, SEC-040 |
| Contract commit | `d1535ee3c149229fae67e3ee7f0abebbdaa9dcd7` |
| Implementation commits | `2601fb1`; `d66fd4f872d10d7a7526b4335a2e89992966dacb` |
| Clean baseline evidence | `COH-toolchains/ci-artifacts/baseline/run.37pIcq` |
| Baseline report digest | `c5fca80857047de9ef2fe024477808b5ed0668f2868b750cfb49c21af0e6d5db` |
| Result | Passed |

## Verified boundary

The broker-private lifecycle implements request, grant, reject, expire,
consume, and revoke over the versioned `coh.approval-lifecycle/v1` record. It
does not expose policy, fingerprint-verification, or approval capabilities to
workflow or transport packages; the broker public-surface test and architecture
gate enforce that boundary.

Each record immutably binds the exact CYB-50 fingerprint, manifest and policy
decision digests, organization/tenant/case, requestor authority revision,
action owner, validity, approval threshold, and use limit. Every revision adds
the fresh acting identity revision, bounded reason, operation digest, event
identity, and broker time. Terminal rejected, expired, consumed, and revoked
records cannot regain authority.

Request, grant, and consume revalidate fingerprint authority where it creates
or exercises consequential authority. Actor active state, exact scope,
permission, distinct approver, action-owner, validity, and expected revision
checks default deny. The requestor cannot approve their own action.

## Policy decision and approval proof

The lifecycle proof includes the verified `coh.approval-fingerprint/v1`
candidate, signed-action envelope digest, signer identity/key revision/active
state and key digest, plus the complete canonical-digest-bound
`coh.policy-decision/v1` decision. The broker calls the CYB-50 verifier before
request, grant, or consume. The persisted operation digest covers those facts
and the fresh actor snapshot without storing key material or raw action data.

`TestLifecycleSuccessReplayAndTerminalDenial` proves the complete
requested → granted → consumed path, exact request/grant replay, maximum-use
enforcement, and terminal denial. Each successful revision has one atomic
`approval.<operation>` outbox row referencing the immutable record revision and
digest.

## Denial, revocation, and adversarial trace

| Test or fixture | Proven behavior |
|---|---|
| `TestTransitionTable` | Only the frozen transitions are accepted; stale revision, binding mutation, self-approval, use-before-grant, and terminal transitions deny. |
| `TestLifecycleSuccessReplayAndTerminalDenial` | Request/grant/consume succeed once, exact retries recover, and a consumed grant is never reusable. |
| `TestLifecycleDispositionTransitions` | Reject, revoke-before-grant, revoke-after-grant, and time-driven expire reach the correct terminal state. |
| `TestConcurrentConsumeAllowsExactlyOneUse` | Two consumers race on one remaining use; exactly one succeeds and one optimistic conflict is audited. |
| `TestDenialsCancellationAndAuditFailure` | Self-approval, cancellation, stale revision, and audit outage return no usable authority. |
| `TestFingerprintDenialScopeBindingAndAuditRedaction` | Scope substitution and revoked/tampered fingerprint authority deny; unvalidated secret-like identifiers are blanked before audit. |
| Shared `approval-lifecycle-cas-and-outbox` conformance | SQLite and PostgreSQL accept exact replay, reject stale CAS, and retain the exact lifecycle revision/digest and audit outbox atomically. |
| `lifecycle-denial-corpus.json` | 26 named invalid, tamper, stale, replay, terminal, revocation, cancellation, timeout, and audit failures remain frozen and unique. |

Denied attempts use a detached, bounded mandatory audit call. If denial audit
is unavailable, the effective result becomes `audit_unavailable`. Successful
state and audit-outbox writes are a single storage transaction, so neither can
commit alone.

## Retry, crash, and persistence evidence

Each transition requires the immediately preceding revision. The use counter
increments in that same compare-and-swap and reaches terminal `consumed` at its
maximum. The persisted last-operation digest binds the operation, idempotency
key, actor snapshot, proof, reason, and expected revision. After a commit whose
response is lost, only an exact retry can recover that new revision with
`replayed=true`; changed input or a later revision conflicts.

The existing SQLite WAL/reopen test and PostgreSQL transactional conformance
cover adapter crash/recovery behavior. The shared conformance suite now adds a
real lifecycle record and outbox transaction for both adapters. No SQL DDL was
needed: both already use generic canonical metadata, idempotency, and outbox
tables. The required migration is the domain-registry policy/audit schema
change from the provisional approval payload to the lifecycle payload. Legacy
payloads are never interpreted as current grants.

## Gate evidence

The dedicated `scripts/verify_approval_lifecycle.sh` verifier passed contract,
state-table, service, adapter parity, race, vet, architecture, and file-size
checks with this summary:

```text
approval-lifecycle summary: states=6 transitions=10 denials=26 storage_adapters=2 concurrency=cas idempotency=exact audit=atomic-outbox terminal=default-deny failures=0
```

The clean baseline ran at `d66fd4f` with `vcs_modified=false`. All 18 required
stages passed: format, file size, workflow, worktree/history secret scans,
architecture, quality-contract, vet, static analysis, unit, race, fuzz seeds,
license, dependency/vulnerability, SBOM, supply chain, evidence secret scan,
and provenance. It covered 39 architecture packages with zero violations and
verified 183 approved modules with zero vulnerabilities.

## Follow-on bindings

CYB-48 will derive a two-grant threshold for T4 while reusing this append-only
distinct-grant record and CAS service. CYB-49 will publish and integrity-check
the transactional lifecycle outbox. The independent security architecture
review in CYB-173 remains a hard gate before the first production release and
is not claimed by this evidence.
