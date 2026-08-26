# CYB-48 T4 dual-approval verification

| Field | Evidence |
|---|---|
| Stable key | COH-E05-05 |
| Requirements | FR-005, SEC-007, EVAL-007 |
| Implementation commit | `ac26f2d31f852dcb6b9539f8b723d4ba793c8204` |
| Lifecycle contract | `coh.approval-lifecycle/v2` / `2.0.0` |
| Clean baseline evidence | `COH-toolchains/ci-artifacts/baseline/run.IuaXeq` |
| Baseline report digest | `95921d4d291438b53c9b6c8d08e95887ef60c1a765874d77ff541ab96eb6f402` |
| Result | Passed |

## Verified control

The broker derives approval count only after the CYB-50 verifier successfully
revalidates the signed action envelope and fingerprint. Verified T4 manifests
produce a required grant count of two; all other currently supported approval
tiers produce one. No request or transition command has a threshold field, so
a workflow, model, transport, or caller cannot downgrade T4.

The first valid T4 grant commits a new audited lifecycle revision that remains
`requested`. The second grant reaches `granted` only when its authenticated
actor account and stable human principal are both distinct from the requestor
and first approver. The requestor therefore satisfies neither grant, including
through a second account mapped to the same person.

Each approver must be active, exact-scope, carry the `approver` role and
`approval.decide`, have identity kind `human`, and have a positive current
enrollment revision and enrolled state. Administrator or service status does
not imply eligibility or waive separation.

## Policy, fingerprint, and enrollment proof

The private broker fingerprint adapter returns action tier only after signed
manifest/fingerprint verification. The lifecycle operation digest binds the
complete fingerprint proof, actor snapshot, stable principal authority,
enrollment revision/state, expected lifecycle revision, reason, and
idempotency key. Only safe identifiers, revisions, booleans, and digests are
persisted.

Lifecycle v2 stores action tier and the requestor principal, plus actor ID,
actor revision, principal ID, and enrollment revision for every grant. Actor
and principal grant histories are independently unique and append-only.

Before consumption, the broker revalidates both stored grant identities using
fresh current actor and enrollment authorities. Missing authority, actor
revocation, unenrollment, lost role/permission, scope change, stale actor or
enrollment revision, or principal reassignment denies before the use counter
can advance.

## Adversarial trace

| Test or fixture | Proven behavior |
|---|---|
| `TestT4RequiresTwoDistinctEnrolledHumanPrincipals` | T4 derives threshold two, remains requested after one grant, denies premature consumption, grants after the second human, exactly replays the second grant, and consumes once with both fresh authorities. |
| `TestT4ConcurrentFirstGrantsSerialize` | Two different first approvers race on revision one; one commits, one conflicts, and the record remains requested with exactly one grant. |
| `TestT4DeniesAliasServiceAndUnenrolledApprovers` | Same-person account aliases, requestor-principal aliases, service identities, and unenrolled identities cannot supply the second grant. |
| `TestT4ConsumptionRevalidatesBothEnrollments` | Missing second authority, unenrollment, actor revocation, stale enrollment, and principal reassignment all deny consumption. |
| `TestTransitionTable` | Principal/tier bindings cannot change and terminal records cannot regain authority. |
| Shared adapter conformance | Lifecycle v2 records retain exact optimistic revisions/digests and transactional outbox parity in SQLite and PostgreSQL. |
| `t4-denial-corpus.json` | 26 named zero/one, alias, service, enrollment, stale, replay, terminal, cancellation, timeout, concurrency, and audit denials remain frozen and unique. |

Successful first and second grants commit their record revision and audit
outbox reference atomically. Denied attempts reach the mandatory redacted
audit sink; audit failure returns no usable result. Exact committed operations
recover as replay, while changed input or stale revisions conflict.

## Migration and compatibility

The current domain registry now validates `coh.approval-lifecycle/v2`. V2 adds
the verified action tier, requestor stable principal, and per-grant stable
principal/enrollment revision required to prove two distinct humans.
Lifecycle v1 and provisional approval payloads are never accepted as T4
authority and must be re-requested.

No SQL DDL migration was needed. SQLite and PostgreSQL already store generic
canonical approval records with optimistic revisions, idempotency, and an
atomic outbox. Their shared conformance suite validates the v2 payload.

## Gate evidence

The dedicated verifier completed with:

```text
t4-dual-approval summary: threshold=2 distinct=actor-and-principal human=required enrollment=fresh partial=unavailable consume=revalidated concurrency=cas denials=26 failures=0
```

It ran the T4 positive/negative suite normally and under the race detector,
the lifecycle/domain and both persistence-adapter suites, vet, architecture,
and file-size gates. The broader CYB-51 lifecycle verifier also passed after
the v2 migration.

The clean baseline ran at `ac26f2d` with `vcs_modified=false`. All 18 required
stages passed: format, file size, workflow, worktree/history secret scans,
architecture, quality-contract, vet, static analysis, unit, race, fuzz seeds,
license, dependency/vulnerability, SBOM, supply chain, evidence secret scan,
and provenance. It covered 39 architecture packages with zero violations and
verified 183 approved modules with zero vulnerabilities.

## Follow-on bindings

CYB-49 will publish and integrity-check the transactional approval audit
outbox. Fresh pre-dispatch policy, signed ROE, safety watch, isolated runner,
lease, and exactly-once execution remain separate mandatory T4 controls. The
independent review tracked by CYB-173 remains a hard pre-production gate.
