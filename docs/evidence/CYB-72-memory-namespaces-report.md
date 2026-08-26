# CYB-72 session and case memory namespace verification

| Field | Value |
|---|---|
| Stable key | COH-E09-03 |
| Requirements | FR-026, SEC-015 |
| Implementation commit | `d32c79b723ab9e0e256d5ff4942d2b0e538b167a` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI report digest | `def13ceb0ad797697e288cdb22148a92148de7337c82709a93ba76d768a1f337` |
| CI report file SHA-256 | `9a6dc647e4c3d24d864994da98c06a86e51d4fc03bc0d02df640105d1855654b` |
| Focused verifier log SHA-256 | `06560fc6dc7ea651a532c3f67af4c8a64177c6e375446f3f6cd6af1ec95bf5f3` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.X1v48A/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB72.YWkq6Y/memory-namespaces.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.X1v48A/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.X1v48A/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.X1v48A/unit.log`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.X1v48A/ci-provenance.json`

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Four separate memory classes | The controller requires four constructor-bound stores. Each repository adapter is fixed to exactly one of session, case, analyst-preference, or reviewed-organization memory; cross-class wiring and value types are rejected. |
| Exact namespace identity | Session binds organization/tenant/case/session/actor; case binds organization/tenant/case; analyst preference binds organization/tenant/subject actor without a case; reviewed organization binds organization/tenant without case, session, or subject ownership. |
| Separate retention | Namespace-specific classes and hard maxima are enforced: session 30 days, case 10 years, analyst preference 2 years, reviewed organization 1 year. Every record carries a policy digest and exact expiry, and expired reads fail closed. |
| Default-deny access | Every read and write receives a fresh decision whose canonical digest is recomputed. It binds request, actor, operation, namespace, scope, key, full immutable value digest, retention, policy, and deadline. False, stale, substituted, malformed, canceled, timed-out, or unavailable decisions do not resolve memory. |
| Independent organization review | Reviewed-organization writes require a reviewer different from the writer. Both writes and reads recheck a revisioned review authority and deny revoked, expired, mismatched, or invalid review decisions. |
| Reference-only values | The only value is a bounded immutable JSON `domain.ArtifactRef`. The value digest covers digest, media type, classification, length, and namespace-specific value type. Public/reflection tests prohibit content, bytes, prompts, instructions, query handles, secrets, paths, URLs, callbacks, connectors, and executors. |
| Optimistic, idempotent, crash-safe writes | Expected revisions enforce optimistic concurrency. One atomic storage transaction writes the current record and an immutable receipt. Exact replay rechecks current authority; changed replay and stale revisions are denied. Old receipts remain exactly recoverable after newer revisions. |
| Chained provenance | Every revision binds the prior provenance digest and the complete canonical record. Store results and every read are revalidated before an owned copy is returned; tamper tests fail closed. |
| Cancellation, timeout, denial, and recovery | Typed tests cover invalid input, ownership/cross-case denial, policy denial, decision tamper, retention expiry, review revocation, cancellation, timeout, stale revision, exact replay, changed replay, and provenance tamper. |
| SQLite restart | Integration writes all four namespaces, advances case memory, closes/reopens SQLite, reads each namespace, recovers the older receipt, and denies a changed replay. |
| Agent orchestration | `coh.agent-loop.memory-lookup.v1` exposes a one-method, read-only `BoundedMemoryLookup`. It cannot write memory, fetch bytes, or receive execution authority and preserves typed controller errors. |
| Migration | `coh.storage/v1` adds the explicit `memory` metadata kind. Only this new kind may omit `case_id` for analyst/organization scope. Generic SQLite/PostgreSQL tables require no DDL change; documented cutover and fail-closed rollback preserve rows and receipts. |

## Requirement trace

- **FR-026:** session, case, analyst-preference, and reviewed-organization
  memory are distinct types, identities, stores, value labels, retention rules,
  and authorization paths. Evidence and working hypotheses are not accepted as
  memory value types.
- **SEC-015:** persistence keys and authorization digests bind organization,
  tenant, namespace, and every applicable case/session/actor identity. Cross-
  case, cross-actor, cross-class, expired, revoked, and tampered resolution is
  denied before an artifact reference is returned.

## Verification summary

The focused verifier ran schema, canonical binding, success, class separation,
scope, ownership, policy, retention, review, replay, stale revision, tamper,
cancellation, timeout, agent-boundary, SQLite close/reopen, repeated, race,
vet, static-analysis, architecture, file-size, and link checks. The clean
baseline then passed all 18 required stages: format, file-size, workflow,
worktree/history/evidence secret scans, architecture, quality contract, vet,
static analysis, unit, race, fuzz seeds, license, dependency/vulnerability,
SBOM, supply chain, and provenance.

No unresolved blocking finding remains for CYB-72. Hostile-content inspection
of referenced memory artifacts is intentionally the downstream scope of
CYB-75; this issue exposes no content bytes that could bypass that boundary.

