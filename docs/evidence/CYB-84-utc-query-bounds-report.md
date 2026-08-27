# CYB-84 mandatory UTC query-bounds verification

| Field | Value |
|---|---|
| Stable key | COH-E12-02 |
| Requirements | FR-046, FR-047, FR-048, SEC-013 |
| Implementation commits | `3256973`, `615d852`, `7b5adeb`, `fc7fa0d` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI stages | `18 passed / 0 failed` |
| CI report digest | `47c351df6520264a98848ace039f7b8db22ddd2e3e19719b97c91253e6194530` |
| CI report file SHA-256 | `28b64322284cd15e7b753acd983c60aee0321db43402849961815d9a13e9d0a7` |
| Canonical allowed-decision digest | `sha256:4940a003b677186b47bd925e2d42bdf0a7176f6b969d98c4beb6e7227741fa54` |

## Evidence locations

- Decision schema: `contracts/query-bounds/v1/query-bound-decision.schema.json`
- Canonical allowed policy decision: `contracts/query-bounds/v1/fixtures/allowed-decision.canonical.json`
- Denial/revocation corpus: `contracts/query-bounds/v1/fixtures/denial-corpus.json`
- Threat model: `docs/design/mandatory-utc-query-bounds.md`
- Focused evidence: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB84.Y3QkFj`
- Adversarial trace: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB84.Y3QkFj/adversarial.log`
- Approval/audit proof: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB84.Y3QkFj/approval-audit.log`
- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.Qd1NIo/quality-report.json`

The hashes in [`CYB-84-artifacts.sha256`](CYB-84-artifacts.sha256) identify the
contract, focused, and baseline evidence.

## Acceptance evidence

| Criterion | Direct evidence |
|---|---|
| Tenant/resource allowlist and half-open UTC bounds are mandatory; missing, live/open, excessive, and future-unsafe ranges fail closed. | The upstream strict CYB-85 decoder plus `TestMissingOpenEndedAndNonUTCQueriesNeverReachAdmission` reject missing/open/equal/non-UTC bounds, empty resources, and zero limits. `TestUTCIntervalDeadlineAndLimitMatrix` denies interval, future, deadline, and every individual limit overflow. |
| The control is default-deny, actor/scope bound, redacted, audit-before-admit, and safe under replay, tamper, stale state, and revocation. | `Engine.Admit` compares exact actor/organization/tenant/case/source/resources and authorization/policy/audit/capability digests, requires active current authority, E-stop clear, exact approval when required, current replay observation, canonical decision integrity, and durable audit. The 24-reason corpus and adversarial trace cover each denial/revocation class. |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance and policy authority. | Tests cover nil/canceled/deadline contexts, invalid/stale/future authority, denied authorization/policy/approval, replay/audit outages, audit recovery, and reauthorization of exact replay. Decisions retain query, resource, authority, capability, policy, approval, audit, revocation, interval, and limit digests without native query or secret values. |
| Automated tests and repository gates pass. | Focused verbose, 10-repeat, race, vet, static, concurrency, architecture, file-size, quality-contract, schema/corpus, and documentation checks passed. The clean `fc7fa0d` baseline passed all 18 stages, including secrets, licenses, vulnerabilities, SBOM, supply-chain, and provenance. |
| Required evidence cross-references the issue and requirements. | The decision schema, canonical policy decision, approval/audit proof, adversarial trace, denial/revocation corpus, threat model, retained logs, checksums, and this report identify COH-E12-02, CYB-84, FR-046, FR-047, FR-048, and SEC-013. |

## Authority and audit proof

Query bytes cannot assert current authority. A trusted snapshot owns actor,
source, allowlist, capability, authorization, policy, approval, E-stop,
revocation, maximum interval, future skew, typed maximum limits, and broker
time. All authority and request bindings are captured by domain-separated
digests in the redacted decision.

When approval is required, it must be allowed, unexpired, and bound to the
exact canonical query and policy-decision digest. Both allowed and denied
decisions pass through the durable audit port. An audit error produces only an
`unavailable/audit_unavailable` result; no query admission is returned.

## Replay, revocation, and recovery

An exact query-ID replay is marked only after fresh scope, authority, approval,
E-stop, revocation, time, and limit checks run again. A changed query digest for
the same ID is denied as `changed_replay`. A prior allow is never authority.
Actor, source, allowlist, or capability revocation and emergency stop all deny
before replay observation.

Cancellation and timeout publish no admission. The audit attempt uses a
bounded context detached from caller cancellation so the redacted failure can
still be retained. Recovery starts from the immutable validated query under
fresh authority and reproduces its query/provenance identity.

## Transient CI bootstrap history

Two initial full-baseline attempts ended before project gates: one could not
acquire the pinned `actionlint` module lock and one received an HTTP/2 stream
error downloading the pinned `x/tools` archive. The subsequent clean run
completed all 18 stages. These bootstrap failures are diagnostic history, not
acceptance evidence.

## Migration, rollback, and release follow-up

Unknown versions, fields, revisions, reasons, or authority states deny. Time,
skew, limit, approval, replay, authority-binding, canonical, or digest changes
require a new major security contract and adversarial migration proof. Rollback
restores the prior control, schema, policy, and adapter together without
rewriting decisions or query evidence.

No unresolved blocking finding remains. An independent security architecture
review remains required before the first production release.

## Verification summary

The focused and baseline evidence proves all CYB-84 acceptance criteria at
clean commit `fc7fa0d873ec2e0b09564bd61bb54e8cc51f93ae`.
