# CYB-13 skills, memory, and subagents verification

| Field | Value |
|---|---|
| Stable key | COH-E09 |
| Requirements | FR-042, FR-043, SEC-018, FR-026, SEC-015, FR-044, SEC-001, SEC-016, EVAL-022, FR-016, FR-040, FR-041 |
| Implementation commit | `b7048ee8235c096e1296abcb98b1bc3af0dbb004` |
| CI lane | `baseline` / Go `1.26.7` |
| CI outcome | `passed` |
| Quality-gate promotable | `true` |
| VCS modified during CI | `false` |
| CI report digest | `4e417dce70f001d6ee09dad119e27ea742c7ee9a53adaa6ead3ebfdbd4ad9f20` |
| CI report file SHA-256 | `e385a164cb4127082e9e28b528386130c6e41f7eedb96c287f31bef77d777382` |
| Focused verifier log SHA-256 | `078713f7e4ec8165d084f600f236d6df0630999fffe56e6ef2cb6262e17a0d58` |

## Evidence locations

- Baseline report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.pKdEVm/quality-report.json`
- Focused verifier: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/focused.CYB13.pH1fZT/e09-integration.log`
- Architecture report: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.pKdEVm/architecture-report.json`
- Race output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.pKdEVm/race.log`
- Unit output: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.pKdEVm/unit.log`
- Dependency/vulnerability result: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.pKdEVm/govulncheck.sarif`
- Provenance: `/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.pKdEVm/ci-provenance.json`

## Child completion evidence

| Issue | Capability | Committed evidence | Focused gate |
|---|---|---|---|
| CYB-70 / COH-E09-01 | Signed, reviewed skill registry | `CYB-70-signed-skill-registry-report.md` and `CYB-70-artifacts.sha256` | `verify_skill_registry.sh` |
| CYB-73 / COH-E09-02 | Progressive skill discovery | `CYB-73-progressive-skill-discovery-report.md` and `CYB-73-artifacts.sha256` | `verify_skill_discovery.sh` |
| CYB-72 / COH-E09-03 | Memory namespaces | `CYB-72-memory-namespaces-report.md` and `CYB-72-artifacts.sha256` | `verify_memory_namespaces.sh` |
| CYB-75 / COH-E09-04 | Hostile-content retrieval | `CYB-75-hostile-content-retrieval-report.md` and `CYB-75-artifacts.sha256` | `verify_hostile_content_retrieval.sh` |
| CYB-74 / COH-E09-05 | Bounded subagent DAG | `CYB-74-bounded-subagent-dag-report.md` and `CYB-74-artifacts.sha256` | `verify_bounded_subagent_dag.sh` |

## Acceptance evidence

| Criterion | Evidence |
|---|---|
| Only signed, reviewed skills execute; production agents cannot modify promoted content | CYB-70 verifies independent publisher, reviewer, and owner domains; strict Ed25519 signatures; exact manifest, resource, permission, policy, actor, tenant, case, and task bindings; immutable promoted versions; live revocation; read-only resolution; and a model-facing surface with no content, authority, write, or execution capability. CYB-73 verifies compact-to-detail-to-resource progression, current-state registry revalidation, immutable artifact references, and no discovery execution capability. The parent gate reruns the promotion, signature-denial, immutable surface, exact discovery binding, replay revalidation, resource inspection, and SQLite revocation tests together. |
| Memory namespaces prevent cross-case and cross-tenant disclosure under hostile retrieval content | CYB-72 verifies four separately bound stores, strict namespace scopes, owner rules, retention, independent review, current access decisions, chained provenance, and a read-only agent surface. CYB-75 verifies every retrieved source remains sanitized untrusted data. `TestE09MemoryNamespaceIsolationPrecedesHostileContentRelease` composes the real memory controller, retrieval controller, and deterministic inspector: an authorized same-case hostile artifact is redacted and neutralized, while cross-case and cross-tenant requests return before content read, retrieval authorization, audit release, or model-facing output. |
| Subagent graphs obey depth, fanout, budget, cancellation, evidence, and recovery | CYB-74 verifies the closed 12-role catalog; depth, fanout, concurrency, total-task, cycle, and deadline bounds; external run-budget reservation and settlement; typed claims/findings with evidence and counterevidence; descendant-first acknowledged cancellation; uncertain caller-cancellation handling; optimistic durable storage; and restart recovery without redispatch. The parent gate reruns the bounds, result, cancellation, recovery, and SQLite restart paths. |
| Cross-leaf bypass resistance | `verify_e09_integration.sh` requires all five committed leaf reports, checksum manifests, and verifier scripts, executes every leaf gate, then selects cross-component skill, memory, hostile-content, subagent, and SQLite restart tests. Static analysis, architecture, file-size, Markdown-link, and clean-diff gates run after the composed tests. |
| Deterministic verification | The parent gate passed from the clean implementation commit. It includes repeated leaf execution and race detection. A wall-clock-sensitive subagent fixture discovered during evidence replay was corrected to keep production operation deadlines ahead of real time, then the affected terminal-state and cancellation tests passed 20 repetitions and the race detector before the clean parent rerun. |

## Requirement trace

- **FR-042, FR-043, SEC-018:** signed manifests, independent review,
  immutable promoted versions, exact resource bindings, rollback, revocation,
  and read-only resolution constrain skill execution.
- **FR-026, SEC-015:** progressive discovery exposes bounded metadata before
  detail and immutable resource references, with durable parent bindings and
  current authorization revalidation.
- **FR-044, SEC-001, SEC-016, EVAL-022:** retrieved content remains untrusted,
  deterministic sanitized data and cannot mutate scope or authorization; the
  adversarial corpus covers all closed source and hostile-finding classes.
- **FR-016, FR-040, FR-041:** the durable delegation DAG enforces graph and
  budget limits across the 12 closed roles and returns typed evidence-bearing
  claims and findings with cancellation and recovery semantics.

## Verification summary

The focused parent verifier passed all five leaf gates and their strict schema,
signature, authorization, revocation, namespace, retention, review,
sanitization, adversarial, graph-bound, budget, evidence, cancellation,
recovery, SQLite restart, repeated, race, vet, static-analysis, architecture,
file-size, link, and clean-diff checks. Its final summary records five children,
signed/reviewed/immutable/revalidated skills, progressive discovery,
namespace-isolated memory, sanitized untrusted hostile content, and bounded,
cancellable, recoverable subagents with zero failures.

The clean baseline passed all 18 required stages: format, file-size, workflow,
worktree/history/evidence secret scans, architecture, quality contract, vet,
static analysis, unit, race, fuzz seeds, license, dependency/vulnerability,
SBOM, supply chain, and provenance. The report binds the exact clean
implementation commit and is promotable. No unresolved blocking finding
remains for CYB-13.
