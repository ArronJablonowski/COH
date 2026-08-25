# COH product contract

| Field | Decision |
|---|---|
| Document ID | COH-E01-01 |
| Status | Approved for M0 design freeze |
| Owner | COH product owner / project lead (Arron Jablonowski) |
| Required approvers | Product owner, security reviewer, and requirements reviewer |
| Approval status | Approved 2026-08-25 at source checkpoint `8c6012d`; independent security review tracked by CYB-173 before production |
| Effective baseline | Research snapshot 2026-08-19 |
| Change control | A reviewed PRD revision with updated requirement trace and qualification impact |

This document fixes COH's v1 scope, users, and success contract. The
[PRD](../../outputs/COH-PRD.md) remains normative if this summary and the PRD
ever conflict. This issue produces documentation only; it does not activate
policy, grant authority, or implement a runtime control.

## Product decision

COH is a standalone, Apache-2.0, evidence-centered LLM harness for defensive
cybersecurity operations. It must run without Onion Sentinel or any other host
application. The model is an untrusted planner and analyst; deterministic
services outside the model own identity, authorization, credentials, policy,
execution, evidence, and audit.

Native macOS and Linux operation is primary. Docker Desktop and Docker Compose
are supported but optional. Connected and fully air-gapped operation are both
product modes.

## Personas and authority

### Primary persona

The primary v1 persona is a **solo cybersecurity analyst** who may also hold the
administrator role. This user investigates alerts, hunts threats, develops
detections, triages vulnerabilities, plans response, and produces evidence-backed
reports. Solo operation may perform T0 through T3 actions only when deterministic
policy permits the exact action and any required approval is present.

Solo status never weakens separation of duties. T4 production validation is
unavailable until two distinct eligible, authenticated, non-requestor human
approvers are enrolled; the requestor cannot supply either T4 approval. A
human-requested T4 action therefore normally requires at least three distinct
enrolled humans: one requestor and two approvers.

### Secondary personas

| Persona | Need | Default authority boundary |
|---|---|---|
| Approver | Assess exact scope, evidence, risk, rollback, and action digest | Approve only within assigned policy; cannot approve their own T4 request |
| Administrator | Configure identities, providers, connectors, runners, retention, and signed policy bundles | Configuration does not confer action approval |
| Auditor | Verify cases, lineage, decisions, approvals, and audit integrity | Read-only |
| Service actor | Perform a provider, connector, workflow, broker, or runner operation | Narrow machine identity and short-lived task capability only |

Organization, tenant, case, and actor identity are enforced from day one even
when one person initially fills several human roles.

## Supported v1 workflows

COH supports these end-to-end defensive workflows through shared Web, CLI, and
REST/SSE contracts:

1. Alert intake, deduplication, triage, investigation, and evidence-backed handoff.
2. Bounded SIEM queries across Elastic, Security Onion, Splunk, and Microsoft
   Sentinel/Log Analytics, including schema discovery, paging, cancellation, and
   explicit completeness.
3. Multi-source log normalization, entity correlation, time-skew-aware timelines,
   hypotheses, findings, negative evidence, and telemetry-gap recording.
4. Threat hunts with falsifiable hypotheses, bounded scope, expected benign
   patterns, stop conditions, and recorded positive or negative outcomes.
5. Incident-response planning, action preview, governed containment,
   eradication/recovery planning, rollback, and analyst/executive reporting.
6. Sigma detection authoring, explicit field mapping, pinned compilation, native
   validation, bounded canaries, reviewed promotion, and rollback.
7. Threat-intelligence enrichment and provenance using ATT&CK, D3FEND, CWE,
   STIX/TAXII, CVE, NVD, KEV, EPSS, and OSV content.
8. Vulnerability ingestion, normalization, explainable prioritization,
   remediation tracking, retest, exception, and closure across SBOM, VEX, CSAF,
   SARIF, scanner, and asset evidence.
9. Bounded, authorized security validation through signed tool recipes and the
   T0-T4 action model; T4 is isolated and dual-approved.
10. Case management, immutable evidence capture, custody, governed redaction,
    signed import/export, retention, legal hold, and reporting.

## Measurable success outcomes

The product contract is met only when release evidence demonstrates all of the
following; a target date or an enabled-but-hidden flag is not evidence:

| Outcome | Release measure |
|---|---|
| Solo native workflow | On every Tier 1 native platform, a solo analyst can install COH, create a case, qualify a model, execute a bounded SIEM investigation, build a timeline, and export a signed evidence package with Docker absent. |
| Interface and packaging parity | The reference case-critical workflow passes the same contract suite through Web, CLI, and API in native and Compose profiles. |
| Authority containment | The adversarial suite records zero unauthorized side effects, cross-case disclosures, approval replays, scope escapes, or direct model-to-executor actions. |
| Evidence grounding | At least 95% of evaluated factual claims have valid evidence citations and zero claimed artifact identifiers are fabricated. |
| Accountability | 100% of policy decisions and side effects appear in the tamper-evident audit chain. |
| Solo T4 prohibition | Every attempt to execute T4 without two distinct eligible human approvers and all signed ROE prerequisites is denied before dispatch. |
| Support-claim integrity | Every advertised platform, provider, connector, workflow, and security capability has attached, version-specific qualification evidence; unqualified capabilities are labeled unsupported or experimental. |

## Explicit non-goals

- Unsupervised production remediation or containment.
- Replacing a SIEM, log lake, scanner manager, SOAR platform, or enterprise
  identity provider.
- Model-visible credentials, generic model-controlled HTTP, remote shells, or
  unrestricted command execution.
- Self-modifying production skills or automatic promotion of model-generated
  policy, detections, tools, or scope.
- Unrestricted exploitation, arbitrary Metasploit RPC, arbitrary payloads,
  persistence, lateral movement, evasion, or automatic scope expansion.
- Treating a shared Docker Desktop stack as a T4 isolation boundary.
- Token-identical LLM replay; deterministic control-plane and evidence replay is
  required instead.
- Windows-native v1 support. Windows is best-effort Docker-only and is not a
  release gate.
- Delivery commitments based on speculative dates, or support claims concealed
  behind undocumented feature flags.

## Adopted and rejected alternatives

| Source or choice | Adopt | Reject or redesign | Decision reason |
|---|---|---|---|
| [Hermes Agent v0.20.4](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.18) | Provider-independent loop, progressive tool/skill disclosure, context handling, delegation, and observable steps | Personal-agent trust, shared session/container assumptions, process-local delegation, fail-open audit, writable production skills, and oversized control-flow files | Useful analysis mechanics require an external security and durability boundary |
| [OpenClaw v2026.7.1-2](https://github.com/openclaw/openclaw/releases/tag/v2026.7.1-2) | Explicit bounded task states, exact approvals, concurrency limits, narrower nested policy, and durable claiming | Single trusted-operator assumptions, permissive host execution, best-effort completion, and fail-open authentication | Cyber work requires hostile-input handling and deterministic authorization |
| [Gas Town v1.2.1](https://github.com/gastownhall/gastown/releases/tag/v1.2.1) | Durable work graphs, ownership, checkpoints, supervisors, recovery, and E-stop | Worktrees as isolation, terminal injection as control plane, broad host access, and normal bypass modes | Operational durability is valuable; developer-process boundaries are not security boundaries |
| Trusted core | Go services with Temporal behind `WorkflowEngine`, embedded OPA, SQLite workstation storage, PostgreSQL server storage, and immutable evidence | One large agent process, a custom workflow engine, or a Python/Rust trusted core for v1 | Selected approach balances reviewability, portability, durability, and dependency risk |
| Deployment | Native-first plus equivalent optional Compose and signed air-gap bundles | Docker-required installation and shared Docker T4 execution | Native local inference and air-gap use must not depend on a container daemon |
| Tool surface | Typed, allowlisted broker intents and signed recipes | Generic HTTP, shell, arbitrary RPC, and model-authored authorization | A probabilistic model cannot grant or widen authority |

These decisions summarize the dated [research dossier](../../outputs/COH-Research.md),
especially §§3, 6, 13, and 14. Version-specific support is not inferred from
these references; it is earned by qualification evidence for the exact pinned
combination.

## Request and failure behavior

These are product-contract outcomes. Detailed schemas, state machines, policies,
and tests belong to their implementation issues.

| Condition | Required behavior |
|---|---|
| Valid input | Accept only a typed request with required identity, tenant/case scope, data classification, bounded targets/time range, and a registered capability; preserve its provenance. |
| Invalid or unsupported input | Reject before policy or execution; return a safe, actionable validation result; do not invent defaults that broaden scope. |
| Policy or approval denial | Persist the denial and reason without side effects; preserve the request/evidence so the analyst may narrow or revise it. A model cannot override the denial. |
| Pre-dispatch timeout | Preserve durable state and evidence. A bounded retry or qualified provider fallback is allowed only when policy and data route still match. |
| Post-dispatch timeout | Mark the outcome `uncertain`, revoke further attempts, and reconcile through the owning connector. Never report success or retry blindly. |
| Cancellation | Stop new planning and leases, request cancellation of connector-owned work, preserve evidence/audit, and resolve as cancelled or uncertain according to confirmed side effects. |
| Worker/process loss | Recover from durable history, reacquire only expired safe leases, and never convert failed, denied, cancelled, or uncertain work into success or duplicate a confirmed side effect. |
| T4 in solo mode | Deny before dispatch with the unmet second-approver prerequisite; enrollment changes eligibility only and does not retroactively approve an action. |
| Qualification missing or stale | Do not advertise or dispatch the capability as supported; expose the missing evidence and required qualification path. |

## Requirement traceability

| Contract decision | Requirement | Normative PRD locations | Verification evidence |
|---|---|---|---|
| COH is independently installable and runnable; integrations are optional adapters, not host dependencies | **FR-001** | §1 Product definition; §1.2 Goals; §1.5 In scope; §1.6 Non-goals; §13 Locked assumptions | Clean native install and end-to-end solo workflow with Onion Sentinel and other host applications absent |
| Solo T0-T3 operation remains policy-bound; T4 is technically unavailable until two distinct eligible non-requestor human approvers are enrolled | **FR-005** | §1.3 Success measures; §1.4 Personas; §2.1 Action tiers; §13 Locked assumptions | Positive T0-T3 policy fixtures plus T4 denial traces for zero/one approver, duplicate identity, requestor identity, expiry, and ineligibility |
| Releases use evidence-backed support claims, not dates or hidden flags | **NFR-030** | §1.3 Success measures; §10 M9 exit gate; §13 Locked assumptions; §14 Definition of GA | Published support matrix linked to versioned conformance reports, release evidence, and an inspection showing no undocumented release-gating flag |

The broader failure behavior above is normatively defined in PRD §8. This
document does not claim those controls are implemented; their test evidence is
required before the related support claims can be made.

## Approval checklist

- [x] Product owner confirms the primary/secondary personas, supported workflows,
  measurable outcomes, and non-goals.
- [x] Security reviewer confirms solo/T4 separation and denial behavior.
- [x] Requirement reviewer confirms exact coverage of FR-001, FR-005, and NFR-030.
- [x] Local links and cited version URLs pass the recorded link check.
- [x] Reviewer sign-off and the approved document diff are attached to COH-E01-01.

The approval record is `docs/evidence/M0-E01-approval-record-2026-08-25.md`.
