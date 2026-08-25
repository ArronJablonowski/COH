# COH T0–T4 Action-Tier Decision Table

## Governance metadata

| Field | Value |
|---|---|
| Decision ID | `COH-E01-03` |
| Linear issue | [CYB-30](https://linear.app/cyber-operations-harness/issue/CYB-30/coh-e01-03-define-the-t0-t4-action-decision-table) |
| Status | Accepted for M0 design freeze |
| Version | 1.0 |
| Decision date | 2026-08-19 |
| Effective date | 2026-08-19 |
| Decision owner | Security Architecture |
| Accountable owner | Product Owner |
| Required reviewers | Product, Security Architecture, and Implementation |
| Approval basis | Proposed implementation of the approved [COH PRD](../../outputs/COH-PRD.md) and dated [COH research dossier](../../outputs/COH-Research.md) |
| Review evidence | Approved 2026-08-25 at source checkpoint `8c6012d`; independent security architecture review tracked by CYB-173 before production |
| Data classification | Internal product-governance metadata; no credentials or case evidence |
| Security impact | High: defines the authorization floor for every tool action |
| Migration impact | None for this document; future tier changes may require policy, manifest, workflow, and stored-action migrations |
| Supersedes | None |
| Next review | Before a new action class, execution zone, approval mode, or tier semantic is introduced, and at every major release |
| Normative language | “Shall,” “must,” “never,” and “required” are mandatory; “may” is explicitly discretionary |

This document is the accepted M0 decision record for classifying and controlling COH
actions. It records design intent and does
not itself grant authority. Signed tool manifests and signed runtime policy implement
the approved decision, and `coh-brokerd` is the sole action authority.

## Decision

COH uses five monotonically stricter action tiers, T0 through T4. A tier is selected
from the action's observable effects, target environment, reversibility,
intrusiveness, credential class, and required isolation—not from model confidence,
operator wording, or the purported purpose of the action.

The following invariants apply to every tier:

1. An action must arrive as a schema-valid, canonical `ToolIntent` carrying
   organization, tenant, case, actor, exact operation, exact targets and arguments,
   tool/version, credential class, requested data route, and applicable ROE and
   policy references.
2. The referenced signed tool manifest must be valid and must explicitly enumerate
   the operation and its baseline tier. It also defines the highest action tier that
   the tool is allowed to perform.
3. Runtime policy may deny or narrow a manifest's allowed capability ceiling. It
   cannot lower an operation's required control tier or extend the signed manifest
   to a higher tier. Raising the manifest ceiling or adding an operation requires a
   newly reviewed and signed manifest.
4. Deterministic contextual rules may escalate the required control tier. If the
   context requires a tier above the effective signed capability ceiling, the broker
   denies the action; it does not relabel or improvise authority.
5. Missing, unknown, unsupported, contradictory, or ambiguous values—including an
   unknown tool, operation, target, tenant, data route, tier, validator state, or
   capability field—fail closed. If deterministic classification cannot select one
   tier, the action is denied and must be corrected or governed through change
   control. Human approval cannot make an unknown action executable.
6. Embedded OPA evaluates the signed policy at intent creation and again immediately
   before dispatch. The dispatch-time decision controls. Policy drift invalidates
   preparation and requires a new decision and, when bound fields changed, new
   approval.
7. The model, prompts, retrieved content, tool output, and model confidence never
   supply identity, scope, approval, credentials, or authorization.
8. A consequential action cannot dispatch unless its required policy, approval,
   evidence, audit, credential, runner, and isolation prerequisites are healthy.

### Classification precedence

The broker applies these controls in order:

`schema validation → identity/scope validation → manifest signature and operation → baseline tier → contextual escalation → effective capability ceiling → policy decision → approval validation → audit reservation → credential/runner lease → dispatch`

Any denial stops the chain before credentials or an execution lease are issued.
When more than one row appears applicable, the stricter tier wins only if a signed
manifest and deterministic rule explicitly permit that classification. Otherwise,
the ambiguity is denied.

## Normative T0–T4 decision table

| Tier and representative actions | Authorization and approvals | Required isolation | Evidence and audit | Rollback or compensation | Retry and uncertain outcome | Cancellation and E-stop |
|---|---|---|---|---|---|---|
| **T0 — offline analysis and derived artifacts.** Parse, sort, correlate, or summarize already authorized immutable evidence; build a local timeline; generate hypotheses or a draft report; perform offline schema or query syntax validation; compile a detection into an unpromoted artifact. T0 must not contact a remote source, acquire a credential, mutate authoritative state, or execute active content. | Automatic after schema, case/tenant authorization, manifest, data-class, resource-budget, and signed-policy checks. No human approval. An offline action that needs network access, a credential, or an external side effect is not T0. | Case-scoped analysis worker with no external network and no action credential. Inputs are read-only evidence references; output is written atomically to the evidence/artifact store. Approved validator helpers remain credentialless, network-denied, resource-limited, and ephemeral. | Record actor/case, canonical intent digest, input artifact digests, tool/model/parser versions, policy decision, budgets, transformation lineage, output digest, completeness, and outcome. Derived artifacts never replace source evidence. Required audit failure denies publication of the artifact reference. | Supersede or retract the derived artifact while retaining source evidence and lineage. Atomic publication leaves either a complete digest-verified output or no resolvable output. | A pure, idempotent computation may receive bounded retries from the same immutable inputs before publication. Timeout or crash must not publish a partial artifact as complete. A disputed commit is reconciled by digest/reference lookup; it is never guessed successful. | Cooperative cancellation stops compute and records `cancelled`. A case/global E-stop signals active work and prevents new leases. No credential revocation or egress cut is normally needed because T0 has neither. |
| **T1 — bounded read-only access to pre-authorized sources.** Run bounded SIEM searches; retrieve approved CTI, vulnerability, asset, or connector metadata; poll or page a connector-owned read-only query; fetch an immutable object by authorized reference. A query that can invoke macros, writes, real-time search, arbitrary HTTP, or an unbounded export is not T1. | Automatic only under signed standing policy for the exact connector, tenant, resource, operation, credential class, purpose, time range, and limits. No per-action human approval. Read-only credentials and `allow_partial=false` are mandatory defaults. Policy may require an approval for unusually costly T1 work; that obligation cannot weaken other controls. | Broker-mediated, tenant-scoped connector with a short-lived read-only credential lease, allowlisted resources, mandatory UTC `[start,end)` range, and enforced row, byte, cost, rate, and deadline limits. Generic network or shell access is unavailable. | In addition to the common action record, preserve native query/request, canonical hash, enforced bounds, schema and validator versions, source response metadata, pages/slices, statistics, cost, and completeness. Partial, truncated, rate-limited, cancelled, expired, and uncertain results remain distinct from complete success. Audit covers policy, lease, connector call, cancellation, and result publication. | No remote state rollback is expected. Delete or supersede only derived projections; immutable query evidence remains governed by retention. Cancel connector-owned jobs and revoke the credential lease when work stops. | Bounded retries are allowed only where the connector contract proves the read is safe and observes the same deadline and budget. Before resubmitting a connector-owned job, reconcile its opaque handle. Lost or indeterminate results become incomplete or `uncertain`; they never become complete by inference. | Cancellation propagates to connector-owned jobs, revokes the lease, persists available rows as explicitly incomplete when safe, and records `cancelled` or `uncertain`. E-stop rejects new leases, revokes current credentials, attempts remote-job cancellation, signals workflows, and preserves evidence/audit. |
| **T2 — exact reversible mutation.** Publish or update a draft or staging detection; change reversible case/workflow metadata; create, update, or close an external ticket when the connector supplies deterministic reversal; enable a bounded, quickly reversible configuration in an approved non-critical scope. If reversal is absent, unverified, destructive, or likely to interrupt security/business service, classify at least T3. | Held for one eligible human's exact, expiring approval. Separation between requestor and approver is preferred and may be required by policy; solo T2 is possible only when signed policy explicitly permits the same eligible human to request and approve. Approval is single-use by default and must remain valid at dispatch. | A distinct least-privilege mutation connector or low-risk runner with a task-scoped credential/capability lease. It receives only approved targets and arguments. Query credentials cannot be reused for mutation. Network and filesystem access are limited to the action manifest. | Capture pre-action state, plain-language preview, canonical action digest, both policy decisions, approval identity and binding, lease, dispatch receipt/external ID, post-action verification, and final state. Audit append failure blocks dispatch. | A tested compensating operation, restoration snapshot, or deterministic reverse API is required in the action manifest. Compensation is a new policy-controlled action and is recorded; it does not erase the original receipt. | Safe preparation may retry before dispatch. A mutation is idempotent only when its connector contract and remote idempotency key prove it. A post-dispatch timeout, lost acknowledgement, or conflicting remote state transitions to `uncertain`, freezes automatic retry, and requires reconciliation. | Pre-dispatch cancellation produces `cancelled` and invalidates unused execution authority. During execution, cancel cooperatively and reconcile; compensate only under policy. E-stop rejects/revokes leases and credentials, cuts runner egress where present, cancels remote work, and signals reconciliation. |
| **T3 — containment, destructive change, or intrusive scanning.** Isolate or release an endpoint; disable an identity or revoke sessions; deploy a production block or potentially service-affecting detection; delete/quarantine authoritative data; run an intrusive or authenticated scan; perform eradication or another change with material blast radius. A state-changing production vulnerability-validation action is T4, not T3. | Held for explicit exact approval by at least one eligible human; signed policy may require two. Requestor/approver separation is policy-controlled for T3 so a solo deployment can operate only where policy expressly allows it. Irreversibility, critical assets, large scope, or missing verification may trigger a second approval or denial. Approval is exact, expiring, revocable, and single-use by default. | Dedicated least-privilege connector or approved isolated runner appropriate to the hazard. Intrusive scanners require signed recipes, exact allowlisted targets/exclusions, bounded rate/time/resources, and restricted egress. The control-plane host and ordinary agent process never execute the action. Isolation requirements may be stronger than Docker containment. | All T2 records plus affected-service owner, blast-radius analysis, health/safety telemetry, stop conditions, rollback owner, pre-action evidence, confirmation evidence, post-action evidence, and residual risk. Policy, approvals, leases, side effects, E-stop, and compensation are fail-closed audit events. | A reviewed rollback or compensating plan is mandatory. Where an effect is inherently irreversible, the manifest must say so plainly and policy must explicitly admit the exact action; “best effort” is not represented as rollback. Failed verification invokes safe stop, reconciliation, and approved compensation. | No blind retry after dispatch. Preparation may retry before any authority is consumed. Connector idempotency and confirmation are still required. Any indeterminate side effect becomes `uncertain`; automatic attempts freeze until an authorized human or connector-specific reconciliation resolves observed state. | Cancellation before dispatch revokes approval use and leases. During execution, stop at a documented safe point, revoke authority, cut egress, and determine `cancelled`, `compensated`, or `uncertain` from evidence. E-stop always applies and cannot depend on model/worker cooperation. |
| **T4 — state-changing production validation.** Execute a curated signed module or recipe against an exact production target to validate exploitability or another vulnerability by intentionally causing a controlled state change. T4 excludes arbitrary payloads, shells, persistence, evasion, credential dumping, lateral movement, pivoting, or target expansion. | Denied unless there is a signed, in-window ROE and two distinct eligible authenticated human approvers, neither of whom is the requestor. The requestor satisfies neither approval. A staffed safety watch, rehearsed rollback, healthy isolated runner, exact action binding, and fresh dispatch policy decision are mandatory. **T4 is unavailable until both eligible non-requestor approvers are enrolled. A human-requested T4 action normally requires at least three distinct humans including the requestor; administrator status cannot waive this rule.** | Execute exactly once in a dedicated disposable VM or approved isolated remote zone—never on the control-plane host, an ordinary workstation process, or the shared Docker Desktop/Compose stack. Use a single-use capability lease, no ambient credentials, exact target-only egress, and no access to public Internet, metadata, package/artifact services, control-plane data, GPUs, or non-target networks except required control endpoints. | Preserve signed ROE and its digest; exact inclusions/exclusions, window, method, rate, stop conditions, tool/module/payload/image digests; both approvals; rollback rehearsal; safety-watch heartbeats; pre-action snapshot; lease; network policy; runner attestation; complete execution trace; external receipts; health telemetry; E-stop events; confirmation; post-action evidence; cleanup; reconciliation; and residual risk. Audit or evidence failure denies dispatch. | A rehearsed rollback and cleanup recipe, owner, verification criteria, and safe-stop behavior are mandatory. If rollback cannot be demonstrated before the window, deny. Rollback is separately observed and evidenced; an inability to confirm it produces `uncertain` and immediate escalation. | T4 dispatch is exactly once and is **never automatically retried**, including after timeout, worker loss, control-plane restart, or indeterminate response. Recovery may only reconcile the original attempt. An indeterminate outcome becomes `uncertain`, revokes authority, preserves the zone, and requires human resolution. | Global or case E-stop rejects new leases within 1 second, cuts runner egress within 2 seconds, signals workflows within 5 seconds, and terminates cooperative work within 10 seconds. Heartbeat expiry triggers the same safe-stop path. E-stop revokes outstanding authority independently of the model and worker, preserves the isolated zone/evidence, and starts reconciliation. |

## Approval binding and separation of duties

Every T2–T4 approval binds all of the following canonical fields:

- canonical action digest and schema version;
- organization, tenant, case, requestor, and action owner;
- signed policy bundle identity and revision;
- ROE identity and digest when applicable;
- exact inclusions, exclusions, targets, operation, and arguments;
- credential class, tool identity/version, and binary, image, module, recipe, or
  payload digest as applicable;
- execution zone and required isolation profile;
- validity start/end, maximum use count, and approval nonce; and
- rollback/compensation identity and safety-watch binding where required.

Canonicalization must reject duplicate keys, invalid encodings, non-finite numbers,
unresolved aliases, and non-normalized targets rather than producing competing
digests. Any byte-level change to a canonical bound input invalidates the approval.
An expired, revoked, consumed, replayed, wrong-case, wrong-policy, or wrong-action
approval is unusable. Approval records are evidence of a human decision, not bearer
authority; the broker still reevaluates identity, policy, scope, health, and current
preconditions at dispatch.

Separation rules are:

- T0 and T1 do not require a per-action approver.
- T2 requires one eligible approval; signed policy decides whether the approver must
  differ from the requestor.
- T3 requires at least one eligible approval, may require two, and may require
  requestor separation according to signed policy and context.
- T4 always requires two distinct eligible human approvers. Neither may be the
  requestor, service actor, model identity, or the same human under another account.
  Identity-linkage and eligibility checks fail closed.
- Enrollment, role assignment, or policy administration performed solely to satisfy
  an in-flight approval cannot retroactively validate that approval.

## Failure, cancellation, and recovery decision table

| Condition | Required state and behavior | Required record |
|---|---|---|
| Malformed or non-canonical input | Reject before execution. Do not infer omitted fields, ask the model to fill authority fields, issue credentials, or request approval. A corrected intent is a new intent. | Safe validation error, actor/case/correlation IDs, schema version, redacted reason, and attempted input digest when one can be computed safely. |
| Unknown or ambiguous action/tier/capability | `denied`. Human approval cannot override the missing signed classification. Add or clarify the operation only through manifest and policy change control. | Default-deny policy result, missing/ambiguous fields, manifest and policy revisions, and no-lease proof. |
| Policy denial or unavailable/invalid policy | `denied`; no dispatch. An invalid or unavailable bundle never falls back to an older or permissive policy silently. | Signed-bundle identity if available, evaluation input digest, reasons/obligations, health degradation, and no-lease proof. |
| Approval denied, expired, revoked, consumed, replayed, or mismatched | `denied`; invalidate prepared state and do not dispatch. A new approval request uses a new nonce and the current canonical digest. | Approval identity, decision/reason, binding comparison without secrets, replay or expiry evidence, and audit event. |
| Pre-dispatch deadline or operator cancellation | `cancelled`; invalidate prepared authority, revoke leases, and cancel connector-owned preparation. No external side effect may be reported. | Cancellation actor/source, last durable state, approval-use disposition, lease revocation, and confirmation that dispatch did not occur. |
| Timeout or cancellation after dispatch | Signal safe stop, revoke authority, cancel remote jobs, and reconcile. Use `cancelled` only when evidence confirms no lasting side effect; use `compensated` after verified reversal; otherwise use `uncertain`. | Dispatch receipt, signals, external status, observed state, evidence completeness, compensation, and reconciliation owner. |
| Worker or control-plane loss | Resume from durable history, verify audit/evidence integrity, and reacquire only expired safe leases. Never convert a failed, denied, cancelled, or uncertain action to success. Never redispatch T4 or any uncertain side effect. | Recovery event, workflow version/replay result, prior receipt, lease status, policy revision, integrity checks, and reconciliation decision. |
| Audit append/checkpoint unavailable | Block T2–T4 and any T1 marked consequential by policy. T0 publication and ordinary T1 follow the signed fail-closed policy; no required audit record may be dropped. | Degraded health signal and, after recovery, a gap-free audit/accounting record proving no blocked action dispatched. |
| Evidence write or verification failure | Publish no resolvable artifact reference. Consequential dispatch requiring pre-action evidence is denied; post-dispatch failure becomes `uncertain` until reconciled. | Quarantined temporary object metadata, digest/length failure, action receipt if dispatched, and recovery result. |
| E-stop or safety-watch heartbeat expiry | Reject new leases, revoke outstanding authority, cut runner egress, cancel remote work, signal workflows, preserve evidence, and reconcile. T4 uses the timing objectives in the normative tier table. | Scope and actor of stop, monotonic timestamps for each control, affected leases/jobs/runners, failures, and final reconciled states. |

## Alternatives considered

| Alternative | Decision |
|---|---|
| Let the model select or waive an action tier | Rejected. Model output is untrusted data and cannot be an authorization boundary. |
| Treat all tool calls alike behind one confirmation dialog | Rejected. It encourages approval fatigue and fails to match control strength to external effect. |
| Use broad standing human approval for mutations | Rejected. T2–T4 approvals bind an exact canonical action and expire; T1 standing authority is bounded signed policy, not a mutable human approval. |
| Permit an operator to approve an unknown action as T4 | Rejected. Unknown or ambiguous capabilities have no reviewed manifest, isolation contract, or test evidence and therefore fail closed. |
| Allow policy to promote a tool above its signed manifest | Rejected. Extending authority requires a newly reviewed and signed manifest. |
| Require a distinct approver for every T2/T3 action | Not adopted as a universal rule because the approved product contract permits policy-bounded solo T0–T3 use. Policy may impose separation or dual approval for specific contexts. |
| Let the requestor provide one T4 approval | Rejected. The requestor satisfies neither approval, and two distinct eligible humans are mandatory. |
| Use the ordinary shared Compose stack as T4 isolation | Rejected. Containers are defense in depth and do not establish the required hostile-execution boundary. |
| Automatically retry state changes after a timeout | Rejected. A lost response does not prove a failed side effect; reconciliation and `uncertain` are required. |
| Expose generic HTTP, shell, Docker socket, or Metasploit RPC and rely on approval | Rejected. These surfaces defeat exact classification, least privilege, scope enforcement, and meaningful approval. |

## Non-goals

This decision does not:

- implement OPA policy, approval storage, workflows, connectors, credential leasing,
  runners, E-stop controls, or their test suites;
- authorize any real action or serve as a substitute for a signed manifest, policy,
  approval, ROE, or credential lease;
- provide an exhaustive inventory of future tools or operations;
- permit unrestricted exploitation, arbitrary payloads or shells, persistence,
  lateral movement, evasion, credential dumping, or automatic target expansion;
- permit unsupervised production remediation, containment, or T4 execution;
- claim that Docker, a container, a worktree, or a model sandbox is a sufficient T4
  boundary; or
- guarantee recovery of an irreversible effect; uncertainty and residual risk must
  remain visible when compensation cannot restore prior state.

## Change control

1. Changes to tier meaning, approval count, requestor separation, T4 isolation,
   E-stop behavior, or default-deny semantics require an approved PRD revision and
   an architecture decision. They cannot be made only in runtime policy.
2. A new tool or operation requires a schema, deterministic classification,
   reviewed signed manifest, threat analysis, isolation profile, success and denial
   fixtures, timeout/cancellation/recovery tests, and an accountable owner.
3. Increasing a tool's signed capability ceiling, changing executable/recipe
   identity, or adding targets/arguments requires a new signed manifest. Runtime
   policy may only narrow or deny allowed capability.
4. Any policy, manifest, ROE, tool, target, argument, credential class, isolation, or
   rollback change invalidates affected prepared actions and approvals. They return
   to policy review; stale approvals are never grandfathered.
5. Every semantic change receives a new version, migration/replay assessment,
   adversarial tests, documentation update, requirement trace, and reviewer sign-off.
6. Emergency policy may deny more work immediately. Emergency widening of authority
   is prohibited; normal signed change control still applies.

## Requirement traceability

| Requirement | Decision evidence in this document |
|---|---|
| `SEC-003` | Default-deny invariants, classification precedence, unknown/ambiguous failure row, and invalid-policy handling deny unknown tools, targets, tenants, routes, tiers, validators, and capability fields. |
| `SEC-005` | Invariants 2–4 and change-control items 2–3 bind operations to signed manifest classifications and allow runtime policy to narrow, never extend, the capability ceiling. |
| `SEC-006` | The approval-binding section enumerates action, policy, ROE, tenant/case, targets/arguments, credential, tool/version/digests, validity, use, and execution bindings. |
| `SEC-007` | The T4 row and separation rules require two distinct eligible authenticated humans and prohibit the requestor from satisfying either approval. |
| `SEC-008` | T2–T4 rows plus approval binding require exact, expiring, revocable, case/action-bound approvals that are single-use by default and replay-protected. |

Related controls carried forward for implementation include `FR-005`, `FR-012`
through `FR-015`, `FR-074` through `FR-077`, `SEC-001`, `SEC-002`, `SEC-004`,
`SEC-009`, `SEC-020`, `SEC-022`, `SEC-026` through `SEC-030`, and `EVAL-005`,
`EVAL-007` through `EVAL-011`.

## Acceptance evidence required by COH-E01-03

Before the Linear issue can move to Done, reviewers must attach:

- the approved document diff and Product/Security/Implementation sign-off;
- a link check for the PRD, research dossier, and Linear issue;
- a requirement-trace report covering `SEC-003`, `SEC-005`, `SEC-006`,
  `SEC-007`, and `SEC-008`;
- review evidence that representative T0–T4 actions cover authorization,
  approvals, isolation, evidence/audit, rollback, retries, uncertainty,
  cancellation, recovery, and E-stop;
- negative review fixtures for invalid input, unknown/ambiguous classification,
  denial, expired/replayed approval, timeout, cancellation, worker loss, audit
  failure, evidence failure, and E-stop; and
- the repository line-size result and confirmation that no critical/high defect,
  secret, forbidden license, or unapproved dependency was introduced.

No new external version claim is introduced by this decision. Source links and
version-sensitive claims remain governed by the 2026-08-19 research snapshot.
