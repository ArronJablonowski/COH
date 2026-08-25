# ADR-0001: Architecture and trust boundaries

| Field | Value |
|---|---|
| Status | Accepted for M0 design freeze |
| Decision date | 2026-08-19 |
| Effective from | Initial implementation |
| Decision owners | COH product owner and security architecture owner |
| Implementation issue | [COH-E01-02 / CYB-31](https://linear.app/cyber-operations-harness/issue/CYB-31/coh-e01-02-record-architecture-and-trust-boundary-adr) |
| Supersedes | None |
| Superseded by | None |
| Normative sources | [COH PRD](../../outputs/COH-PRD.md), [COH research dossier](../../outputs/COH-Research.md) |
| Classification | Public design metadata; no evidence or credentials |
| Approval record | `docs/evidence/M0-E01-approval-record-2026-08-25.md`; independent security review tracked by CYB-173 before production |

## Context

COH processes attacker-controlled logs, alerts, tickets, documents, threat
intelligence, tool output, and model output. It may also propose or execute
consequential actions. A useful model can be persuaded, mistaken, compromised,
or unavailable. A sandbox or connector can fail independently. No prompt,
session, container, or model confidence score can therefore serve as an
authorization boundary.

The product must preserve four security contexts on every request, workflow,
artifact, query, and action:

- `organization_id`: the administrative and policy ownership boundary;
- `tenant_id`: the customer/data-source isolation boundary;
- `case_id`: the investigation, evidence, and approval boundary; and
- `actor_id`: the authenticated human or narrowly enrolled service identity.

The four values are typed identifiers established by the trusted control plane.
They are not accepted from model assertions or inferred from retrieved content.
They remain present in storage keys, workflow references, cache keys, connector
plans, credential leases, audit records, and exported manifests. Missing,
malformed, conflicting, or unauthorized context is a denial, not a default.

## Decision drivers

- Hostile content must remain data even when it contains plausible instructions.
- The probabilistic analysis plane must not acquire deterministic authority.
- Every side effect must have one inspectable, testable authorization path.
- Credentials must be invisible to models and narrowly scoped at dispatch.
- Cross-organization, cross-tenant, and cross-case access must fail closed.
- Indeterminate remote effects must not become successful outcomes or blind retries.
- Native and optional Compose deployments must enforce the same logical
  boundaries.
- T4 execution must remain safe even if a container boundary fails.
- Audit failure must not silently turn consequential operations into unaudited
  work.

## Decision

### 1. The model is an untrusted planner

Models, prompts, retrieved content, tool output, summaries, confidence values,
and model-generated code are untrusted inputs. A model may propose a typed plan,
`ToolIntent`, claim, hypothesis, query, or explanation. It cannot:

- authenticate an actor or service;
- select or widen an organization, tenant, case, target, or data route;
- grant a role, approval, rule of engagement, credential, or capability lease;
- bypass validation, policy, audit, evidence, or confirmation;
- invoke a connector, validator, runner, shell, Docker daemon, or network client
  directly; or
- reinterpret embedded text as control-plane instructions.

Model confidence affects analyst presentation only. It never changes action
tier, validation obligations, approval count, credential scope, retry behavior,
or runner isolation.

### 2. `coh-brokerd` is the sole action authority

Every model-, agent-, or workflow-initiated tool action, connector access,
validator request, runner execution, or other external side effect becomes a
canonical, schema-validated intent and crosses `coh-brokerd`. The broker owns
tool lookup, policy evaluation, approval verification, credential leasing,
dispatch, confirmation, action-evidence publication, and required audit writes.
No provider, agent, workflow, API process, helper, or runner receives an
alternate route to a connector or action endpoint.

This rule does not reroute model inference, authenticated control-plane metadata
commands, or authorized evidence reads through the action broker. Those use the
dedicated provider, API, persistence, and evidence boundaries shown below, but
none of those paths may dispatch a tool or external side effect.

The permitted path is:

`authenticated request → durable workflow → typed intent → broker policy and approval → bounded adapter or runner → confirmation → evidence and audit`

The broker revalidates organization, tenant, case, actor, action digest, policy
revision, target scope, tool identity, credential class, and current execution
preconditions immediately before dispatch. Earlier validation is not a dispatch
capability.

### 3. Architecture and trust-boundary map

```mermaid
flowchart LR
    subgraph Z0["Operator endpoint — untrusted presentation zone"]
        U["Web, CLI, or REST client"]
    end

    subgraph Z1["Authenticated API boundary"]
        A["cohd\nauthentication, authorization, API/SSE"]
    end

    subgraph Z2["Durable control-plane boundary"]
        D["SQL metadata and transactional outbox"]
        T["WorkflowEngine / Temporal"]
        W["coh-workerd\ndurable orchestration"]
    end

    subgraph Z3["Trusted model-gateway boundary"]
        P["coh-providerd\nqualified provider adapter"]
    end

    subgraph Z3U["Untrusted model-runtime boundary"]
        M["Local, hosted, or external model runtime"]
    end

    subgraph Z4["Action-authority boundary"]
        B["coh-brokerd\nschema, policy, approvals, dispatch"]
        K["Credential store\nopaque references and short leases"]
    end

    subgraph Z5["Data-integrity boundary"]
        E["Immutable content-addressed evidence"]
        G["Append-only hash-chained audit"]
        X["Memory, hypotheses, and projections"]
    end

    subgraph Z6["Bounded integration boundary"]
        C["Typed SIEM, CTI, vulnerability, and response connectors"]
        V["Credentialless network-denied validators"]
    end

    subgraph Z6U["External security-system boundary — untrusted remote state"]
        H["Remote SIEM, CTI, vulnerability, and response APIs"]
    end

    subgraph Z7["Disposable low-risk execution zone"]
        R["coh-runnerd\nsigned manifest and leased capability"]
    end

    subgraph Z8["Independent T4 isolation boundary"]
        Q["Dedicated disposable VM or isolated remote zone"]
        N["Exact target-only egress"]
        S["Independent safety watch and E-stop"]
    end

    U -->|"authenticated request; four-part context"| A
    A -->|"authorized command and immutable references"| T
    A --> D
    T --> W
    W -->|"bounded model request"| P
    P <-->|"untrusted prompts and output; no credentials"| M
    W -->|"canonical ToolIntent only"| B
    B -->|"task-scoped dispatch lease"| C
    B -->|"bounded typed input"| V
    B -->|"signed manifest and lease"| R
    B -->|"T4 signed manifest and lease over mTLS"| Q
    K -->|"dispatch-time secret injection; never model-visible"| B
    C -->|"typed result and source receipt"| B
    C <-->|"allowlisted operation; bounded request and result"| H
    V -->|"typed validation result"| B
    R -->|"receipt and evidence references"| B
    Q -->|"receipt, heartbeat, and confirmation"| B
    Q --> N
    S -->|"revokes authority and cuts egress"| Q
    B --> E
    B --> G
    W --> X
    X -.->|"case-scoped references only"| W
    E -.->|"digest-addressed evidence only"| W
```

Arrows are allowlisted contracts, not general reachability. An omitted arrow is
forbidden. Network rules, process identities, socket permissions, mTLS, typed
ports, policy, and architecture tests must make the diagram true in each
deployment profile.

## Boundary catalogue

| Boundary | Trusted side | Less-trusted side | Mandatory enforcement | Fail-closed result |
|---|---|---|---|---|
| Identity | `cohd` authentication and authorization | Clients, headers, prompts, imported data | Establish actor from an authenticated session; bind organization, tenant, and case from authorized records; reject caller/model substitutions | Denied request with a safe correlation ID |
| Process | Narrowly identified Go services | Other processes and hosts | Versioned protobuf/gRPC; restrictive Unix sockets locally; mTLS, enrolled identity, and capability allowlists remotely | No call or lease is issued |
| Model | Durable workflow and provider adapter | Local, hosted, or external model | Qualified adapter, typed I/O, approved data route, no credentials, bounded context and budget | Output is rejected, quarantined as data, or replanned within budget |
| Data | Immutable evidence and tenant/case-scoped metadata | Imported bytes, derived artifacts, memory, projections | Content digests, manifests, classification, lineage, access scope, distinct stores and types | No evidence reference is published until atomic verification succeeds |
| Credential | Credential backend and broker lease issuer | Models, workflows, connectors, runners, diagnostics | Opaque references until dispatch; task-scoped short-lived lease; exact audience, target, operation, expiry, and revocation | Dispatch denied or active lease revoked |
| Broker | Canonical schema, policy, approval, audit, and dispatch logic | Agent/tool requests | Default-deny typed intent; signed policy; exact approvals; current-state recheck; idempotency and confirmation | `denied`, `cancelled`, or `uncertain`; never implicit success |
| Connector | Vendor-specific typed adapter | Remote SIEM, CTI, vulnerability, or response service | Fixed methods, resource allowlists, query/action bounds, separate read/mutation identities, result completeness | Error or incomplete result is preserved; scope cannot widen |
| Validator | Broker validator client | .NET Kusto and Python pySigma helpers | Signed and pinned helper; credentialless, network-denied, read-only, resource-limited, bounded typed I/O | Dependent operation denied; no heuristic fallback |
| Runner | Broker and runner enrollment service | Disposable execution environment and invoked tool | Signed manifest, exact tool digest, leased capability, resource/network confinement, receipt and heartbeat | Lease revoked; cancellation and reconciliation begin |
| Audit | Append-only audit writer and signing key | Services submitting records and ordinary telemetry | Tenant scope, hash chain, durable append, signed checkpoints, independent health | Consequential dispatch is blocked when required audit cannot commit |
| T4 isolation | Independent control plane, approvers, safety watch, and E-stop | Hostile production-validation execution | Separate disposable VM or independently administered remote zone, target-only egress, no ambient services/secrets, two distinct human approvers and signed ROE | T4 remains unavailable or is stopped; never falls back to workstation/Compose |

### Process boundary

Each process has one primary responsibility and a distinct service identity:

- `cohd` authenticates clients and exposes the public API; it does not call
  models or perform consequential side effects.
- `coh-workerd` owns durable state, budgets, cancellation, and orchestration; it
  holds neither credentials nor connector clients.
- `coh-providerd` translates provider-specific model contracts; it does not
  authorize or execute tools.
- `coh-brokerd` is the only process that can authorize dispatch and obtain a
  credential lease.
- `coh-runnerd` executes one signed, leased manifest; it cannot amend scope,
  choose policy, or retain reusable credentials.

Service identity is not inherited from a shared host or container network.
Local calls use permission-restricted Unix sockets and platform peer identity
where supported. Remote service calls require mTLS, enrolled identities,
short-lived certificates, and explicit capabilities.

### Data boundary

Raw evidence, transformed evidence, operational metadata, workflow state,
memory, hypotheses, projections, audit, and telemetry are separate logical data
classes even when a workstation profile co-locates physical storage.

- Raw evidence is immutable and content-addressed.
- A transformation creates a new artifact and a lineage edge; it never rewrites
  source evidence.
- Workflows carry identifiers, digests, bounded status, and retry metadata—not
  raw evidence, secrets, full prompts, or large output.
- Memory and hypotheses may influence planning but cannot satisfy an evidence,
  identity, approval, or authorization check.
- Cache keys and object locators include organization, tenant, and case scope.
- Exports repeat scope, classification, lineage, and integrity metadata and are
  authorized independently.

### Credential boundary

Secrets remain in an approved credential backend. Configuration, prompts,
workflow histories, evidence, audit payloads, diagnostics, and model-visible
tool schemas contain opaque references only. After the broker's final policy
decision, it may exchange a reference for a short-lived lease restricted to one
task, connector or runner, operation, target set, and validity window.

The consuming adapter receives no broader capability than its manifest permits.
Revocation is independent of model and workflow cooperation. A changed action,
expired lease, changed credential version, cancellation, E-stop, or lost runner
health invalidates dispatch authority.

### Connector boundary

Connectors expose finite, typed operations. They are not generic HTTP proxies.
They validate tenant/resource and target allowlists, time and result bounds,
schema/validator state, credential class, and cancellation support before remote
I/O. Read-only query identities and mutation identities are separate. Native
queries, request hashes, bounds, remote identifiers, paging decisions,
statistics, and completeness states return through the broker as evidence.

Remote free text is hostile data. It cannot select another connector operation,
cause a callback, modify a pending intent, or authorize a follow-up action.

### Validator boundary

The Kusto.Language and pySigma helpers are parsers/compilers, not authorities.
They run from pinned signed artifacts with no network, credentials, persistent
write access, or access to unrelated case data. The broker supplies bounded
typed input and validates bounded typed output against a versioned schema.
Unavailability, timeout, malformed output, signature mismatch, or version drift
denies the dependent query or detection operation. Textual or model-based
validation is not a fallback.

### Runner boundary

A runner accepts only a signed manifest and an unexpired broker-issued lease. It
must independently verify the manifest digest, assigned identity, action tier,
organization, tenant, case, actor/requestor, exact target and exclusions, tool
digest, resource limits, network policy, and validity window. It reports a
durable receipt and cannot request expanded authority from the model.

Low-risk native or OCI runners remain disposable and least privileged. They do
not establish that arbitrary hostile execution is safe. No runner receives the
raw Docker socket, ambient control-plane credentials, generic shell service, or
untyped RPC surface.

### Audit boundary

The required audit path is independent of ordinary logs, traces, and metrics.
Authentication, schema rejection, policy, approval, lease, dispatch,
cancellation, confirmation, side effects, evidence transformations, E-stop, and
administrative changes produce tenant-scoped append-only records. Records form a
hash chain and periodic signed checkpoints.

The broker must durably append required pre-dispatch records before a
consequential action and required outcome records during reconciliation. If the
audit path cannot durably commit, the broker blocks new consequential dispatch.
Telemetry may degrade separately but never substitutes for audit.

### T4 isolation boundary

T4 state-changing production validation runs only in a dedicated disposable VM
or an independently administered remote execution zone. It never runs:

- in a `cohd`, `coh-workerd`, `coh-providerd`, or `coh-brokerd` process;
- on the control-plane host;
- as an ordinary workstation process;
- in the shared Docker Desktop Linux VM or ordinary Compose stack; or
- in a low-risk runner merely because that runner uses a container.

The T4 zone has disposable identity and filesystem, exact target/protocol egress,
no route to public Internet, metadata services, package/artifact proxies,
databases, workflow services, or non-target internal networks, and no nearby
long-lived credentials. It receives a single signed recipe and action lease only
after exact policy, signed ROE, two distinct eligible human approvals (neither
the requestor), rollback rehearsal, healthy runner, and staffed safety watch all
pass.

An independent E-stop and heartbeat controller can reject new leases, revoke
active authority, cut egress, and signal work without model or runner
cooperation. T4 is never automatically retried. If any prerequisite is absent,
solo mode remains T4-disabled.

## Failure semantics

| Condition | State and required behavior | Provenance and authority invariant |
|---|---|---|
| Invalid or malformed client request | Reject before workflow creation when possible; otherwise record a terminal validation failure | Preserve safe correlation, actor, scope, schema version, and rejection reason; do not call a model or broker |
| Invalid or malformed model/tool intent | Reject before policy evaluation; record typed validation errors; allow bounded replanning only | Model text cannot become authority, acquire credentials, or reach an adapter |
| Missing/conflicting organization, tenant, case, or actor | Deny without defaulting, inference, or cross-scope lookup | Record the authenticated actor and safe denial reason; expose no protected existence information |
| Policy or approval denial | Transition to `denied`; issue no credential or action lease | Preserve intent digest, policy revision, decision, obligations, and approval references |
| Model timeout or cancellation | Preserve durable run state; retry or provider fallback only within pre-approved route and budget and only before a side effect | Retain model identity, attempt, cancellation source, and evidence references; no authorization changes |
| Validator timeout, cancellation, invalid output, or unavailable helper | Deny the dependent operation; do not use regex, model judgment, or stale success as fallback | Record helper identity/version, input digest, terminal reason, and no-dispatch result |
| Pre-dispatch connector/runner timeout | Cancel or deny the attempt and revoke any prepared lease | Preserve intent/action digest and attempt record; a timeout cannot widen scope or skip approval |
| Post-dispatch timeout or lost response | Transition to `uncertain`, freeze automatic retry, revoke further attempts, and invoke connector-specific reconciliation | Preserve dispatch receipt, remote identifier if known, timestamps, action digest, and incomplete confirmation |
| Explicit cancellation | Stop issuing leases, revoke outstanding authority, signal connector/runner work, and cancel owned remote jobs where supported | Record actor/source, time, affected digest, acknowledgements, and whether execution was confirmed stopped |
| Cancellation or heartbeat loss during execution | Reconcile to `cancelled` only when non-effect or safe stop is confirmed; otherwise use `uncertain` | Never report cancellation as proof that no side effect occurred |
| Indeterminate remote outcome | Remain `uncertain` until operation-specific reconciliation or an attributable human resolution | Never convert uncertainty to success, failure, or safe-to-retry based on model inference |
| Evidence commit failure | Publish no evidence reference until bytes, digest, length, manifest, scope, and atomic commit verify | Preserve the failed attempt in operational/audit metadata without fabricating an artifact ID |
| Required audit failure | Block new consequential actions and surface degraded health | No fail-open dispatch and no substitution of ordinary telemetry |
| T4 heartbeat expiry or E-stop | Revoke leases, cut target egress, signal workflow and runner cancellation, then reconcile | Never retry T4; preserve pre-action evidence, watch events, action receipts, and final uncertainty |

The valid consequential-action state progression is:

`planned → policy_checked → awaiting_approval → prepared → executing → confirmation_pending → verified | compensated | uncertain | denied | cancelled`

Transitions must be durable and monotonic with respect to authority: recovery may
resume analysis or confirmation, but it cannot recreate an expired approval,
lease, credential, target scope, or T4 prerequisite.

## Enforceable rules and verification

The normative package, identity, connector, runner, validator, audit, deployment,
and T4 enforcement rules and their success/failure evidence matrix are maintained
in the [ADR-0001 verification contract](0001-trust-boundaries-verification.md).
That companion is part of this decision and must pass the same review and change
control. It explicitly rejects workflow/provider bypasses to connectors or runners.

## Alternatives rejected

| Alternative | Rejection rationale |
|---|---|
| Trust the model or prompt | Prompt injection, compromised retrieval, provider drift, and ordinary model error would become authorization mechanisms; natural language is not canonical authority. |
| Put tools in the agent/provider process | Creates alternate execution paths, mixes credentials with hostile content, weakens audit coverage, and turns process compromise into action authority. |
| Offer generic HTTP, shell, evaluator, Docker, or RPC tools | A generic primitive can reconstruct withheld capabilities; production tools must be finite domain operations with validated targets, arguments, cost, and effects. |
| Share evidence, memory, and hypothesis storage | Derived or model-authored text becomes hard to distinguish from preserved observations and can leak through retrieval or cache reuse. |
| Trust validator helpers as general services | Helpers process hostile syntax and dependencies; their result informs policy but grants no authority, and compromise must expose neither credentials nor network. |
| Use an ordinary container or shared Docker Desktop stack for T4 | Container hardening is defense in depth; a shared Linux VM remains in the control-plane host trust domain and exposes nearby services if isolation fails. |
| Retry all timeouts automatically | A lost response may hide a completed remote effect, so retry could duplicate containment, mutation, notification, scanning, or validation. |
| Use best-effort telemetry as audit | Telemetry may be sampled, dropped, reordered, or unavailable; consequential authority needs a durable, integrity-protected audit path. |

## Non-goals

This ADR does not:

- define all API, protobuf, policy, lease, evidence, or audit schemas;
- select a network-policy, VM, PKI, secret-backend, or sandbox vendor;
- implement authentication, policy, connectors, validators, runners, or tests;
- authorize any T2, T3, or T4 action;
- make prompt injection impossible or model analysis trustworthy;
- claim that containers alone contain hostile code;
- replace detailed threat modeling, data-classification, deployment, incident
  response, or disaster-recovery design; or
- permit persistence, lateral movement, unrestricted exploitation, generic
  shells, arbitrary payloads, or automatic scope expansion.

## Consequences

### Positive

- The authorization boundary remains deterministic even when model analysis is
  wrong or manipulated.
- A single action path makes policy, audit, testing, incident analysis, and
  revocation reviewable.
- Four-part context and separate data classes reduce cross-tenant and cross-case
  disclosure risk.
- Short-lived leases reduce credential exposure and make cancellation and E-stop
  effective without model cooperation.
- Explicit `uncertain` outcomes prevent unsafe duplicate side effects.
- Physically separate T4 execution limits damage if a container or tool escapes.

### Costs and constraints

- Every integration requires a typed adapter, schema, policy input, result
  envelope, confirmation strategy, and negative tests.
- The broker is security-critical and must be highly available without becoming
  fail-open; its policy, audit, and credential dependencies need explicit health.
- Remote runner enrollment, mTLS, target-only networking, and independent T4
  infrastructure increase operational complexity.
- Some useful operations remain unavailable when a validator, audit store,
  second approver, safety watch, or sufficiently isolated runner is absent.
- Generic agent-tool ecosystems cannot be exposed directly in production.

### Residual risks

- A model can still produce poor analysis or manipulate analyst attention.
- A compromised, correctly authorized connector may misuse its scoped remote
  credential until expiry or revocation.
- Kernel or hypervisor compromise remains possible in isolated execution.
- A privileged host administrator can destroy local data even though integrity
  checks make undetected mutation harder.
- Vendor APIs may not provide reliable confirmation, leaving some actions in
  `uncertain` until manual reconciliation.

These risks require evidence citations, reviewer challenge, least privilege,
short lease lifetime, independent monitoring/checkpoints, backups, adversarial
evaluation, and the option for policy to prohibit T4 entirely.

## Deployment implications

- Native workstation co-location preserves process identities, typed ports, logical
  stores, protected sockets, and broker-only dispatch.
- Native server mode separates services and uses mTLS plus distinct OS/database identities.
- Optional Compose packaging preserves the same contracts, identities, networks,
  credential references, and broker-only action path; its network is not implicit trust.
- Docker absence must not change policy or disable logical boundaries.
- Air-gapped mode denies outbound fallback; local providers and offline packs do
  not receive extra authority.
- No native or Compose profile can relabel its ordinary runner as T4-capable.

## Traceability

The normative requirement scope of this ADR is exactly the following four PRD
requirements:

| Requirement | ADR decision and verification hook |
|---|---|
| `SEC-001` | “The model is an untrusted planner” denies identity, scope, authorization, and credentials from all model-associated inputs; invalid-intent and hostile-content tests verify it. |
| `SEC-002` | The broker-only action path, process dependency rules, lease audience, and architecture/network tests make `coh-brokerd` the sole action authority. |
| `SEC-017` | Agent/provider surfaces exclude generic HTTP, unrestricted shell, arbitrary evaluators, raw Docker sockets, and untyped RPC; registry and import tests enforce the exclusion. |
| `SEC-026` | The independent T4 boundary and runner-enrollment negative tests reject control-plane-host, workstation-process, low-risk-runner, and ordinary Docker Desktop/Compose execution. |

No additional PRD requirement is claimed as implemented or satisfied by this
documentation-only decision.

## Change control

Once approved, this ADR is binding for the initial implementation. A change to a trust assumption,
allowed edge, identity context, credential visibility, broker authority, agent tool,
validator privilege, runner class, audit behavior, uncertainty rule, or T4 isolation
requires all of the following before implementation:

1. a new superseding ADR; this accepted record is not edited to conceal history;
2. an updated threat model and data-flow diagram;
3. explicit mapping to changed PRD requirements and affected action tiers;
4. security- and product-owner approval, with separation-of-duty review for reduced control;
5. updated success, denial, timeout, cancellation, recovery, bypass, and isolation tests; and
6. migration, rollback, operator-documentation, and release-evidence updates.

Editorial corrections may use normal review. Each release verifies that deployed
process, package, network, credential, model, connector, validator, runner, data,
and audit edges still match this decision.
