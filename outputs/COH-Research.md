# Cyber Operations Harness (COH): Deep-Research Dossier

- **Research snapshot:** 2026-08-19
- **Product:** Cyber Operations Harness (COH)
- **Status:** Architecture and product-requirements research baseline
- **License assumption:** Apache-2.0
- **Intended audience:** Product engineering, security architecture, SOC practitioners, detection engineers, incident responders, and independent reviewers

## Executive summary

COH should be a security control plane with an LLM-assisted planner, not an LLM with powerful tools attached to it. The model may propose, explain, rank, and synthesize. Deterministic services outside the model must authenticate identities, authorize exact actions, enforce case and target scope, lease credentials, constrain queries, isolate execution, record evidence, and stop work.

The strongest ideas from the researched agent harnesses are complementary:

- Hermes Agent contributes a provider-independent agent loop, progressive tool and skill discovery, context management, provider adapters, delegation, and a practical developer experience.
- OpenClaw contributes bounded task states, explicit tool-policy precedence, exact approvals, concurrency lanes, and durable child-task semantics.
- Gas Town contributes durable work graphs, identity/session separation, supervision, checkpoints, and an operational E-stop mindset.

Their assumptions cannot be imported wholesale into a cybersecurity product. A personal-agent trust model, host-visible shells, shared persistent containers, best-effort child announcements, non-durable prompt layers, fail-open audit hooks, and autonomous skill mutation are incompatible with high-assurance SOC and incident-response work.

COH therefore needs five hard boundaries:

1. A durable, typed workflow control plane independent of model context.
2. A sole action broker that evaluates signed policy immediately before every side effect.
3. Immutable evidence and a separate, fail-closed, tamper-evident audit trail.
4. Provider-, connector-, case-, tenant-, and execution-zone isolation with short-lived credentials.
5. A graduated action model in which production state-changing validation is unavailable without a signed rules of engagement (ROE), two distinct approvers, a safety watch, rollback, and dedicated isolation.

The recommended trusted core is Go, with Temporal hidden behind a workflow-engine interface, embedded OPA for policy, SQLite for the workstation profile, PostgreSQL for server deployments, and a filesystem content-addressed evidence store. Native processes are the primary deployment. A complete Docker Desktop/Docker Compose profile is supported but optional. Two narrowly scoped helpers—Microsoft Kusto.Language and pySigma—are accepted because replacing their authoritative parsers with ad hoc Go implementations would create more security risk than isolating them.

## 1. Research question, method, and confidence

### 1.1 Research question

What architecture best supports evidence-grounded, auditable, and safely bounded LLM assistance for:

- SIEM investigation and query generation;
- log correlation and event timelines;
- incident response and containment planning;
- threat hunting and threat-intelligence enrichment;
- detection engineering and validation;
- vulnerability discovery, prioritization, remediation, and retesting;
- authorized active validation under explicit ROE; and
- normal SOC reporting, review, and handoff?

### 1.2 Method

The research prioritized primary sources in this order:

1. Official specifications, standards, release notes, and vendor API documentation.
2. Source repositories and security documentation for the referenced agent systems.
3. Official engineering incident reports and architecture publications.
4. Peer-reviewed or vendor-published benchmark papers where no specification exists.

Version-sensitive findings are pinned to the 2026-08-19 snapshot. “Recommended” means suitable for the stated COH threat model, not universally superior. URLs in the source ledger are direct sources rather than search-result pages.

### 1.3 Confidence conventions

- **High:** Normative specification, official API contract, release notes, or directly inspected source behavior.
- **Moderate:** Official design documentation whose behavior still requires a COH conformance test.
- **Provisional:** Emerging benchmark, fast-changing integration, experimental backend, or behavior not guaranteed by a stable public contract.

All third-party runtime behavior remains untrusted until exercised by COH's qualification suite.

## 2. Decision synopsis

| Topic | Adopt | Reject or constrain | COH implication |
|---|---|---|---|
| Agent loop | Typed plan/act/observe/review loop | A monolithic, process-local loop as the system of record | Workflow state lives outside prompts and processes |
| Tools | Progressive discovery and typed contracts | Model-selected generic HTTP, arbitrary shell, or ambient credentials | Every operation crosses the broker |
| Delegation | Bounded hierarchical tasks | Unlimited fanout, recursive autonomy, best-effort completion notices | Durable child records with budgets and evidence references |
| Memory | Case-scoped retrieval and compaction | Mixing evidence, preferences, hypotheses, and summaries | Separate stores and trust labels |
| Policy | Exact, expiring approvals | Natural-language authorization or approval of a mutable plan | Approval binds a canonical action digest |
| Durability | Temporal behind an internal port | Custom workflow engine or automatic retry of unknown effects | Replay tests and an explicit `uncertain` terminal state |
| Audit | Append-only hash chain and signed checkpoints | Fail-open observer callbacks as the audit system | Consequential actions fail closed if audit is unavailable |
| Runtime | Native-first Go services | Docker as a mandatory dependency | Native and Compose profiles share contracts and tests |
| Isolation | Disposable, zone-specific workers | Shared control-plane containers as an exploit boundary | T4 uses a dedicated VM or remote execution zone |
| Providers | Dedicated adapters and qualification | A generic “OpenAI-compatible” adapter | Preserve each provider's real semantics and limitations |
| SIEM | Vendor-aware read-only adapters | One universal query string or generic REST escape hatch | Parse, bind, bound, canary, and preserve completeness |
| Detection | Sigma with explicit mappings and native validation | Treating successful text conversion as supported | Compilation is a tested, versioned supply chain |
| Vulnerability risk | Explainable ordered factors | Multiplying EPSS and CVSS into an opaque score | Preserve source, version, date, and rationale |
| Active testing | Signed recipes under tiered ROE | Generic exploit consoles, persistence, or lateral movement | T4 requires dual approval and exact isolation |

## 3. Harness precedents

### 3.1 Hermes Agent v0.20.4

The research baseline is [Hermes Agent v0.20.4 / v2026.8.18](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.18), not an unpinned branch.

#### Adopt

- A canonical, provider-independent conversation loop with explicit tool-call handling.
- Progressive tool search so the model sees only the contracts relevant to the current step.
- Versioned skills and staged disclosure of instructions and resources.
- Provider-runtime boundaries rather than provider logic scattered through the agent.
- Context compaction and session search as operational necessities for long investigations.
- Delegation as a first-class mechanism for parallel research, review, and specialized analysis.
- Observable agent steps and structured runtime events.

These ideas are supported by the official [agent-loop guide](https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/website/docs/developer-guide/agent-loop.md), [tool-search guide](https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/website/docs/user-guide/features/tool-search.md), [provider-runtime guide](https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/website/docs/developer-guide/provider-runtime.md), and [observability documentation](https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/docs/observability/README.md).

#### Reject or redesign

- Session identifiers must never stand in for authentication or authorization.
- A personal-agent/single-operator security assumption cannot protect multi-tenant, multi-case cyber evidence.
- Persistent Docker reuse across sessions is unacceptable without identity- and case-specific isolation.
- Top-level child work that is lost on process restart is not durable orchestration.
- Best-effort or fail-open observers cannot be the audit trail.
- Ephemeral prompt layers that are absent from the durable record prevent reliable replay and review.
- Skills must not be freely writable or self-promoted by production agents.
- Very large control-flow files impede review, testing, ownership, and security analysis. COH enforces an 800-line hard ceiling for handwritten production files, warning at 500 lines, and a normal target of 150–400.

Hermes's own [security model](https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/SECURITY.md) is useful precisely because it makes its trust assumptions visible. COH adopts the mechanisms, not the personal-assistant threat model.

### 3.2 OpenClaw

The inspected snapshot was [OpenClaw v2026.7.1-2](https://github.com/openclaw/openclaw/releases/tag/v2026.7.1-2).

#### Adopt

- Explicit task states such as queued, running, succeeded, failed, timed out, cancelled, and lost.
- Hierarchical delegation with depth, fanout, and concurrency limits.
- Per-session and global execution lanes to prevent starvation and accidental overload.
- Exact approvals that bind a proposed command/action rather than a vague intention.
- Tool-policy precedence that becomes narrower, never broader, at lower layers.
- Deterministic workflows for repeated operational playbooks.
- Optimistic concurrency for state transitions and durable task claiming.

#### Reject or redesign

- A single trusted-operator boundary is insufficient for production security operations.
- Sandbox-disabled defaults and permissive host execution are inappropriate.
- Prompt injection cannot be declared out of scope when logs, alerts, tickets, banners, documents, and threat intelligence are attacker-controlled.
- Announcements and completion delivery cannot be best effort; the durable task record is authoritative.
- Authentication fallback must fail closed.
- Rootless containers improve containment but do not create a complete exploit-lab boundary.

COH uses OpenClaw's task discipline while making identity, evidence, policy, and isolation mandatory rather than optional.

### 3.3 Gas Town

The inspected snapshot was [Gas Town v1.2.1](https://github.com/gastownhall/gastown/releases/tag/v1.2.1).

#### Adopt

- A durable control plane for work ownership, state, dependencies, and recovery.
- Typed work graphs rather than informal prompt-only plans.
- Identity separated from an individual process or terminal session.
- Checkpoints, supervisors, health visibility, and explicit recovery paths.
- An operational E-stop that stops intake, revokes execution authority, and cancels remote work.

#### Reject or redesign

- Git worktrees are collaboration boundaries, not security isolation.
- Host-exposed agents and broad filesystem access cannot execute hostile evidence safely.
- Terminal injection mechanisms such as tmux `send-keys` are too fragile for the control plane.
- “Bypass” modes cannot be normal production defaults.
- Dispatch success must mean the worker durably accepted a lease, not merely that a command was emitted.

COH borrows Gas Town's durable operational posture without tying identity or execution correctness to terminals, worktrees, or developer workstations.

### 3.4 Combined lesson

The synthesis is a deterministic control plane around a probabilistic analysis plane:

- Models produce typed proposals, claims, hypotheses, and explanations.
- Durable workflows own state and recovery.
- The action broker owns authorization and dispatch.
- Execution zones own containment.
- Evidence and audit systems own truth and accountability.
- Reviewers approve exact manifests, not prose summaries.

## 4. Standards and control baseline

### 4.1 Cybersecurity operations

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) supplies Govern, Identify, Protect, Detect, Respond, and Recover outcome language.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) is the incident-response lifecycle baseline.
- [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/) anchors adversary behavior mappings; the snapshot observed ATT&CK 19.2 dated 2026-08-06.
- [MITRE D3FEND](https://d3fend.mitre.org/) provides defensive countermeasure relationships.
- [OCSF](https://schema.ocsf.io/) is the preferred normalized event envelope, without discarding source-native records.
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) remains necessary for Elastic-native data and mappings.
- [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) and [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html) define interoperable threat-intelligence objects and transport.
- [Sigma specification](https://sigmahq.io/sigma-specification/) provides portable detection intent, not guaranteed target-query equivalence.

### 4.2 AI and agent risk

- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework) supplies Govern, Map, Measure, and Manage functions.
- [NIST AI 600-1, Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) adds generative-AI risk considerations.
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) covers prompt injection, sensitive-information disclosure, supply-chain weaknesses, excessive agency, and related application risks.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) expands the focus to goal hijacking, tool misuse, identity abuse, unexpected autonomy, and inter-agent risks.
- [NCSC guidance on secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development) reinforces secure design, development, deployment, and operations.

The design consequence is non-negotiable: prompt injection is a residual risk to manage, not a parsing bug the product can promise to eliminate. Hostile content must never be able to grant itself credentials, tools, scope, approval, network access, or persistence.

### 4.3 Vulnerability and software-supply-chain data

- [CVE Record Format / CVE JSON 5](https://github.com/CVEProject/cve-schema/releases) preserves authoritative claims and provenance.
- [CWE](https://cwe.mitre.org/data/index.html) provides weakness taxonomy.
- [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document) expresses severity and environmental factors.
- [EPSS](https://www.first.org/epss/data) estimates exploitation probability for a stated model and date.
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) identifies known exploitation and required-action context.
- [OSV schema](https://ossf.github.io/osv-schema/) supports package-oriented vulnerability records.
- [CycloneDX specifications](https://cyclonedx.org/specification/overview/) and [SPDX specifications](https://spdx.dev/use/specifications/) support SBOM interchange.
- [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) and [OpenVEX](https://openvex.dev/docs/) carry advisories and exploitability assertions.
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) supports static-analysis result interchange.

COH must retain source, version, timestamp, and contradictory claims rather than collapse these feeds into a single mutable “truth” field.

### 4.4 Snapshot caveat

Observed version labels—including OCSF 1.8.0, ECS 9.4.0, CWE 4.20, CVE schema 5.2.0, Sigma 2.1.0, and EPSS model generation—are research-snapshot facts, not perpetual compatibility promises. A release must pin exact versions in a machine-readable compatibility manifest and rerun corpus tests before promotion.

## 5. Agent and harness engineering

### 5.1 Control plane versus analysis plane

OpenAI recommends explicit autonomy boundaries, typed tool use, guardrails, and human approval for consequential actions in its [latest-model guidance](https://developers.openai.com/api/docs/guides/latest-model), [agent guardrails guidance](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals), and [sandbox guidance](https://developers.openai.com/api/docs/guides/agents/sandboxes). Anthropic similarly describes a durable session outside a disposable harness and sandbox in [Building a C Compiler with a Team of Parallel Claudes](https://www.anthropic.com/engineering/building-c-compiler) and the more general [managed-agents architecture](https://www.anthropic.com/engineering/managed-agents).

COH applies that separation as follows:

- The model is an untrusted planner and analyst.
- `coh-workerd` owns durable orchestration but cannot directly perform tools.
- `coh-brokerd` is the sole action authority.
- Credentials are referenced by opaque IDs and injected at dispatch, never inserted into prompts.
- `coh-runnerd` executes signed, bounded manifests in an appropriate zone.
- The evidence service stores source material and transformations.
- The audit service records policy and side-effect decisions independently of ordinary telemetry.

### 5.2 Typed durable state

Side-effecting work follows:

`planned → policy_checked → awaiting_approval → prepared → executing → confirmation_pending → verified | compensated | uncertain | denied | cancelled`

The `uncertain` state is essential. If a network call may have reached a remote system but the response was lost, automatic retry can duplicate containment, mutation, notification, scanning, or exploitation. Reconciliation must query remote state through an operation-specific confirmation mechanism.

Workflow payloads carry stable IDs, action and evidence hashes, policy versions, and small typed results. They do not carry raw evidence, secrets, full prompts, or large tool output.

### 5.3 Evidence-grounded outputs

Every analyst-facing assertion is represented as a claim with:

- zero or more resolvable evidence references;
- provenance and transformation chain;
- confidence and the basis for confidence;
- counterevidence and unresolved alternatives;
- data completeness and collection limitations; and
- a distinction between observed, inferred, externally asserted, and recommended.

Compaction may replace content with references and structured summaries, but cannot remove timestamps, ordering qualifications, negative query results, source completeness, or clock uncertainty.

### 5.4 Evaluation

Agent quality is not one end-to-end pass rate. OpenAI's [agent-evaluation guidance](https://developers.openai.com/api/docs/guides/agent-evals) and Anthropic's [agent-evaluation framework](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) support evaluating outcomes and trajectories over repeated trials.

COH needs:

- deterministic unit and contract tests for the control plane;
- replay tests for workflow histories;
- repeated model trials with immutable traces;
- outcome graders for factual and operational success;
- trajectory graders for unsafe, wasteful, or policy-violating behavior;
- expert calibration for SOC conclusions;
- adversarial prompt-injection and tool-output suites; and
- independent checks that every cited evidence ID exists.

[ExCyTIn-Bench](https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/) is relevant to cyber-threat investigation. General cyber-agent benchmarks remain supplementary because benchmark containment, task distribution, and scoring may not match production SOC risks.

## 6. Platform architecture choices

### 6.1 Go trusted core

Go is selected for the API, CLI, workflow workers, provider gateway, broker, connectors, audit, and runner control logic because it provides:

- straightforward macOS arm64, Linux amd64, and Linux arm64 builds;
- static or nearly self-contained service binaries;
- strong concurrency and cancellation primitives;
- a mature HTTP, gRPC, cryptography, observability, and systems ecosystem; and
- operational simplicity for native and container deployments.

The baseline is Go 1.26.7; Go 1.27 is a qualification lane until replay, dependency, and platform suites pass. Releases are tracked through the official [Go release history](https://go.dev/doc/devel/release).

“All-Go core” does not mean replacing authoritative language tooling with regexes. The Kusto.Language and pySigma helpers are bounded plugins because query-validation correctness is a security property.

### 6.2 Durable workflows

[Temporal](https://github.com/temporalio/temporal) and its [Go SDK](https://github.com/temporalio/sdk-go) are selected behind a COH-owned `WorkflowEngine` interface. Temporal is mature, MIT-licensed, supports durable timers and signals, and has explicit [self-hosted production guidance](https://github.com/temporalio/documentation/blob/main/docs/production-deployment/self-hosted-guide/deployment.mdx).

The abstraction is required to:

- prevent Temporal types from becoming public product contracts;
- enable deterministic unit tests with an in-memory fake;
- constrain workflow payloads;
- make replay a release gate; and
- preserve an exit path if licensing or operational needs change.

Rejected alternatives:

- A custom workflow engine: deceptively complex around replay, timers, leases, cancellation, and unknown outcomes.
- [durabletask-go](https://github.com/microsoft/durabletask-go): its repository describes it as work in progress rather than a production baseline.
- [go-workflows](https://github.com/cschleiden/go-workflows): attractive and MIT-licensed but a higher maturity and support risk for this safety-critical control plane.
- [Restate](https://github.com/restatedev/restate): technically relevant, but its server license and dependency posture do not fit the preferred permissive open-source baseline as cleanly as Temporal.

### 6.3 Policy

[Open Policy Agent](https://www.openpolicyagent.org/docs/latest/) is embedded in the broker. Signed policy bundles are versioned and evaluated against canonical typed inputs. Policy is re-evaluated immediately before dispatch because approval-time facts can become stale.

The broker defaults to deny when:

- identity, tenant, case, resource, or target scope is missing;
- the policy bundle is invalid or unavailable;
- approval does not match the action digest;
- credentials or tool versions differ from the approved manifest;
- evidence/audit persistence is unavailable for consequential work; or
- runner health, isolation, watch, or ROE preconditions are not satisfied.

### 6.4 Persistence

- SQLite supports a single-workstation native profile.
- PostgreSQL 18 supports server and multi-process deployments.
- A SHA-256 content-addressed store retains immutable evidence and artifacts.
- Parquet is used for large normalized datasets through a bounded dataset interface.
- Transactional outbox/inbox patterns connect SQL mutations to durable workflows and events.

Raw evidence, operational metadata, workflow state, memory, projections, and audit are logically separated even if a workstation profile co-locates some storage physically.

### 6.5 Native first, Docker optional

Native processes are the primary profile and must not probe for or require Docker. Docker Desktop/Compose is a complete alternate packaging profile, not an architectural dependency.

The container profile follows [Compose profiles](https://docs.docker.com/compose/how-tos/profiles/) and [Compose secrets](https://docs.docker.com/reference/compose-file/secrets/):

- pinned multi-architecture images for `linux/amd64` and `linux/arm64`;
- no Docker socket mount;
- non-root users, dropped capabilities, resource limits, health checks, and read-only roots where practical;
- internal PostgreSQL and Temporal networks with only `cohd` published by default;
- file-backed or external secrets rather than environment-carried plaintext; and
- separate inference, observability, and low-risk-runner profiles.

Docker Desktop on macOS runs Linux containers in a VM. It can host the whole application, but native Ollama/llama.cpp is preferred when Metal acceleration matters. On DGX Spark, GPU devices are exposed only to the selected inference service, never to an untrusted tool or exploit worker.

A shared Compose stack is not a T4 security boundary. T4 requires a disposable dedicated VM or independently administered remote zone with target-only egress.

## 7. Provider-adapter research

### 7.1 Why separate adapters

“OpenAI-compatible” commonly describes endpoint shape, not identical state, tool, streaming, reasoning, tokenizer, template, or error semantics. COH therefore uses one capability contract and distinct adapters.

Each qualified endpoint/model records:

- requested and actual model identity;
- immutable revision, weights digest, or hosted version where available;
- runtime and runtime version;
- tokenizer and chat/prompt template;
- tool parser and reasoning parser;
- context and output limits;
- sampling controls and determinism claims;
- hardware and quantization;
- state-retention and data-routing mode; and
- the policy and qualification-suite revisions.

### 7.2 OpenAI Responses

Use the native [Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses) rather than flattening it into Chat Completions. Preserve typed response items, function-call IDs, structured outputs, reasoning state, and tool-call ordering. Default to `store:false` for sensitive work unless a documented data-governance profile permits storage. Tool schemas follow the official [function-calling guide](https://developers.openai.com/api/docs/guides/function-calling/).

OpenAI-hosted MCP/connectors are not implicitly trusted. The [MCP security guidance](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) requires trusted servers, approval for sensitive actions, and logging; COH still routes every consequential operation through its own broker.

### 7.3 Ollama

The native adapter targets [`/api/chat`](https://docs.ollama.com/api/chat), detects advertised capabilities, and verifies tool-call, JSON-schema, streaming, and context behavior per model. Model names are insufficient provenance; the model manifest/digest and effective template must be recorded.

### 7.4 llama.cpp

The adapter targets the llama.cpp [server API](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md) separately from Ollama. Qualification records the GGUF digest, build/version, context, chat template, grammar/schema behavior, tool-call format, and hardware offload. Unsupported tool semantics fail qualification rather than falling back to parsing prose.

### 7.5 vLLM

The adapter follows the [vLLM OpenAI-compatible server documentation](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/), but records explicit chat template, tool-call parser, reasoning parser, tokenizer mode, tensor parallelism, and served-model revision. Parser or template changes create a new qualification identity.

### 7.6 Codex

Codex is treated as an external agent runtime, not merely a model endpoint. The preferred integration is the documented [Codex App Server](https://developers.openai.com/codex/app-server/) or SDK contract, which preserves task events and approvals. `codex exec` is a bounded batch fallback with a fixed working directory, environment allowlist, timeout, output limit, and no ambient credentials.

### 7.7 Provider failure modes

The conformance suite must detect:

- a requested model silently resolving to another model;
- tool arguments emitted as prose or malformed JSON;
- missing or duplicated tool-call IDs;
- reordered streaming items;
- context truncation without a surfaced signal;
- incompatible structured-output behavior;
- retry behavior that could duplicate actions;
- retention or routing settings that violate classification; and
- template/parser upgrades that change security behavior.

## 8. SIEM, log, and detection adapters

### 8.1 Common connector contract

Every connector implements:

`ProbeCapabilities → DiscoverSchema → Validate → Execute → Poll/NextPage → Cancel`

Every query requires a UTC half-open `[start,end)` range, tenant/resource allowlist, read-only credential reference, row/byte/deadline/cost bounds, and `allow_partial=false` by default. Interactive defaults are 200 rows with hard caps of 2,000 rows, 5 MiB, and 60 seconds. Explicit export is separately authorized and capped at 10,000 rows per page/slice, 100 MiB per artifact, and 300 seconds.

The evidence record includes the canonical request, source, native query, bounds, schema version, connector version, query hash, result statistics, paging/slicing decisions, and a completeness state such as complete, truncated, partial, cancelled, or uncertain.

Generic HTTP is not part of the model-facing connector surface.

### 8.2 Elastic and Security Onion

For Elastic, use [ES|QL REST](https://www.elastic.co/docs/reference/query-languages/esql/esql-rest) for bounded interactive work. Because ES|QL is not a stable cursor protocol, use Query DSL with point-in-time plus `search_after` for complete export, following [Elasticsearch pagination guidance](https://www.elastic.co/guide/en/elasticsearch/reference/current/paginate-search-results.html).

Validation includes index resolution, field capabilities, query validation, an allowlisted source set, mandatory API-level time filters, conservative limits, and a bounded canary. ES|QL constructs such as broad forks or unbounded sources fail closed.

Security Onion is a separate adapter using its [Connect API](https://docs.securityonion.net/en/3/main/connect-api/so-api-reference.html) and OQL semantics. The client is generated or checked against the target appliance's exposed OpenAPI definition. Cases, detections, grid administration, configuration, and PCAP operations are not reachable through the read-only query adapter. If the appliance provides no stable continuation mechanism, reaching its limit means “truncated,” followed by policy-bounded time slicing—not an assertion of completeness.

### 8.3 Splunk

Splunk uses its [search job REST endpoints](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/search-endpoints/search-endpoint-descriptions). Preflight parses SPL and disables lookups and macros. An allowlist admits analytical commands; high-risk commands such as `collect`, `delete`, `outputlookup`, `sendemail`, `script`, `run`, `map`, `rest`, `savedsearch`, and `loadjob` are denied. Backticks, custom commands, macros, and subsearches are denied unless a future recursive validator proves them safe.

Queries require absolute earliest/latest bounds, prohibit real-time search, use positive runtime/result caps, page finalized results, and can poll or cancel only search IDs created by the connector.

### 8.4 Microsoft Sentinel / Log Analytics

Use the [Log Analytics query API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format) and workspace metadata, not Sentinel management APIs, for the read-only query path. A request-body timespan is mandatory. A `PartialError` result is incomplete failure unless a separate policy explicitly admits partial data.

KQL is parsed and analyzed by the official [Kusto.Language library](https://learn.microsoft.com/en-us/kusto/api/netfx/about-the-sdk), using discovered metadata. Control commands, `externaldata`, cross-cluster references, wildcard unions, and unsafe plugins are denied; stored functions are recursively validated. Limits are inserted into the parsed query plan rather than appended blindly.

The Log Analytics response does not provide a general cursor. Export uses adaptive half-open time slices and stable-key deduplication. If many records share a timestamp and no stable key exists, the connector fails closed rather than claiming completeness. Search Jobs are outside the initial read-only contract.

### 8.5 Sigma and detection lifecycle

The safe path is:

`safe YAML → Sigma validation → explicit tenant mapping → pinned backend/pipeline → native validator → bounded canary → immutable artifact → reviewed promotion`

Use [pySigma](https://github.com/SigmaHQ/pySigma) in a credentialless, network-denied helper. Unsupported constructs do not pass through with `--skip-unsupported`, and automatic field guessing is forbidden. Elastic and Splunk backends require pinned versions and corpus tests. Kusto mappings are tenant-specific. Security Onion conversion remains provisional until pinned appliance fixtures demonstrate equivalence.

Rule deployment is a separate, approved mutation. Successful compilation does not authorize publication.

### 8.6 Timeline and correlation requirements

Correlation must preserve:

- source and collection timestamps;
- original timezone and timestamp text;
- normalized UTC timestamp;
- clock precision and estimated uncertainty;
- ingestion delay and source ordering limits;
- duplicate identity and deduplication rationale;
- mapping and parser versions; and
- negative-result and missing-telemetry statements.

Events with overlapping uncertainty intervals cannot be asserted to have a strict order. Entity resolution produces explainable links and confidence, not silent destructive merges.

## 9. Incident response, hunting, and analyst workflows

### 9.1 Incident response

NIST SP 800-61 Rev. 3 implies workflows for preparation/governance, detection and analysis, response, recovery, and lessons learned. COH should capture:

- the initial alert and preservation actions;
- hypotheses and investigation questions;
- affected identities, assets, data, and business services;
- containment options with blast radius and rollback;
- pre-action and post-action evidence;
- eradication, recovery, monitoring, and validation;
- regulatory or contractual handoff flags without offering legal conclusions; and
- an immutable decision and approval history.

### 9.2 Threat hunting

Hunts begin with a falsifiable hypothesis, required telemetry, time and environment scope, expected benign patterns, stop conditions, and success/negative-result criteria. The harness distinguishes “not observed” from “not present” and records coverage gaps.

### 9.3 Threat intelligence

STIX/TAXII content, ATT&CK techniques, D3FEND relationships, CVE assertions, and vendor reporting retain publisher, version, timestamps, markings, and confidence. External reporting is treated as a claim until correlated with local evidence.

### 9.4 Reporting and review

The reviewer agent cannot manufacture evidence or approve actions. Its role is to challenge unsupported claims, missing alternative hypotheses, incomplete collection, temporal errors, and policy violations. Reports distinguish executive conclusions, technical findings, observed facts, inferences, limitations, decisions, and recommended next steps.

## 10. Vulnerability operations and authorized validation

### 10.1 Canonical model

The vulnerability model preserves CVE claims and aliases, CVSS vector/version/source, EPSS score/date/model, KEV state, CWE, PURL/CPE, asset exposure, asset criticality, VEX assertions, scanner observations, remediation, exceptions, and verification evidence.

Priority is explainable and ordered:

`confirmed compromise > KEV > SSVC decision > exposure and asset criticality > EPSS > CVSS > fix availability and age`

EPSS and CVSS are not multiplied into a false-precision score. Conflicting records coexist with provenance until an analyst or deterministic reconciliation rule resolves them.

### 10.2 Discovery and imports

Initial read and import paths cover CVE List V5, NVD, CISA KEV, EPSS, OSV, CWE, CycloneDX, SPDX, CSAF/OpenVEX, SARIF, and common scanner results. Air-gapped deployments use signed, timestamped, rollback-capable content packs.

### 10.3 Scanner and validation adapters

Syft, Trivy, Grype, Nmap, Nuclei, ZAP, and external Greenbone/OpenVAS integrations use signed recipes with exact binary/image digests, target scope, argument schemas, resource bounds, parsers, and evidence outputs. They do not expose generic command construction.

Nmap redistribution requires a legal/license review. Greenbone community containers are reference/evaluation packaging, not a promised production scanner appliance.

A separately packaged Metasploit proxy may expose only curated modules whose behavior, payload, confirmation, cleanup, and rollback are reviewed. Generic RPC, interactive shells, arbitrary payloads, persistence, credential dumping, and lateral movement are unavailable.

### 10.4 Action tiers

- **T0:** Offline analysis and derived artifacts; automatic.
- **T1:** Bounded read-only queries to pre-authorized sources; automatic.
- **T2:** Reversible mutations; one exact, expiring approval.
- **T3:** Intrusive scans, containment, or destructive changes; explicit approval, with policy able to require two.
- **T4:** State-changing production validation; always two distinct human approvers plus signed ROE and dedicated isolation.

The requestor cannot be either T4 approver. Consequently, a solo deployment cannot perform T4 until a second authenticated approver is enrolled.

An approval binds the canonical action digest, policy revision, ROE digest, exact targets and exclusions, arguments, tool/payload digest, credentials, validity window, and use count. Any one-byte change invalidates it.

T4 requires a rollback rehearsal, staffed safety-watch heartbeat, target-only egress, pre-action evidence, a tested E-stop, post-action confirmation, and no automatic retry. It cannot expand targets, persist, or pivot.

## 11. Sandbox and supply-chain lessons

OpenAI's official [Hugging Face model-evaluation security incident report](https://openai.com/index/hugging-face-model-evaluation-security-incident/) describes a sandbox escape using a zero-day in an artifact-proxy component, followed by Internet access, lateral movement, and credential exposure. The material lesson is that a sandbox can fail and surrounding infrastructure must assume it will.

COH therefore requires:

- no long-lived or ambient credentials inside untrusted execution;
- no reachable package, artifact, metadata, database, workflow, or control-plane service from exploit zones;
- default-deny egress with exact target and protocol allowlists;
- disposable worker identity and filesystem;
- image, binary, model, policy, and skill digests in the action manifest;
- signed SBOMs and provenance for releases and offline packs;
- no GPU access for untrusted tool execution;
- independent host/VM boundaries for T4; and
- revocation that remains effective if the model or worker stops cooperating.

Container hardening is defense in depth, not proof of isolation.

## 12. Principal risks and residual exposure

| Risk | Primary control | Residual exposure / required evidence |
|---|---|---|
| Prompt injection in logs, tickets, banners, documents, or feeds | Treat content as data; broker-enforced tools and policy | Model analysis can still be biased; require citations, reviewer challenge, and adversarial evals |
| Tool-output injection | Typed result envelopes and untrusted-content labels | Free-text fields remain hostile; never interpret them as authority |
| Credential disclosure | Opaque references and dispatch-time leases | A compromised connector may misuse its scoped credential; minimize scope and lifetime |
| Sandbox escape | Dedicated zones, target-only egress, no nearby secrets/services | Kernel or hypervisor escape remains possible; T4 needs independent infrastructure and monitoring |
| Duplicate side effect after timeout | Idempotency, confirmation, and `uncertain` state | Some vendor actions lack reliable status APIs; require manual reconciliation |
| Partial SIEM results presented as complete | Explicit completeness status, limits, bounded slicing | Vendor caps and schema changes can still reduce coverage; show limitations to analyst |
| Cross-case or cross-tenant leakage | Identity in every key, query, cache, event, and lease | Requires continuous negative tests and storage-policy review |
| Evidence tampering | CAS hashes, lineage, append-only audit, signed checkpoints | Host administrator can destroy data; external checkpointing and backups improve detection/recovery |
| Timeline overconfidence | Original time, precision, skew, and uncertainty intervals | Bad source clocks may preclude strict order; report ambiguity |
| Model/version drift | Qualification identity and repeated evals | Hosted model changes may be opaque; quarantine unqualified identities |
| Parser/backend drift | Pin helpers and run corpus/native validation | Vendor languages evolve; unsupported syntax must fail closed |
| Supply-chain compromise | Pinned digests, SBOM, provenance, signature verification | Signing infrastructure becomes critical; isolate keys and test revocation |
| Optional Docker misconfiguration | Secure Compose defaults and parity tests | Docker Desktop shares a host trust domain; never use it alone for T4 |
| DGX resource interference | GPU exposed only to inference; quotas | Local inference can starve control services; reserve CPU/memory and enforce budgets |
| Autonomous skill poisoning | Signed, reviewed, read-only production skills | Reviewers can approve malicious changes; require tests, provenance, and rollback |
| Vulnerability false confidence | Preserve claims, observations, and verification states separately | Absence of scanner findings is not proof of absence |
| T4 collateral impact | Signed ROE, exact targets, dual approval, watch, E-stop, rollback | Production testing inherently carries risk; policy may forbid T4 entirely |
| Operational complexity | Native workstation profile and automated diagnostics | Temporal/PostgreSQL/server PKI add burden; document and test upgrades/restore |
| License incompatibility | Dependency policy and legal review | Tool redistribution and changing upstream terms require release-by-release review |

## 13. Rejected alternatives

| Alternative | Rejection rationale |
|---|---|
| Python trusted core | Excellent ecosystem, but less attractive for self-contained cross-platform control-plane binaries; Python remains limited to isolated pySigma helper |
| Rust trusted core | Strong safety properties but higher implementation and contributor complexity for this product; isolation and policy are still required regardless of language |
| One large agent process | Couples model context, policy, credentials, side effects, and evidence; weak crash recovery and reviewability |
| Generic OpenAI-compatible provider | Loses provider-specific state, tool, reasoning, template, streaming, and retention semantics |
| Generic HTTP or shell tool | Creates an unreviewable capability escape hatch and defeats least privilege |
| Agent-authored policy decisions | A probabilistic model cannot be the authorization boundary |
| Custom durable workflow engine | High correctness burden around replay, leases, timers, idempotency, and unknown outcomes |
| Restate server as baseline | Less aligned with the selected permissive dependency/licensing posture |
| durabletask-go as baseline | Upstream maturity warning is incompatible with the critical path |
| Embedded go-workflows as baseline | Smaller operational footprint, but insufficient maturity evidence for the safety-critical control plane |
| Docker-required installation | Violates native-first and air-gap usability; burdens macOS local-model acceleration |
| Shared Docker Desktop stack for T4 | Containers and a shared Linux VM are not an adequate hostile-execution boundary |
| One evidence/memory store | Makes summaries or preferences indistinguishable from preserved observations |
| Plain append-only log without integrity checkpoints | Does not detect privileged insertion, deletion, reordering, or rollback |
| Regex-only KQL/SPL/ES|QL validation | Query languages are structured and extensible; regex cannot establish safe semantics |
| Automatic Sigma field mapping | Produces plausible but unverified detections and hidden false negatives |
| Sentinel Search Jobs in initial read-only path | Search Jobs create resources and complicate mutation policy and cleanup |
| Opaque CVSS × EPSS score | Mixes severity and probability without a defensible model and hides decision factors |
| Generic Metasploit RPC | Exposes arbitrary payload, shell, persistence, and pivot capabilities outside signed recipes |
| Unbounded subagents | Enables budget exhaustion, confused-deputy behavior, and unreviewable task trees |
| Automatic production skill self-modification | Allows prompt injection or model error to become durable authority |

## 14. COH-specific design implications

The research yields the following architecture decisions for the PRD and backlog:

1. Identity is explicit at organization, tenant, actor, case, run, task, evidence, approval, credential lease, and runner levels.
2. The model never receives a credential or a generic network primitive.
3. All tool calls become canonical `ToolIntent` objects and cross `coh-brokerd`.
4. All consequential actions are durable state machines with reconciliation and `uncertain` handling.
5. Evidence is immutable; transformations create new artifacts and lineage edges.
6. Audit is independent of telemetry and fails closed for consequential actions.
7. Provider and connector capability discovery is empirical and version-pinned.
8. Query validation occurs outside the model and combines syntax, schema, policy, bounds, and canaries.
9. Detection compilation is a governed pipeline, not a text-generation result.
10. Timeline order is uncertainty-aware.
11. Skills are reviewed supply-chain artifacts.
12. Subagents are bounded durable tasks whose outputs cite evidence.
13. Native and Compose deployments exercise the same API, policy, workflow, and artifact conformance suites.
14. Air-gapped operation uses signed, independently updatable code, model, policy, tool, and data packs.
15. T4 is technically impossible in solo mode and physically separated from the control plane when enabled.
16. Source files and scripts are kept small enough to review: 800-line hard limit, 500-line warning, 150–400-line production target, and 300-line script target.

## 15. Verification implications

The research is not satisfied by happy-path demonstrations. At minimum, COH release evidence must show:

- zero unauthorized side effects, approval replays, cross-case disclosures, or scope escapes in the adversarial suite;
- approval invalidation after a one-byte action change;
- crash injection at every side-effect boundary without duplicate confirmed effects;
- preservation and detection of complete, truncated, partial, cancelled, and uncertain query outcomes;
- byte-level evidence and audit tamper detection;
- provider qualification for exact endpoint/model/template/parser identities;
- native operation with Docker absent;
- API and artifact parity in the optional Compose profile;
- no DNS or Internet attempts during a 24-hour air-gap test;
- prompt-injection resistance at the authorization boundary, even when analysis is degraded;
- corpus-based KQL, SPL, ES|QL, Sigma, timeline, and vulnerability tests;
- E-stop lease rejection, network cut, workflow signal, and worker termination timing; and
- proof that T4 cannot start without two distinct approvers, signed ROE, healthy isolated runner, rollback, and staffed watch.

## 16. Source ledger

### Agent harnesses and engineering

- Hermes Agent release: https://github.com/NousResearch/hermes-agent/releases/tag/v2026.8.18
- Hermes security model: https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/SECURITY.md
- Hermes agent loop: https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/website/docs/developer-guide/agent-loop.md
- Hermes tool search: https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/website/docs/user-guide/features/tool-search.md
- Hermes provider runtime: https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/website/docs/developer-guide/provider-runtime.md
- Hermes observability: https://github.com/NousResearch/hermes-agent/blob/v2026.8.18/docs/observability/README.md
- OpenClaw repository: https://github.com/openclaw/openclaw
- OpenClaw inspected release: https://github.com/openclaw/openclaw/releases/tag/v2026.7.1-2
- Gas Town repository: https://github.com/gastownhall/gastown
- Gas Town inspected release: https://github.com/gastownhall/gastown/releases/tag/v1.2.1
- OpenAI latest-model guidance: https://developers.openai.com/api/docs/guides/latest-model
- OpenAI guardrails and approvals: https://developers.openai.com/api/docs/guides/agents/guardrails-approvals
- OpenAI sandbox guidance: https://developers.openai.com/api/docs/guides/agents/sandboxes
- OpenAI agent evals: https://developers.openai.com/api/docs/guides/agent-evals
- OpenAI MCP/connectors: https://developers.openai.com/api/docs/guides/tools-connectors-mcp
- OpenAI Hugging Face security incident: https://openai.com/index/hugging-face-model-evaluation-security-incident/
- OpenAI internal coding-agent monitoring: https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/
- OpenAI EVMbench: https://openai.com/index/introducing-evmbench/
- Anthropic managed agents: https://www.anthropic.com/engineering/managed-agents
- Anthropic effective agents: https://www.anthropic.com/engineering/building-effective-agents
- Anthropic agent evals: https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
- Anthropic trustworthy agents: https://www.anthropic.com/research/trustworthy-agents
- Microsoft ExCyTIn-Bench: https://www.microsoft.com/en-us/research/publication/excytin-bench-evaluating-llm-agents-on-cyber-threat-investigation/

### Standards and security guidance

- NIST CSF 2.0: https://www.nist.gov/cyberframework
- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
- OWASP Agentic Top 10: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- NCSC secure AI development: https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development
- MITRE ATT&CK versions: https://attack.mitre.org/resources/versions/
- MITRE D3FEND: https://d3fend.mitre.org/
- OCSF schema: https://schema.ocsf.io/
- Elastic Common Schema: https://www.elastic.co/guide/en/ecs/current/index.html
- STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
- Sigma specification: https://sigmahq.io/sigma-specification/

### Platform, policy, and deployment

- Go release history: https://go.dev/doc/devel/release
- Temporal server: https://github.com/temporalio/temporal
- Temporal Go SDK: https://github.com/temporalio/sdk-go
- Temporal self-hosting: https://github.com/temporalio/documentation/blob/main/docs/production-deployment/self-hosted-guide/deployment.mdx
- Open Policy Agent: https://www.openpolicyagent.org/docs/latest/
- Docker Compose profiles: https://docs.docker.com/compose/how-tos/profiles/
- Docker Compose secrets: https://docs.docker.com/reference/compose-file/secrets/
- durabletask-go: https://github.com/microsoft/durabletask-go
- go-workflows: https://github.com/cschleiden/go-workflows
- Restate: https://github.com/restatedev/restate

### Model and agent providers

- OpenAI Responses migration: https://developers.openai.com/api/docs/guides/migrate-to-responses
- OpenAI function calling: https://developers.openai.com/api/docs/guides/function-calling/
- Ollama chat API: https://docs.ollama.com/api/chat
- llama.cpp server API: https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
- vLLM online serving: https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/
- Codex App Server: https://developers.openai.com/codex/app-server/

### SIEM, detection, and query systems

- Elastic ES|QL REST: https://www.elastic.co/docs/reference/query-languages/esql/esql-rest
- Elasticsearch result pagination: https://www.elastic.co/guide/en/elasticsearch/reference/current/paginate-search-results.html
- Security Onion Connect API: https://docs.securityonion.net/en/3/main/connect-api/so-api-reference.html
- Splunk search endpoints: https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/search-endpoints/search-endpoint-descriptions
- Azure Log Analytics request format: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format
- Kusto .NET SDK / Kusto.Language: https://learn.microsoft.com/en-us/kusto/api/netfx/about-the-sdk
- pySigma: https://github.com/SigmaHQ/pySigma

### Vulnerability and exchange formats

- CVE schema releases: https://github.com/CVEProject/cve-schema/releases
- CWE: https://cwe.mitre.org/data/index.html
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- EPSS data and model: https://www.first.org/epss/data
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV schema: https://ossf.github.io/osv-schema/
- CycloneDX specifications: https://cyclonedx.org/specification/overview/
- SPDX specifications: https://spdx.dev/use/specifications/
- CSAF 2.0: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
- OpenVEX: https://openvex.dev/docs/
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## 17. Version drift, legal review, and research refresh

This dossier is a dated decision input, not a substitute for release qualification. Before each major COH release:

1. Resolve every source URL and record the retrieved release/specification version.
2. Diff provider, SIEM, schema, policy, workflow, container, and packaging contracts.
3. Rebuild compatibility fixtures against supported vendor versions.
4. Re-run provider, query, Sigma, timeline, evidence, workflow replay, adversarial, native, Compose, DGX, and air-gap suites.
5. Review upstream licenses and redistribution terms, especially scanners, rules, model weights, feeds, containers, and non-Go helpers.
6. Issue an ADR for any changed trust assumption, default, protocol, action tier, or release gate.
7. Preserve the old source ledger and compatibility manifest so investigations remain reproducible.

Claims derived from current behavior rather than a normative contract must remain marked provisional. A successful integration test is evidence for the exact pinned version only; it is not permission to silently widen the supported range.

## Conclusion

The best cybersecurity LLM harness is not the most autonomous one. It is the one that makes useful analytical autonomy possible while preserving deterministic authority, durable recovery, evidentiary integrity, exact human control, and honest uncertainty. COH should combine Hermes's practical agent ergonomics, OpenClaw's bounded execution discipline, and Gas Town's durable operational model inside a substantially stronger security boundary designed for hostile data and consequential actions.
