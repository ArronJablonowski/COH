# DeepSeek Harness architectural adoption plan

| Field | Decision |
|---|---|
| Review date | 2026-08-27 |
| Upstream | `deepseek-ai/deepseek-harness` at `cd5ef8148158c3a752a658978873241fdf8e2bbc` |
| Status | Approved for backlog integration; implementation evidence required per leaf issue |
| Scope | Harness composition, extension lifecycle, model-surface provenance, and architecture introspection |
| Security posture | COH's broker, signed registries, action tiers, immutable evidence, and fail-closed audit remain authoritative |

## Decision

COH will adopt five mechanisms demonstrated clearly by DeepSeek Harness without
adopting its unrestricted "everything is a plugin" trust model.

1. **Typed capability seams.** Each replaceable capability has a versioned
   service definition, one or more qualified providers, and explicit consumers.
   The resolved dependency graph is closed, scope-aware, and validated before
   startup. A provider registration does not grant action authority; every
   model-originated operation still enters the broker as a typed intent.
2. **Deterministic profiles and overlays.** Native workstation, native server,
   Compose, air-gap, headless, Web, CLI, API, and test profiles resolve from
   ordered signed layers into one canonical configuration. Operators can dump
   the redacted resolved graph and its digest. Unknown rows, ambiguous providers,
   dependency cycles, scope widening, or unsigned overlays fail closed.
3. **Transactional, scoped lifecycle effects.** Extension registration returns
   an idempotent revocation handle. A failed activation unwinds all effects in
   reverse order; deactivation removes only the owning extension's registrations
   and drains admitted work before release. Restart reconstructs the same graph
   from durable signed configuration rather than serialized callbacks.
4. **Durable model-surface projection.** Every message, prompt section, tool
   schema, retrieved context item, compaction replacement, and policy notice
   visible to a model is derived from durable typed records or an immutable
   digest-bound artifact. The inference request records the exact ordered source
   IDs. A runtime invariant denies a request when any visible item lacks a
   durable source or when replay produces a different surface digest.
5. **Generated architecture catalogs.** CI generates and verifies the capability
   graph, configuration catalog, event producer/consumer map, model-surface event
   catalog, and application-entrypoint inventory. Stale generated catalogs,
   undeclared dependency edges, alternate launch paths, and authority bypasses
   fail the architecture gate.

The first two mechanisms improve portability and operator understanding. The
third makes extension upgrades and rollback safer. The fourth directly improves
accuracy and reproducibility because the exact model context can be replayed and
audited. The fifth keeps those guarantees from drifting as the harness grows.

## COH-specific boundaries

DeepSeek Harness describes plugins contributing services, events, and reversible
effects to a shared context, ordered profile and bundle layers, a session log as
the source of model history, and generated capability and persistence catalogs.
Those are useful implementation patterns, not evidence that its security model
is appropriate for cyber operations. Its own safety notice says the developer
preview has not undergone a security audit and may expose commands, plugins,
network, processes, credentials, and files.

COH therefore applies these restrictions:

- The broker, policy engine, approval verifier, audit writer, credential
  resolver, evidence verifier, and E-stop cannot be replaced or intercepted by
  an ordinary extension.
- Extensions are signed, reviewed, version-pinned, permission-declared,
  policy-scoped, qualified, and revocable. Production agents cannot install,
  modify, activate, or promote them.
- Profiles may narrow capabilities and resources. Any widening requires a new
  signed profile revision, policy evaluation, administrative authority, audit,
  and applicable approval.
- Security-critical live reload is forbidden. Composition changes enter a
  quiescent maintenance transition and become active only after validation.
- Configuration and inspection output is schema-closed and redacted. It never
  includes credentials, raw evidence, prompt content, private paths, or mutable
  executable objects.
- No generic shell, arbitrary HTTP, unrestricted filesystem, dynamic code
  loader, or direct executor surface is introduced.
- Durable session records do not replace COH's hash-chained audit, workflow
  history, immutable evidence, or chain-of-custody records; they bind to them.

## Integration map

| Addition | COH integration point | Existing foundations | Required new proof |
|---|---|---|---|
| Capability seams | composition root and registries | workspace boundaries, provider contract, query connector SPI, tool and skill registries | closed definition/provider/consumer graph; single-provider and scope checks; no broker bypass |
| Profiles and overlays | deployment-profile validation | signed deployment profiles and native/Compose parity | deterministic merge, canonical digest, redacted dump, downgrade/cycle/ambiguity denials |
| Lifecycle effects | signed extension activation | skill/tool signing, revocation, E-stop, recovery control | atomic activation, reverse unwind, drain/cancel, crash recovery, replay and rollback |
| Model-surface projection | durable agent loop and provider request construction | agent phases, context compaction, evidence references, provider contracts | complete source binding, deterministic projection, tamper denial, exact replay digest |
| Generated catalogs | architecture and CI gates | architecture contract, entrypoint and dependency checks | freshness gate and complete graph/event/config/entrypoint inventories |

## Delivery order

1. Freeze the contracts for capability seams and canonical composition.
2. Implement the resolver and redacted inspection command without dynamic
   activation.
3. Add transactional activation and revocation for signed data-plane extensions.
4. Add the durable model-surface projection and invariant before expanding the
   model-facing capability set.
5. Generate catalogs from the implemented registries and make freshness and
   boundary checks release-blocking.

Each stage must cover invalid input, denial, timeout/cancellation, restart,
replay, tamper, stale state, revocation, and rollback. Promotion requires focused
tests, race tests, architecture checks, secret scans, and the full CI quality
lane. Independent security architecture review remains required before the first
production release.

## Explicit non-adoptions

- No unprivileged or model-controlled plugin installation.
- No arbitrary out-of-tree executable plugin loaded into a trusted process.
- No hot module replacement for authority, credentials, policy, evidence,
  audit, workflow, connector, runner, or validator boundaries.
- No waterfall listener chain that can silently suppress downstream security
  checks. Interception points return typed, composable decisions and mandatory
  guards always run.
- No claim that a general-purpose harness sandbox is a T4 isolation boundary.
- No compatibility promise with the upstream developer-preview plugin API.

## Source record

- [DeepSeek Harness repository](https://github.com/deepseek-ai/deepseek-harness)
- [Architecture](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md)
- [Safety notice](https://github.com/deepseek-ai/deepseek-harness/blob/master/SAFETY.md)
- [Capability-seam catalog](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/capability-seams.md)
- [Agent lifecycle](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/agent-lifecycle.md)
- [Persistence catalog](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/persistence-catalog.md)

Upstream is informative only. COH's approved PRD, trust-boundary ADR, signed
contracts, action-tier table, and Linear acceptance criteria remain normative.
