# ADR-0001 verification contract

| Field | Value |
|---|---|
| Parent decision | [ADR-0001](0001-trust-boundaries.md) |
| Implementation issue | [COH-E01-02 / CYB-31](https://linear.app/cyber-operations-harness/issue/CYB-31/coh-e01-02-record-architecture-and-trust-boundary-adr) |
| Status | Accepted with ADR-0001 for M0 design freeze |
| Requirements | `SEC-001`, `SEC-002`, `SEC-017`, `SEC-026` |

This companion is normative. It separates executable rules and verification
evidence from the architectural rationale so both files remain reviewable.

## Enforceable implementation rules

1. Package dependency rules must prevent provider, agent, and workflow packages
   from importing connector, runner-dispatch, credential-backend, generic network,
   shell-execution, or Docker-client packages.
2. Only broker-owned packages may construct dispatch leases or hold connector
   clients; their public inputs are canonical typed intents, not commands or URLs.
3. Public and internal contracts require organization, tenant, case, and actor
   fields and reject zero values at every ingress and artifact resolution.
4. Production agent tool registries contain only typed proposal/query/action
   schemas and no generic HTTP, shell, evaluator, Docker, or untyped RPC tool.
5. Connectors and runners accept broker-authenticated leases and reject direct
   calls, replay, expiry, wrong audience, wrong scope, and digest mismatch.
6. Validators have a separate credentialless, network-denied launch profile and
   strict input/output size, time, memory, and process limits.
7. Required audit preconditions execute before credential acquisition or
   dispatch; evidence references appear only after verified atomic commit.
8. Deployment conformance tests assert equivalent logical boundaries for native
   and Compose profiles. Docker is optional and is not a T4 isolation claim.
9. T4 runner enrollment records an independent zone identity and rejects the
   control-plane host, workstation runner class, shared Compose network, missing
   watch, or unreachable E-stop.
10. Architecture tests enumerate permitted dependency, public capability-surface,
    and network edges and fail when an agent, provider, workflow, or ordinary
    command can bypass the broker to obtain or reach a connector, credential
    backend, validator, runner, generic network, or execution primitive.

## Required verification matrix

| Path | Required result and evidence |
|---|---|
| Success | A valid scoped intent crosses the broker and produces a receipt, evidence reference, and complete audit sequence. |
| Invalid input | Each missing or conflicting context field is rejected at every ingress and resolution boundary. |
| Denial | Unknown tools, direct calls, stale or mismatched approvals, wrong scopes, and wrong runner audiences issue no credential or dispatch lease. |
| Timeout | Pre-dispatch timeout has no side effect; post-dispatch timeout becomes `uncertain` and is not retried. |
| Cancellation | Lease revocation and remote cancellation are recorded; an unconfirmed stop remains `uncertain`. |
| Recovery | Durable replay resumes only allowed analysis or reconciliation and never duplicates a confirmed side effect. |
| Architecture | Static dependency, exported-API capability, and runtime network tests show commands, providers, agents, and workflows cannot obtain or reach connectors or runners except through the broker. |
| Agent surface | Production registries contain no generic HTTP, unrestricted shell, arbitrary evaluator, Docker socket, or untyped RPC tool. |
| T4 isolation | Negative tests reject local, workstation, low-risk, shared-host, and ordinary Compose runners before approval or dispatch. |

## Completion evidence

The issue must include the reviewed document diff, Markdown and Mermaid validation
results, requirement trace, architecture-test report, and reviewer sign-off. The
report must identify the exact ADR and companion digests and link to COH-E01-02.

## Change control

This companion changes only with ADR-0001. Any relaxation requires a superseding
ADR, updated threat model, migration assessment, negative fixtures, and Product and
Security Architecture approval. Emergency changes may deny more work but may not
widen authority.
