# Typed capability seams

| Field | Decision |
|---|---|
| Linear issue | CYB-182 / COH-E25-01 |
| Status | v1 contract frozen; resolver implementation follows |
| Public contract | `contracts/capability-seam/v1/` |
| Architecture source | `docs/design/deepseek-harness-adoption.md` |

## Boundary

COH composition is a closed typed graph, not a general plugin container. Every
replaceable service has one versioned definition, one selected qualified
provider, and explicit consumers. Resolution happens before publication and is
all-or-nothing. The graph is descriptive, redacted metadata and never an
executable object graph or authority token.

Definitions establish the maximum lifecycle, permissions, multiplicity, and
dependency surface. Providers can only narrow that surface. Consumers can only
narrow it again. A capability identity is exact; v1 has no ranges, duck typing,
name aliases, late binding, or best-effort provider selection.

## Non-replaceable control plane

The composition root owns a compiled reserved-authority table. Broker, policy,
approval, audit, credential, evidence, E-stop, runner, connector, and validator
authority cannot be registered by an extension, shadowed by a profile, or
intercepted by a consumer. Reserved identity matching is exact and includes
aliases maintained by the architecture gate so renaming cannot evade it.

Registration has no implication of permission. Model-originated work remains a
typed broker intent and passes current policy, approval, scope, budget, lease,
audit, revocation, and E-stop checks immediately before dispatch.

## Resolution invariant

For one signed profile revision, resolution must prove:

1. strict decoding and canonical identity of every declaration;
2. one definition for every referenced capability;
3. multiplicity and exact-version provider selection;
4. current qualification for the exact provider artifact and profile;
5. provider and consumer scope/permission subset relationships;
6. complete declared consumer and dependency edges;
7. an acyclic dependency graph and stable lexical topological order;
8. compiled non-replaceable authority invariants; and
9. context cancellation has not occurred before graph publication.

Any failure returns a typed redacted reason and no graph. There is no fallback
provider, partial graph, last-known-good in-memory authority, or callback
recovery. A separately authorized signed rollback may select a prior durable
revision, but it is resolved again under current revocation and policy state.

## Delivery boundary

This design freeze defines the public records and invariants. CYB-182's next
tasks implement strict Go decoding, canonical digests, immutable owned values,
the resolver, current qualification admission, architecture enforcement, and
adversarial evidence. CYB-183 later signs and composes ordered profile layers;
CYB-184 owns transactional activation and revocation. Neither concern is
silently implemented inside this base contract.
