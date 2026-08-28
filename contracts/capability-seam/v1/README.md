# Typed capability seam contract v1

| Field | Value |
|---|---|
| Stable key | COH-E25-01 / CYB-182 |
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Digest | Domain-separated SHA-256 |
| Requirements | NFR-019, NFR-026, FR-018, FR-031, SEC-001, SEC-002 |

This contract makes runtime composition explicit without turning composition
into execution authority. A declaration bundle contains a closed set of service
definitions, qualified providers, and named consumers. The resolver produces a
single immutable graph before startup or a quiescent maintenance transition.

## Contract bundle

| Schema | Purpose |
|---|---|
| `capability-seam-bundle.schema.json` | Definitions, providers, consumers, scopes, permissions, lifecycle, dependencies, and qualification bindings |
| `resolved-capability-graph.schema.json` | Digest-bound resolved nodes, edges, and deterministic dependency order |
| `fixtures/bundle.valid.json` | Canonicalizable provider-inference declaration bundle |
| `fixtures/graph.valid.json` | Digest-bound resolved graph for the valid bundle |
| `fixtures/denial-corpus.json` | Executable strict-decoding, binding, authority, and tamper denial inventory |

Both schemas use JSON Schema draft 2020-12, pin `schema_version` and
`contract_version`, and reject unknown members. Decoders additionally reject
duplicate JSON names, trailing values, invalid UTF-8, non-integer numbers for
integer fields, oversized inputs, unsorted set-like arrays, and duplicate
logical identities before resolution.

## Identity and ownership

A capability identity is the exact `(name, semantic version)` pair. Definition,
provider, and consumer owners bind a compiled module name to its immutable
artifact digest. Provider identity additionally binds provider version and
artifact digest. Name similarity, compatible prefixes, and runtime aliases do
not establish identity or compatibility.

The v1 resolver supports exact capability versions only. Version ranges and
implicit compatibility are deliberately absent. A version change requires a
new definition, provider qualification, consumer declaration, fixtures, and
composition revision.

## Definitions and authority classes

A definition declares its owner, authority class, replaceability,
multiplicity, lifecycle, access policy, maximum permission set, and capability
dependencies. `access_policy` is schema-closed: `broker_intent_only` requires a
typed-intent provider and broker-intent consumers, while `read_only_service`
requires a non-dispatch provider and read-only consumers. Consequential
permission classes cannot declare the read-only policy.
`authority` definitions must be `non_replaceable`, `exactly_one`, and `static`.
The following authority services are compiled invariants and cannot be supplied
or intercepted by an ordinary extension:

- broker and policy evaluation;
- approval and credential authority;
- audit and evidence authority;
- emergency stop;
- runners, connectors, and native validators.

The compiled invariant list is stricter than the input schema. A declaration
cannot relabel or rename a reserved authority service to make it replaceable.

## Providers, consumers, and routing

A provider is valid only for the exact capability, immutable artifact, owner,
scope, permission subset, lifecycle, profile, and current qualification record.
Qualification is time-bounded and binds the exact provider and profile digests.
Revoked, expired, stale-authority, or profile-mismatched qualification denies
the graph.

Resolution also requires a live, maximum-five-minute trusted registry snapshot
from the composition root. For every selected provider it binds the exact
bundle digest and composition revision, plus the exact
provider identity/version/artifact, capability identity/version, qualification
record ID/digest and validity interval, profile digest, registry revision,
qualification-authority revision, current revocation revision, and active
state. The snapshot contains no executable authority and is not accepted from
JSON, a profile, a provider, an extension, or model-visible data. Missing,
extra, duplicate, reordered, expired, inactive, revoked, or drifted records
deny the complete graph.

A prior bundle cannot be replayed under a newer composition snapshot. Rollback
requires the trusted control plane to make the exact prior bundle digest and
revision current again through its separately signed rollback process; the
resolver then repeats every current qualification and revocation check.

A consumer names one capability, scope, permission subset, and access mode.
The consumer scope and permissions must be no wider than both the definition
and selected provider. Every consumer and dependency edge must be declared.
Orphans, ambiguity, missing providers, duplicate identities, and cycles deny
the complete graph; the resolver never emits a partial graph.

`broker_intent` means the consumer can submit a typed intent to the broker. It
does not receive the provider implementation or an executor capability.
`read_only_service` is valid only for a side-effect-free data-plane contract.
Any model-originated operation remains a typed broker intent regardless of
provider registration or graph resolution.

## Lifecycle

`static` services are fixed by the compiled composition root. `restart_bound`
services may change only across a validated restart. `transactional` applies
only to qualified data-plane extensions and will be implemented by COH-E25-03.
Security-critical live reload is not a valid lifecycle.

The v1 declaration contract records lifecycle intent but does not itself
activate, revoke, drain, or execute a provider. Those effects require the
transactional lifecycle authority, signed durable profile composition, current
policy, audit availability, and a quiescent maintenance transition.

## Canonicalization and digests

Objects use repository-wide `COH-CJ-1`. Set-like arrays are sorted by their
logical identity and contain no duplicates. Dependency order in the resolved
graph is a stable topological order with lexical node identity as the only
tie-breaker. Sequence-bearing arrays preserve declared order only where the
contract says order is meaningful.

The declaration bundle digest uses:

```text
COH-CAPABILITY-SEAM-BUNDLE-V1\0 || COH-CJ-1(bundle)
```

The graph digest uses:

```text
COH-RESOLVED-CAPABILITY-GRAPH-V1\0 || COH-CJ-1(graph with graph_digest omitted)
```

The graph binds the source bundle and profile digests. It contains no callback,
function pointer, credential, raw configuration value, prompt, evidence bytes,
private path, network endpoint, or executable payload.

## Failure and recovery behavior

Unknown schema or contract versions, malformed declarations, cancellation,
timeout, stale qualification, revocation, scope widening, permission widening,
dependency cycles, ambiguous providers, undeclared edges, reserved-authority
replacement, and digest mismatch fail closed before graph publication. Restart
rebuilds from the signed durable declaration and profile; serialized callbacks
or a previously resolved in-memory graph are never authority.

See `compatibility-matrix.md` for mixed-version and rollback behavior.
