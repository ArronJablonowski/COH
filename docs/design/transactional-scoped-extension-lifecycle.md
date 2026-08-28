# Transactional scoped extension lifecycle

| Field | Decision |
|---|---|
| Linear issue | CYB-184 / COH-E25-03 |
| Status | v1 contract frozen; implementation follows |
| Public contract | `contracts/extension-lifecycle/v1/` |
| Architecture source | `docs/design/deepseek-harness-adoption.md` |
| Requirements | FR-014, FR-015, FR-042, FR-043, SEC-018, SEC-020 |

## Boundary

COH adopts DeepSeek Harness's reversible lifecycle-effects pattern, constrained
to reviewed signed data-plane extensions. This is not a general plugin loader.
An extension contributes bounded provider or consumer registrations to an
already resolved capability graph. It never receives a mutable service context,
generic event listener, shell, HTTP, filesystem, dynamic-loader, credential,
broker, policy, audit, approval, E-stop, runner, connector, validator, or
evidence authority.

Manifest signing proves provenance. Promotion proves reviewed availability.
Qualification proves exact artifact/profile compatibility. Policy permits one
administrative lifecycle intent. None of those independently grants action
authority, and ordinary extension use continues through current broker checks.

## Transaction model

Activation is a durable state machine, not a chain of in-memory callbacks:

```text
verified -> prepared -> applying -> active
                         |
                         v
                     unwinding -> inactive

active -> draining -> revoking -> inactive
```

The transition persists before the first effect and after every effect boundary.
Each registration has a stable ordinal and idempotency identity. Its receipt
contains a data-only revocation handle scoped to the exact owner. Failure changes
direction and walks completed ordinals in reverse. The active pointer is
published only after every receipt and activation audit fact are durable.

Deactivation closes admission for the target extension before draining work.
Bounded cancellation is allowed only after the signed drain deadline. Terminal
outcomes become durable before revocation. Revocation removes only registrations
whose owner/manifest/transition/scope/generation tuple exactly matches the
handle. Terminal audit commits before the active pointer is removed and success
is returned.

## Authority inputs

The command root constructs ephemeral typed authority snapshots for current:

1. publisher, reviewer, and owner keys and approval revisions;
2. immutable promotion and predecessor lineage;
3. artifact qualification, SBOM, provenance, tests, and revocation;
4. active profile revision, composition digest, and capability graph;
5. exact narrowed permission/scope digests, policy decision, and administrative
   actor/scope;
6. audit availability and idempotent append capability; and
7. E-stop state and revision.

These values are not accepted from transports, models, agents, manifests, or
persistence rows as self-authorizing facts. They are not serializable authority
objects. A controller restart obtains fresh snapshots and compares them to the
sealed intent before continuing.

## Durability and recovery

Durable records contain canonical data only: signed manifest bytes, digests,
IDs, revisions, phases, ordinals, receipts, revocation handles, work-terminal
digests, and audit receipts. Provider constructors and revokers are compiled
command-root adapters selected by declared registration kind and exact artifact;
their executable values are never persisted or returned through public APIs.

Every boundary tolerates a lost response. Recovery resolves exact idempotency
identity at the effect adapter before deciding whether to apply or revoke. It
never advances from an ambiguous result. Corruption, missing ancestry, stale
authority, or a revoked dependency leaves the extension inactive or admission
closed for operator recovery rather than guessing forward.

## Upgrade and rollback

Upgrade is deactivation of the old version followed by activation of a new
manifest that binds the exact predecessor. Candidate failure never leaks partial
registrations. Once the old version is fully deactivated, failure remains safely
inactive rather than resurrecting stale authority.

Rollback requires a current separately signed scope-exact administrative
decision and selects only an immediate retained predecessor. The target is
reverified as a new activation under current signatures, review, promotion,
qualification, policy, dependencies, profile, E-stop, and audit state. Earlier
success is not authority.

## Required implementation proof

Implementation must cover strict decoding, canonical replay, immutable ownership,
all pre-publication guards, reverse unwind, scoped deactivation, concurrent
activation/deactivation, lost responses at every durable boundary, SQLite
restart, crash injection, stale revision, tamper, revocation, E-stop,
cancellation, timeout, upgrade, rollback, race, fuzz, architecture, secret,
license, size, supply-chain, and full baseline CI evidence.
